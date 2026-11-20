"""PowerShell-backed collection with disk caching.

Collection is deliberately split into small PowerShell calls that emit JSON to a
file (no console encoding issues):

* ``services``  - Win32_Service facts only, ~1 s
* ``evidence``  - existence, size, mtime, company, version per unique path
* ``inspect``   - Authenticode + SHA-256, only for paths whose file changed
* ``events``    - Service Control Manager records with raw property values
* ``action``    - service management, with real exit codes

The evidence cache is keyed by path and invalidated by size/mtime, so repeated
hunts are fast while a replaced binary is always re-inspected.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from . import analysis, config, paths, storage


class CollectionError(RuntimeError):
    pass


class Collector:
    def __init__(self, inventory_ttl: int = 30, event_ttl: int = 60):
        self._inventory_ttl = inventory_ttl
        self._event_ttl = event_ttl
        # Collection mutates shared caches and shells out to PowerShell; serialising
        # it keeps concurrent browser requests from racing or duplicating work.
        self._lock = threading.RLock()
        self._inventory_cache: tuple[float, tuple, dict] | None = None
        self._event_cache: dict[str, tuple[float, dict]] = {}
        self._services_cache: tuple[float, list[dict]] | None = None
        self._state_words: dict[str, str] | None = None
        self._status: dict | None = None

    # ------------------------------------------------------------------ #
    # PowerShell plumbing
    # ------------------------------------------------------------------ #
    def _run(self, mode: str, payload: dict | None = None, timeout: int = 240) -> Any:
        if not config.IS_WINDOWS:
            raise CollectionError(
                "ServiceSentinel manages Windows services and must run on Windows. "
                "The interface is available, but live data cannot be collected here."
            )
        if not config.PS_SCRIPT.exists():
            raise CollectionError(f"Collector script missing: {config.PS_SCRIPT}")

        with tempfile.TemporaryDirectory(prefix="sentinel-") as workspace:
            out_path = Path(workspace) / "out.json"
            args_path = Path(workspace) / "args.json"
            args_path.write_text(json.dumps(payload or {}), encoding="utf-8")
            command = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(config.PS_SCRIPT),
                "-Mode",
                mode,
                "-OutPath",
                str(out_path),
                "-ArgsFile",
                str(args_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    cwd=str(config.PROJECT_ROOT),
                )
            except subprocess.TimeoutExpired as exc:
                raise CollectionError(f"PowerShell collector timed out after {timeout}s ({mode}).") from exc
            except OSError as exc:
                raise CollectionError(f"Unable to start PowerShell: {exc}") from exc

            if not out_path.exists():
                detail = (completed.stderr or completed.stdout or "").strip()
                raise CollectionError(
                    f"Collector '{mode}' produced no output (exit {completed.returncode}). {detail[:500]}"
                )
            raw = out_path.read_text(encoding="utf-8-sig")
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except ValueError as exc:
            raise CollectionError(f"Collector '{mode}' returned invalid JSON: {exc}") from exc
        if isinstance(parsed, dict) and parsed.get("error"):
            raise CollectionError(str(parsed["error"]))
        return parsed

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #
    def status(self, refresh: bool = False) -> dict:
        if self._status and not refresh:
            return dict(self._status)
        admin = False
        if config.IS_WINDOWS:
            try:
                admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:  # noqa: BLE001 - probing must never break the UI
                admin = False
        info = {
            "app": config.APP_NAME,
            "version": config.VERSION,
            "hostname": socket.gethostname(),
            "admin": admin,
            "platform": "Windows" if config.IS_WINDOWS else os.name,
            "data_root": str(config.data_root()),
            "log_file": str(config.log_file()),
            "python": os.sys.version.split()[0],
            "powershell": self._powershell_version(),
            "baseline_exists": config.baseline_file().exists(),
            "evidence_cache_entries": len(self._load_evidence_cache()),
            "triage_count": len(storage.read_jsonl(config.triage_file())),
            "auth_enabled": bool(config.auth_password()),
            "allow_remote": config.allow_remote(),
            "retention_days": config.retention_days(),
        }
        self._status = info
        return dict(info)

    def _powershell_version(self) -> str:
        if not config.IS_WINDOWS:
            return "n/a"
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return (completed.stdout or "").strip() or "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    # ------------------------------------------------------------------ #
    # Services
    # ------------------------------------------------------------------ #
    def raw_services(self, refresh: bool = False) -> list[dict]:
        with self._lock:
            now = time.time()
            if not refresh and self._services_cache and now - self._services_cache[0] < self._inventory_ttl:
                return self._services_cache[1]
            payload = self._run("services")
            items = _items(payload)
            self._services_cache = (now, items)
            return items

    def run_action(self, payload: dict, timeout: int = 240) -> dict:
        """Public entry point for management actions (never used for read-only work)."""
        result = self._run("action", payload, timeout=timeout)
        return result if isinstance(result, dict) else {}

    def invalidate(self) -> None:
        """Drop cached inventory after a state change."""
        with self._lock:
            self._inventory_cache = None
            self._services_cache = None
            self._event_cache.clear()

    # ------------------------------------------------------------------ #
    # File evidence
    # ------------------------------------------------------------------ #
    def _load_evidence_cache(self) -> dict[str, dict]:
        data = storage.read_json(config.evidence_cache_file(), default={}) or {}
        if not isinstance(data, dict):
            return {}
        return data

    def _save_evidence_cache(self, cache: dict[str, dict]) -> None:
        try:
            storage.write_json(config.evidence_cache_file(), cache)
        except OSError as exc:
            storage.log("WARN", f"Could not persist evidence cache: {exc}")

    def evidence(self, unique_paths: list[str]) -> dict[str, dict]:
        """Return evidence per path, re-inspecting only files that changed."""
        with self._lock:
            return self._collect_evidence(unique_paths)

    def _collect_evidence(self, unique_paths: list[str]) -> dict[str, dict]:
        if not unique_paths:
            return {}
        cache = self._load_evidence_cache()
        payload = self._run("evidence", {"paths": unique_paths})
        basic = {str(item.get("path") or "").casefold(): item for item in _items(payload)}

        results: dict[str, dict] = {}
        stale: list[str] = []
        now = datetime.now().astimezone().isoformat(timespec="seconds")

        for path in unique_paths:
            key = path.casefold()
            info = basic.get(key) or {"exists": False}
            cached = cache.get(key) or {}
            entry = {
                "exists": bool(info.get("exists")),
                "size": info.get("size") or 0,
                "mtime": info.get("mtime") or "",
                "company": info.get("company") or "",
                "version": info.get("version") or "",
                "signature": "FileNotFound" if not info.get("exists") else cached.get("signature") or "NotChecked",
                "signer": cached.get("signer") or "",
                "sha256": cached.get("sha256") or "",
                "checked_at": cached.get("checked_at"),
            }
            if info.get("exists"):
                unchanged = (
                    cached.get("size") == entry["size"]
                    and str(cached.get("mtime") or "") == str(entry["mtime"])
                    and cached.get("signature")
                    and cached.get("sha256")
                )
                if not unchanged:
                    stale.append(path)
            results[key] = entry

        if stale:
            inspected = self._run("inspect", {"paths": stale, "hash": True})
            for item in _items(inspected):
                key = str(item.get("path") or "").casefold()
                if key not in results:
                    continue
                results[key]["signature"] = item.get("signature") or "Error"
                results[key]["signer"] = item.get("signer") or ""
                results[key]["sha256"] = item.get("sha256") or ""
                results[key]["checked_at"] = now
                cache[key] = {
                    "size": results[key]["size"],
                    "mtime": results[key]["mtime"],
                    "signature": results[key]["signature"],
                    "signer": results[key]["signer"],
                    "sha256": results[key]["sha256"],
                    "checked_at": now,
                }
        self._save_evidence_cache(cache)
        return results

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #
    def raw_events(self, hours: int = 168, refresh: bool = False) -> dict:
        hours = max(1, min(int(hours or 168), 24 * 90))
        key = f"{hours}"
        with self._lock:
            now = time.time()
            cached = self._event_cache.get(key)
            if not refresh and cached and now - cached[0] < self._event_ttl:
                return cached[1]
            payload = self._run("events", {"hours": hours, "max_events": 8000}, timeout=180)
            result = {
                "items": _items(payload),
                "truncated": bool(payload.get("truncated")) if isinstance(payload, dict) else False,
                "hours": hours,
                "collected_at": analysis.iso_now(),
            }
            self._event_cache[key] = (now, result)
            return result

    # ------------------------------------------------------------------ #
    # State words
    # ------------------------------------------------------------------ #
    def state_words(self) -> dict[str, str]:
        if self._state_words is not None:
            return dict(self._state_words)
        stored = storage.read_json(config.state_words_file(), default={}) or {}
        raw = stored.get("words") if isinstance(stored, dict) else None
        if not isinstance(raw, dict):
            # Older files stored the mapping at the top level, with a leading
            # `_learned_at` key that must not become a "state word".
            raw = stored if isinstance(stored, dict) else {}
        words = {
            str(key): str(value)
            for key, value in raw.items()
            if not str(key).startswith("_")
        }
        self._state_words = words
        return dict(words)

    def _learn_state_words(self, raw_events: list[dict], services: list[dict]) -> dict[str, str]:
        known = self.state_words()
        learned = analysis.learn_state_words(raw_events, services, known)
        additions = {
            word: state
            for word, state in learned.items()
            if word.casefold() not in {k.casefold() for k in known}
        }
        if additions:
            merged = dict(known)
            merged.update(additions)
            self._state_words = merged
            try:
                storage.write_json(
                    config.state_words_file(),
                    {"words": merged, "learned_at": analysis.iso_now()},
                )
            except OSError as exc:
                storage.log("WARN", f"Could not persist learned state words: {exc}")
            storage.log("INFO", f"Learned {len(additions)} localised service state word(s): {', '.join(additions)}")
        return learned

    # ------------------------------------------------------------------ #
    # Inventory
    # ------------------------------------------------------------------ #
    def inventory(
        self,
        evidence: bool = True,
        refresh: bool = False,
        hours: int = 168,
    ) -> dict:
        with self._lock:
            return self._collect_inventory(evidence=evidence, refresh=refresh, hours=hours)

    def _collect_inventory(self, evidence: bool, refresh: bool, hours: int) -> dict:
        now = time.time()
        # The cache must distinguish evidence and event-window, otherwise a 24h
        # inventory would be reused for a 7-day hunt and report stale activity.
        cache_key = (bool(evidence), int(hours))
        cached = self._inventory_cache
        if (
            not refresh
            and cached
            and now - cached[0] < self._inventory_ttl
            and cached[1] == cache_key
        ):
            return cached[2]

        services = self.raw_services(refresh=refresh)
        events_payload = self.raw_events(hours=hours, refresh=refresh)
        raw_events = events_payload["items"]
        self._learn_state_words(raw_events, services)
        words = self.state_words()

        derived_paths = []
        for raw in services:
            candidate = paths.normalize_service_path(raw.get("command_line"))
            if candidate:
                derived_paths.append(candidate)
        unique = sorted({path for path in derived_paths if path}, key=str.casefold)

        evidence_map = self.evidence(unique) if evidence else {}

        interpreted = analysis.interpret_events(raw_events, words)
        index = analysis.event_index(interpreted)

        records = []
        for raw in services:
            exe_path = paths.normalize_service_path(raw.get("command_line"))
            evidence_entry = evidence_map.get((exe_path or "").casefold()) if evidence else None
            records.append(
                analysis.build_record(raw, evidence_entry, interpreted=interpreted, index=index)
            )

        triage_latest = storage.latest_by(storage.read_jsonl(config.triage_file()), "service_name")
        for record in records:
            entry = triage_latest.get(str(record["name"]).casefold())
            if entry:
                record["triage"] = {
                    "decision": entry.get("decision"),
                    "analyst": entry.get("analyst"),
                    "timestamp": entry.get("timestamp"),
                    "notes": entry.get("notes"),
                }

        records.sort(key=lambda item: (item["category"], item["display_name"].casefold()))
        payload = {
            "collected_at": analysis.iso_now(),
            "evidence": bool(evidence),
            "event_window_hours": hours,
            "events_truncated": events_payload["truncated"],
            "event_count": len(raw_events),
            "services": records,
            "stats": _stats(records),
        }
        self._inventory_cache = (now, cache_key, payload)
        storage.log("INFO", f"Inventory collected: {len(records)} services (evidence={bool(evidence)})")
        return payload

    # ------------------------------------------------------------------ #
    # Assessments
    # ------------------------------------------------------------------ #
    def assessments(self, hours: int = 168, refresh: bool = False) -> dict:
        with self._lock:
            return self._run_assessments(hours=hours, refresh=refresh)

    def _run_assessments(self, hours: int, refresh: bool) -> dict:
        hours = max(1, min(int(hours or 168), 24 * 90))
        events_payload = self.raw_events(hours=hours, refresh=refresh)
        raw_events = events_payload["items"]
        inventory = self.inventory(evidence=True, refresh=refresh, hours=hours)
        words = self.state_words()
        interpreted = analysis.interpret_events(raw_events, words)
        index = analysis.event_index(interpreted)

        findings = []
        for record in inventory["services"]:
            findings.append(analysis.assess(record, interpreted=interpreted, index=index))
        findings.sort(
            key=lambda item: (-item["threat_score"], -item["reliability_score"], str(item["service_name"]).casefold())
        )

        notable = [item for item in findings if item["threat_score"] > 0 or item["reliability_score"] > 0]
        counts: dict[str, int] = {}
        for item in findings:
            counts[item["threat_level"]] = counts.get(item["threat_level"], 0) + 1
        return {
            "collected_at": inventory["collected_at"],
            "hours": hours,
            "event_count": len(raw_events),
            "events_truncated": events_payload["truncated"],
            "findings": findings,
            "notable": len(notable),
            "counts": counts,
            "scored_services": len(findings),
        }

    def service_detail(self, name: str, hours: int = 168) -> dict:
        with self._lock:
            return self._service_detail(name, hours)

    def _service_detail(self, name: str, hours: int) -> dict:
        inventory = self.inventory(evidence=True, hours=hours)
        target = None
        for record in inventory["services"]:
            if str(record["name"]).casefold() == name.casefold():
                target = record
                break
        if target is None:
            raise KeyError(name)

        events_payload = self.raw_events(hours=hours)
        words = self.state_words()
        interpreted = analysis.interpret_events(events_payload["items"], words)
        index = analysis.event_index(interpreted)
        recent = list(reversed(analysis.events_for(target, interpreted, index)))

        assessment = analysis.assess(target, interpreted=interpreted, index=index)
        triage = storage.latest_by(storage.read_jsonl(config.triage_file()), "service_name").get(
            str(target["name"]).casefold()
        )
        return {
            "service": target,
            "assessment": assessment,
            "events": recent[:25],
            "event_total": len(recent),
            "triage": triage,
            "state_words": words,
        }

    def timeline(self, hours: int = 168, name: str = "", bucket: str = "day", refresh: bool = False) -> dict:
        events_payload = self.raw_events(hours=hours, refresh=refresh)
        words = self.state_words()
        interpreted = analysis.interpret_events(events_payload["items"], words)

        if name:
            keys = {name.casefold()}
            inventory = self.inventory(evidence=False, hours=hours)
            for record in inventory["services"]:
                if str(record["name"]).casefold() == name.casefold():
                    keys.add(str(record["display_name"]).casefold())
            interpreted = [
                event for event in interpreted if str(event.get("service_name") or "").casefold() in keys
            ]

        interpreted.sort(key=lambda item: str(item.get("time") or ""), reverse=True)
        return {
            "hours": hours,
            "name": name,
            "bucket": "week" if str(bucket).lower().startswith("w") else "day",
            "events": interpreted,
            "truncated": events_payload["truncated"],
            "summary": analysis.summarize_timeline(interpreted, bucket),
            "state_words": words,
        }


def _items(payload: Any) -> list[dict]:
    """Accept {items:[...]}, a bare list, or a single object from ConvertTo-Json."""
    if isinstance(payload, dict):
        items = payload.get("items")
    else:
        items = payload
    if items is None:
        return []
    if isinstance(items, dict):
        return [items]
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    return []


def _stats(records: list[dict]) -> dict:
    categories: dict[str, int] = {}
    for record in records:
        categories[record["category"]] = categories.get(record["category"], 0) + 1
    return {
        "total": len(records),
        "running": sum(1 for record in records if record["state"] == "Running"),
        "stopped": sum(1 for record in records if record["state"] == "Stopped"),
        "auto": sum(1 for record in records if record["start_mode"] == "Auto"),
        "unsigned": sum(1 for record in records if record["signature"] == "NotSigned"),
        "signature_unknown": sum(
            1 for record in records if record["signature"] in {"", "NotChecked"}
        ),
        "missing_binary": sum(1 for record in records if record["path_known"] and not record["file_exists"]),
        "user_writable": sum(1 for record in records if record["user_writable"]),
        "unquoted": sum(1 for record in records if record["unquoted_path"]),
        "unknown_path": sum(1 for record in records if not record["path_known"]),
        "categories": [
            {"name": key, "count": value}
            for key, value in sorted(categories.items(), key=lambda item: (-item[1], item[0]))
        ],
    }
