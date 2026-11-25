"""Baseline capture and change detection.

The comparison treats missing values as *unknown* instead of as changes, and it
recognises version-stamped service name rotation (e.g. ``GoogleUpdaterService159``
being replaced by ``GoogleUpdaterService162``), which used to arrive as a
High-severity created+deleted pair on every application update.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .analysis import normalize_account, parse_time
from . import storage

SCHEMA_VERSION = 2
COMPARED_FIELDS = ("command_line", "start_mode", "account", "display_name", "service_type")
FIELD_LABELS = {
    "command_line": "Command line",
    "start_mode": "Startup mode",
    "account": "Account",
    "display_name": "Display name",
    "service_type": "Service type",
}
FIELD_SEVERITY = {
    "command_line": "High",
    "account": "High",
    "start_mode": "Medium",
    "display_name": "Low",
    "service_type": "Low",
}
SNAPSHOT_FIELDS = (
    "name",
    "display_name",
    "state",
    "start_mode",
    "account",
    "service_type",
    "command_line",
    "exe_path",
)

_SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def capture(inventory: list[dict], hostname: str, created_at: str) -> dict:
    services = []
    for record in sorted(inventory, key=lambda item: str(item.get("name", "")).casefold()):
        services.append({field: record.get(field) for field in SNAPSHOT_FIELDS})
    return {
        "schema": SCHEMA_VERSION,
        "hostname": hostname,
        "created_at": created_at,
        "services": services,
    }


def _rotation_key(name: str) -> str:
    """Strip version-like noise so a renamed service can be paired with its predecessor."""
    lowered = str(name or "").casefold()
    without_digits = re.sub(r"\d+", "", lowered)
    return re.sub(r"[^a-z]+", "", without_digits)


def _is_unknown(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return text == "" or text.casefold() in {"unknown", "notavailable"}


def diff(baseline: dict | None, inventory: list[dict]) -> dict:
    if not baseline:
        return {
            "changes": [],
            "unverifiable": [],
            "summary": {},
            "baseline": None,
            "message": "No baseline exists yet. Create one when this computer is known to be clean.",
        }

    old_services = {}
    for item in baseline.get("services") or []:
        name = str(item.get("name") or "").strip()
        if name:
            old_services[name.casefold()] = item
    new_services = {}
    for record in inventory:
        name = str(record.get("name") or "").strip()
        if name:
            new_services[name.casefold()] = record

    changes: list[dict] = []
    unverifiable: list[dict] = []
    created = [name for name in new_services if name not in old_services]
    deleted = [name for name in old_services if name not in new_services]

    # Pair version-stamped name rotations so they do not read as tampering.
    deleted_by_key: dict[str, list[str]] = defaultdict(list)
    for name in deleted:
        deleted_by_key[_rotation_key(name)].append(name)
    rotations: dict[str, str] = {}
    for name in created:
        candidates = deleted_by_key.get(_rotation_key(name))
        if candidates:
            predecessor = candidates.pop(0)
            if predecessor not in rotations:
                rotations[name] = predecessor
                rotations[predecessor] = name

    for name in created:
        record = new_services[name]
        paired = rotations.get(name)
        if paired:
            changes.append(
                {
                    "service_name": record.get("name"),
                    "change_type": "Versioned replacement",
                    "field": "Service",
                    "old_value": old_services[paired].get("name"),
                    "new_value": record.get("name"),
                    "severity": "Low",
                    "reason": "Same service family with a version-stamped name; expected after a software update.",
                }
            )
        else:
            changes.append(
                {
                    "service_name": record.get("name"),
                    "change_type": "Created since baseline",
                    "field": "Service",
                    "old_value": None,
                    "new_value": record.get("command_line"),
                    "severity": "High",
                    "reason": "New service appeared. Verify the source, signer and business purpose.",
                }
            )

    for name in deleted:
        if name in rotations:
            continue
        changes.append(
            {
                "service_name": old_services[name].get("name"),
                "change_type": "Deleted since baseline",
                "field": "Service",
                "old_value": old_services[name].get("command_line"),
                "new_value": None,
                "severity": "High",
                "reason": "Service was removed. Confirm an intended decommission rather than attacker clean-up.",
            }
        )

    for name, record in new_services.items():
        old = old_services.get(name)
        if old is None:
            continue
        for field in COMPARED_FIELDS:
            old_value = old.get(field)
            new_value = record.get(field)

            if field == "account":
                old_norm, old_known = normalize_account(old_value)
                new_norm, new_known = normalize_account(new_value)
                if not old_known and not new_known:
                    continue  # unknown in both snapshots: nothing to compare, nothing to report
                if not (old_known and new_known):
                    unverifiable.append(
                        {
                            "service_name": record.get("name"),
                            "field": FIELD_LABELS[field],
                            "reason": "Account was readable in only one snapshot; comparison skipped rather than guessed.",
                        }
                    )
                    continue
                if old_norm.casefold() == new_norm.casefold():
                    continue
                old_text, new_text = old_norm, new_norm
            else:
                old_unknown = _is_unknown(old_value)
                new_unknown = _is_unknown(new_value)
                if old_unknown and new_unknown:
                    continue  # unknown in both snapshots: no signal, no noise
                if old_unknown or new_unknown:
                    unverifiable.append(
                        {
                            "service_name": record.get("name"),
                            "field": FIELD_LABELS[field],
                            "reason": "Value was readable in only one snapshot; comparison skipped rather than guessed.",
                        }
                    )
                    continue
                old_text = str(old_value).strip()
                new_text = str(new_value).strip()
                if old_text.casefold() == new_text.casefold():
                    continue

            changes.append(
                {
                    "service_name": record.get("name"),
                    "change_type": "Configuration changed",
                    "field": FIELD_LABELS[field],
                    "old_value": old_text,
                    "new_value": new_text,
                    "severity": FIELD_SEVERITY[field],
                    "reason": _reason_for(field, old_text, new_text),
                }
            )

    changes.sort(
        key=lambda item: (-_SEVERITY_ORDER.get(item["severity"], 0), str(item["service_name"]).casefold())
    )
    summary = {
        "total": len(changes),
        "created": sum(1 for item in changes if item["change_type"] == "Created since baseline"),
        "deleted": sum(1 for item in changes if item["change_type"] == "Deleted since baseline"),
        "modified": sum(1 for item in changes if item["change_type"] == "Configuration changed"),
        "versioned": sum(1 for item in changes if item["change_type"] == "Versioned replacement"),
        "unverifiable": len(unverifiable),
        "by_severity": {
            level: sum(1 for item in changes if item["severity"] == level)
            for level in ("High", "Medium", "Low")
        },
    }
    baseline_time = parse_time(baseline.get("created_at"))
    return {
        "changes": changes,
        "unverifiable": unverifiable,
        "summary": summary,
        "baseline": {
            "created_at": baseline.get("created_at"),
            "hostname": baseline.get("hostname"),
            "services": len(baseline.get("services") or []),
            "age": f"{baseline_time:%Y-%m-%d %H:%M}" if baseline_time else "unknown",
        },
        "message": None,
    }


def _reason_for(field: str, old: str, new: str) -> str:
    if field == "command_line":
        return "Binary path changed; the service may have been redirected."
    if field == "account":
        return f"Account changed from '{old}' to '{new}'; check for privilege escalation or lateral movement."
    if field == "start_mode":
        if "auto" in new.casefold():
            return "Startup set to automatic; persistence risk increased."
        if "disabled" in new.casefold():
            return "Service disabled; possible security control bypass."
        return "Startup type changed."
    if field == "display_name":
        return f"Display name changed from '{old}' to '{new}'; possible masquerading."
    if field == "service_type":
        return "Service type changed; structural modification of the service."
    return "Configuration changed."


def create_baseline(inventory: list[dict], hostname: str, created_at: str) -> dict:
    document = capture(inventory, hostname, created_at)
    storage.write_json(_baseline_path(), document)
    history = _baseline_path().with_name(
        f"baseline_{parse_time(created_at).strftime('%Y%m%d_%H%M%S')}.json"
        if parse_time(created_at)
        else "baseline_history.json"
    )
    try:
        storage.write_json(history, document)
    except OSError:
        history = None
    return {"document": document, "path": str(_baseline_path()), "history": str(history) if history else None}


def _baseline_path():
    from . import config

    return config.baseline_file()


def load_baseline() -> dict | None:
    return storage.read_json(_baseline_path())


def history_files() -> list[dict]:
    from . import config

    items = []
    for path in sorted(config.data_root().glob("baseline_*.json")):
        document = storage.read_json(path) or {}
        items.append(
            {
                "file": path.name,
                "created_at": document.get("created_at"),
                "services": len(document.get("services") or []),
                "size": path.stat().st_size if path.exists() else 0,
            }
        )
    return sorted(items, key=lambda item: str(item.get("created_at") or ""), reverse=True)
