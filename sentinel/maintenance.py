"""Retention and pruning.

An investigation tool that writes reports, logs, baseline history and a file
evidence cache will grow without bound. This module keeps the evidence folder
predictable while never deleting the three files that matter most: the current
baseline, the triage log and containment backups.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta
from pathlib import Path

from . import config, storage

PROTECTED_FILES = {"baseline-latest.json", "triage_decisions.jsonl"}

# Reports are written by exports.export() as <report>_YYYYmmdd_HHMMSS.<ext>,
# baseline history as baseline_YYYYmmdd_HHMMSS.json, the app log by date.
_REPORT_PATTERN = re.compile(
    r"^(?P<prefix>[a-z0-9-]+)_(?P<stamp>\d{8}_\d{6})(?:_\d+)?\.(?P<ext>csv|json|html)$"
)
_BASELINE_PATTERN = re.compile(r"^baseline_(?P<stamp>\d{8}_\d{6})\.json$")
_LOG_PATTERN = re.compile(r"^ServiceSentinel_(?P<stamp>\d{8})\.log$")


def _stamp_from(match: re.Match) -> datetime | None:
    raw = match.group("stamp")
    for fmt in ("%Y%m%d_%H%M%S", "%Y%m%d"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _delete(path: Path, removed: list[dict]) -> int:
    try:
        size = path.stat().st_size
        path.unlink()
    except OSError:
        return 0
    removed.append({"file": path.name, "bytes": size})
    return size


def prune(
    retention_days: int | None = None,
    max_exports: int | None = None,
    keep_baselines: int = 10,
) -> dict:
    """Delete expired evidence and expired cache entries. Safe to call repeatedly."""
    root = config.data_root()
    days = retention_days if retention_days is not None else config.retention_days()
    limit = max_exports if max_exports is not None else config.max_export_files()
    cutoff = datetime.now() - timedelta(days=max(1, int(days)))

    removed: list[dict] = []
    freed = 0

    # 1. Exports: drop expired files, then keep only the newest `limit` overall.
    reports: list[tuple[datetime, Path]] = []
    for path in root.iterdir() if root.exists() else []:
        if not path.is_file() or path.name in PROTECTED_FILES:
            continue
        match = _REPORT_PATTERN.match(path.name)
        if not match:
            continue
        stamp = _stamp_from(match)
        if stamp is None:
            continue
        reports.append((stamp, path))

    for stamp, path in sorted(reports, key=lambda item: item[0]):
        if stamp < cutoff:
            freed += _delete(path, removed)

    survivors = [(stamp, path) for stamp, path in sorted(reports) if path.exists()]
    for _stamp, path in survivors[:-limit] if len(survivors) > limit else []:
        freed += _delete(path, removed)

    # 2. Baseline history: keep the newest N, drop anything expired beyond that.
    baselines: list[tuple[datetime, Path]] = []
    for path in root.glob("baseline_*.json"):
        match = _BASELINE_PATTERN.match(path.name)
        stamp = _stamp_from(match) if match else None
        if stamp:
            baselines.append((stamp, path))
    baselines.sort(reverse=True)
    for stamp, path in baselines[keep_baselines:]:
        freed += _delete(path, removed)

    # 3. Application logs older than the retention window.
    for path in root.glob("ServiceSentinel_*.log"):
        match = _LOG_PATTERN.match(path.name)
        stamp = _stamp_from(match) if match else None
        if stamp and stamp < cutoff:
            freed += _delete(path, removed)

    # 4. File evidence cache: drop vanished binaries and cap the entry count.
    cache_file = config.evidence_cache_file()
    cache = storage.read_json(cache_file, default={})
    cache_removed = 0
    if isinstance(cache, dict) and cache:
        # A cache entry for a binary that no longer exists is worthless.
        alive = {
            key: entry
            for key, entry in cache.items()
            if isinstance(entry, dict) and Path(key).exists()
        }
        trimmed = alive
        cap = config.max_evidence_cache_entries()
        if len(alive) > cap:
            ordered = sorted(
                alive.items(),
                key=lambda item: str(item[1].get("checked_at") or ""),
                reverse=True,
            )
            trimmed = dict(ordered[:cap])
        cache_removed = max(0, len(cache) - len(trimmed))
        if cache_removed:
            try:
                storage.write_json(cache_file, trimmed)
            except OSError as exc:
                storage.log("WARN", f"Could not rewrite evidence cache during pruning: {exc}")

    summary = {
        "removed_files": len(removed),
        "freed_bytes": freed,
        "freed_mb": round(freed / (1024 * 1024), 2),
        "cache_entries_removed": cache_removed,
        "retention_days": days,
        "max_exports": limit,
        "baseline_history_kept": min(len(baselines), keep_baselines),
        "pruned_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "removed": removed[:100],
    }
    if removed or cache_removed:
        storage.log(
            "INFO",
            f"Pruned {len(removed)} file(s) ({summary['freed_mb']} MB) and {cache_removed} cache entr(ies)",
        )
    return summary


def disk_usage() -> dict:
    """Evidence folder size, so the UI can warn before a disk fills up."""
    root = config.data_root()
    total = 0
    count = 0
    for path in root.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
                count += 1
            except OSError:
                continue
    free = None
    try:
        import shutil

        free = shutil.disk_usage(str(root)).free
    except OSError:
        free = None
    return {
        "files": count,
        "bytes": total,
        "mb": round(total / (1024 * 1024), 2),
        "free_mb": round(free / (1024 * 1024), 2) if free is not None else None,
        "oldest_age_days": _oldest_age_days(root),
    }


def _oldest_age_days(root: Path) -> float | None:
    stamps = []
    for path in root.glob("*"):
        if not path.is_file():
            continue
        match = _REPORT_PATTERN.match(path.name) or _BASELINE_PATTERN.match(path.name)
        stamp = _stamp_from(match) if match else None
        if stamp:
            stamps.append(stamp)
    if not stamps:
        return None
    return round((time.time() - min(stamps).timestamp()) / 86400, 1)
