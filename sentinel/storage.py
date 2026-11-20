"""Small persistence helpers: atomic JSON writes, JSONL appends and the app log."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from . import config

LOG_LEVELS = ("INFO", "WARN", "ERROR", "ACTION")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json(path: Path, payload: Any) -> None:
    """Write JSON atomically so a crash cannot leave a truncated evidence file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        dir=str(path.parent),
        prefix=f".{path.stem}-",
        suffix=".tmp",
    )
    try:
        with handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict):
                    records.append(item)
    except OSError:
        return []
    return records


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def log(level: str, message: str) -> None:
    level = level if level in LOG_LEVELS else "INFO"
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {message}\n"
    try:
        with open(config.log_file(), "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        # Logging must never break an investigation.
        pass


def tail_log(limit: int = 60) -> list[str]:
    try:
        with open(config.log_file(), "r", encoding="utf-8-sig", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    return lines[-limit:]


def latest_by(records: Iterable[dict], key: str) -> dict[str, dict]:
    """Return the most recent record per service, using the `timestamp` field."""
    newest: dict[str, dict] = {}
    for record in records:
        name = str(record.get(key, "")).strip()
        if not name:
            continue
        current = newest.get(name.lower())
        if current is None or str(record.get("timestamp", "")) >= str(current.get("timestamp", "")):
            newest[name.lower()] = record
    return newest
