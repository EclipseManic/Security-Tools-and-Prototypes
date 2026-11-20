"""Analyst triage decisions.

Every record is an append-only JSONL line carrying a real evidence snapshot
(scores, level, path, hash, signer) taken from the live assessment, so a
decision never claims "score 0 / no evidence" the way the legacy stub did.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from . import config, storage

DECISIONS = ("Investigate", "Monitor", "Allow", "Contain", "FalsePositive", "Resolved")


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def record(
    service_name: str,
    decision: str,
    assessment: dict | None = None,
    analyst: str = "",
    notes: str = "",
    hostname: str = "",
) -> dict:
    if decision not in DECISIONS:
        raise ValueError(f"Invalid decision '{decision}'. Choose one of: {', '.join(DECISIONS)}")
    name = (service_name or "").strip()
    if not name:
        raise ValueError("Service name is required.")

    snapshot = assessment or {}
    entry = {
        "id": uuid.uuid4().hex[:8],
        "service_name": name,
        "decision": decision,
        "analyst": (analyst or "").strip(),
        "notes": (notes or "").strip(),
        "timestamp": _now(),
        "hostname": hostname,
        "category": snapshot.get("category"),
        "state": snapshot.get("state"),
        "start_mode": snapshot.get("start_mode"),
        "account": snapshot.get("account"),
        "executable_path": snapshot.get("exe_path"),
        "sha256": snapshot.get("sha256"),
        "signer": snapshot.get("signer"),
        "signature": snapshot.get("signature"),
        "threat_score": snapshot.get("threat_score"),
        "threat_level": snapshot.get("threat_level"),
        "reliability_score": snapshot.get("reliability_score"),
        "reliability_level": snapshot.get("reliability_level"),
        "threat_reasons": snapshot.get("threat_reasons_text"),
        "evidence_complete": bool(snapshot.get("sha256")),
    }
    storage.append_jsonl(config.triage_file(), entry)
    storage.log("ACTION", f"Triage {decision} recorded for {name} by {entry['analyst'] or 'unattributed'}")
    return entry


def list_all() -> list[dict]:
    records = storage.read_jsonl(config.triage_file())
    return sorted(records, key=lambda item: str(item.get("timestamp", "")), reverse=True)


def latest_by_service() -> dict[str, dict]:
    return storage.latest_by(list_all(), "service_name")


def counts() -> dict[str, int]:
    tally: dict[str, int] = {}
    for entry in list_all():
        key = str(entry.get("decision") or "Unknown")
        tally[key] = tally.get(key, 0) + 1
    return tally
