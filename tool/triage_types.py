"""Shared data model and constants for LogTriage.

Standard library only. Timestamps are stored as naive datetimes normalised to
UTC so that all correlation windows are comparable.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOOL_NAME = "LogTriage"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
DEFAULT_MAX_BYTES = 50 * 1024 * 1024
MAX_LINE_CHARS = 10_000

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"info": 0, "low": 3, "medium": 10, "high": 25, "critical": 40}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def utc_now() -> datetime:
    """Current UTC time as a naive datetime (the project's internal format)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso_z(value: datetime | None) -> str | None:
    """Serialise a naive UTC datetime as ISO-8601 with a trailing Z."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.replace(microsecond=0).isoformat(timespec="seconds") + "Z"


def risk_level_for(score: int) -> str:
    if score <= 0:
        return "clean"
    if score < 20:
        return "low"
    if score < 45:
        return "medium"
    if score < 70:
        return "high"
    return "critical"


def display_path(path: Path) -> str:
    """Return a reproducible relative path without leaking the local username."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return path.name


@dataclass
class Config:
    window_seconds: int = 600
    brute_threshold: int = 5
    scan_threshold: int = 10
    port_scan_threshold: int = 8
    success_window_seconds: int = 1800
    assume_year: int = field(default_factory=lambda: datetime.now().year)
    max_bytes: int = DEFAULT_MAX_BYTES

    def validate(self) -> None:
        positive = {
            "window_seconds": self.window_seconds,
            "brute_threshold": self.brute_threshold,
            "scan_threshold": self.scan_threshold,
            "port_scan_threshold": self.port_scan_threshold,
            "success_window_seconds": self.success_window_seconds,
            "max_bytes": self.max_bytes,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")
        if not (1970 <= self.assume_year <= 2100):
            raise ValueError("assume_year must be between 1970 and 2100")


@dataclass
class Event:
    line_no: int
    raw: str
    timestamp: datetime | None
    source_type: str
    event: str
    host: str | None = None
    src_ip: str | None = None
    username: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    domain: str | None = None
    dst_port: int | None = None
    message: str = ""


@dataclass
class Watchlist:
    ips: dict[str, dict[str, Any]] = field(default_factory=dict)
    domains: dict[str, dict[str, Any]] = field(default_factory=dict)
    hashes: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_path: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def indicator_count(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.hashes)

    def lookup(self, kind: str, value: str) -> dict[str, Any] | None:
        if kind == "ipv4":
            return self.ips.get(value)
        if kind == "domain":
            return self.domains.get(value.lower().rstrip("."))
        if kind == "hash":
            return self.hashes.get(value.lower())
        return None

    def summary(self) -> dict[str, int]:
        return {
            "ips": len(self.ips),
            "domains": len(self.domains),
            "hashes": len(self.hashes),
        }


@dataclass
class IOC:
    value: str
    kind: str  # ipv4 | domain | url | hash
    scope: str | None = None
    note: str | None = None
    hash_type: str | None = None
    hits: int = 0
    lines: list[int] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    contexts: Counter = field(default_factory=Counter)
    source_ips: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    watchlist: dict[str, Any] | None = None

    def observe(self, event: Event) -> None:
        self.hits += 1
        self.lines.append(event.line_no)
        if event.timestamp is not None:
            if self.first_seen is None or event.timestamp < self.first_seen:
                self.first_seen = event.timestamp
            if self.last_seen is None or event.timestamp > self.last_seen:
                self.last_seen = event.timestamp
        self.contexts[event.event] += 1
        if event.src_ip:
            self.source_ips.add(event.src_ip)
        if event.host:
            self.hosts.add(event.host)


@dataclass
class Finding:
    finding_id: str
    rule: str
    title: str
    severity: str
    confidence: str
    description: str
    recommendation: str
    mitre: list[str] = field(default_factory=list)
    source_ip: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 0
    evidence_lines: list[int] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TriageResult:
    input_path: Path
    display_path: str
    size_bytes: int
    sha256: str
    line_count: int
    nonblank_lines: int
    events: list[Event]
    findings: list[Finding]
    iocs: list[IOC]
    risk_score: int
    risk_level: str
    config: Config
    watchlist: Watchlist
    watchlist_path: str | None
    generated_at: datetime
    stats: dict[str, Any]
