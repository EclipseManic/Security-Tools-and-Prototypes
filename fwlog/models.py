"""Data structures shared by the generator, parser, analyzer and report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Event:
    """One parsed firewall deny/drop record."""

    ts: datetime
    host: str
    action: str
    src: str
    dst: str
    proto: str
    spt: int | None = None
    dpt: int | None = None
    flags: str = ""

    def to_log_line(self) -> str:
        """Render back to the synthetic netfilter-ish format used on disk."""
        stamp = self.ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.ts.microsecond // 1000:03d}Z"
        spt = f" SPT={self.spt}" if self.spt is not None else ""
        dpt = f" DPT={self.dpt}" if self.dpt is not None else ""
        flags = f" FLAGS={self.flags}" if self.flags else ""
        return (
            f"{stamp} {self.host} kernel: {self.action} IN=eth0 OUT= "
            f"SRC={self.src} DST={self.dst} PROTO={self.proto}{spt}{dpt}{flags}"
        )


@dataclass
class ScanConfig:
    """Detection thresholds. Every number here is a deliberate trade-off."""

    window_minutes: int = 15
    min_distinct_ports: int = 20
    min_distinct_hosts: int = 15
    max_hosts_for_vertical: int = 2
    max_ports_for_horizontal: int = 3
    distributed_min_sources: int = 5
    distributed_min_events_per_source: int = 2
    distributed_max_events_per_source: int = 6
    enable_long_baseline: bool = True
    benign_volume_threshold: int = 20

    def to_dict(self) -> dict:
        return {
            "window_minutes": self.window_minutes,
            "min_distinct_ports": self.min_distinct_ports,
            "min_distinct_hosts": self.min_distinct_hosts,
            "max_hosts_for_vertical": self.max_hosts_for_vertical,
            "max_ports_for_horizontal": self.max_ports_for_horizontal,
            "distributed_min_sources": self.distributed_min_sources,
            "distributed_min_events_per_source": self.distributed_min_events_per_source,
            "distributed_max_events_per_source": self.distributed_max_events_per_source,
            "enable_long_baseline": self.enable_long_baseline,
        }


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    total_lines: int = 0
    skipped: int = 0
    skipped_samples: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    config: ScanConfig
    input_path: str
    event_count: int
    total_lines: int
    skipped_lines: int
    time_range: tuple[datetime, datetime] | None
    source_count: int
    findings: list[dict]
    gaps: list[dict]
    reputation_assumptions: list[dict]
    unflagged_volume: list[dict]
    protocol_mix: dict
    target_count: int
