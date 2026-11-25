"""Tolerant parser for firewall deny logs.

Accepts the synthetic netfilter-style format and anything else that carries
SRC=/DST=/DPT= style key/value pairs (iptables LOG, Fortinet, pf, Zeek notice).
A line is kept only if it names a deny action and both a source and a
destination; everything else is counted as skipped so the gap analysis can
report it instead of silently dropping it.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .models import Event, ParseResult

_ACTION = re.compile(r"\b(DENY|DENIED|DROP|DROPPED|REJECT|REJECTED|BLOCK|BLOCKED)\b", re.I)
_KV = re.compile(r"\b([A-Za-z_]+)=([^\s,;]+)")
_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z?"
)
_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SRC_KEYS = ("SRC", "SRCIP", "SOURCE", "SRCADDR", "IP_SRC")
_DST_KEYS = ("DST", "DSTIP", "DEST", "DESTINATION", "DSTADDR", "IP_DST")
_DPT_KEYS = ("DPT", "DPORT", "DSTPORT", "DPT_PORT", "DPORT_NUM")


def _first(kv: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if key in kv:
            return kv[key]
    return None


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    digits = re.sub(r"[^0-9]", "", value)
    if not digits:
        return None
    try:
        return int(digits)
    except ValueError:
        return None


def parse_timestamp(line: str, default_year: int = 2025) -> datetime | None:
    """Parse an ISO-8601 or BSD syslog timestamp from the head of a line."""
    match = _ISO.match(line)
    if match:
        year, month, day, hour, minute, second, frac = match.groups()
        micro = int((frac or "0").ljust(6, "0")[:6])
        try:
            return datetime(
                int(year), int(month), int(day),
                int(hour), int(minute), int(second), micro, tzinfo=timezone.utc,
            )
        except ValueError:
            return None
    match = _SYSLOG.match(line)
    if match:
        month_name, day, hour, minute, second = match.groups()
        month = _MONTHS.get(month_name)
        if month is None:
            return None
        try:
            return datetime(
                default_year, month, int(day),
                int(hour), int(minute), int(second), tzinfo=timezone.utc,
            )
        except ValueError:
            return None
    return None


def parse_line(line: str, default_year: int = 2025, default_host: str = "fw01") -> Event | None:
    """Parse one log line. Returns None when the line is not a usable deny record."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    action_match = _ACTION.search(text)
    if not action_match:
        return None
    kv = {key.upper(): value for key, value in _KV.findall(text)}
    src = _first(kv, _SRC_KEYS)
    dst = _first(kv, _DST_KEYS)
    if not src or not dst:
        return None
    ts = parse_timestamp(text, default_year)
    if ts is None:
        return None
    head = text.split()
    host = head[1] if len(head) > 1 else default_host
    return Event(
        ts=ts,
        host=host,
        action=action_match.group(1).upper(),
        src=src,
        dst=dst,
        proto=(kv.get("PROTO") or kv.get("PROT") or "?").upper(),
        spt=_as_int(_first(kv, ("SPT", "SPORT", "SRCPORT"))),
        dpt=_as_int(_first(kv, _DPT_KEYS)),
        flags=kv.get("FLAGS", "").upper(),
    )


def parse_text(text: str, default_year: int = 2025) -> ParseResult:
    result = ParseResult()
    for raw in text.splitlines():
        result.total_lines += 1
        if not raw.strip():
            continue
        event = parse_line(raw, default_year)
        if event is None:
            result.skipped += 1
            if len(result.skipped_samples) < 5:
                result.skipped_samples.append(raw.strip()[:160])
            continue
        result.events.append(event)
    result.events.sort(key=lambda e: e.ts)
    return result


def parse_file(path: str, default_year: int = 2025) -> ParseResult:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_text(handle.read(), default_year)
