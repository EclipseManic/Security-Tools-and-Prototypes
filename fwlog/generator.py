"""Synthetic firewall deny-log generator with planted scan campaigns.

The log is a single day of DENY records from one perimeter firewall. Four
attack campaigns are planted next to realistic benign noise, and every planted
campaign is written to a ground-truth dict so the analyzer can be scored
honestly instead of being graded on the data it was tuned on.

Ground truth exists ONLY because this data is synthetic. On real logs you would
label from incident tickets or allow-logs, not from a generator.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .models import Event

DAY = datetime(2025, 3, 1, tzinfo=timezone.utc)
FIREWALL = "fw01"

# 10.0.4.0/24 is the internal lab subnet. 443 is permitted to 10.0.4.12 only.
INTERNAL_PREFIX = "10.0.4."
TARGET_HOST = "10.0.4.12"

SCAN_A_SRC = "203.0.113.45"       # fast vertical SYN scan, 443 permitted
SCAN_B_SRC = "198.51.100.77"      # horizontal sweep of the /24
SCAN_C_SRCS = [f"192.0.2.{i}" for i in range(11, 17)]  # distributed low-and-slow
SCAN_D_SRC = "203.0.113.90"       # single slow vertical scan, sub-threshold
BACKUP_SRC = "10.0.4.50"          # benign: looks like a sweep, is not one
ADMIN_SRC = "10.0.4.21"           # benign: fat-fingered ports

SWEEP_MISSING_HOSTS = (99, 200)   # absent from the deny log during the /24 sweep


def _ephemeral(rng: random.Random) -> int:
    return rng.randint(32768, 60999)


def _event(ts: datetime, src: str, dst: str, dpt: int, rng: random.Random,
           proto: str = "TCP", flags: str = "SYN", action: str = "DENY") -> Event:
    return Event(
        ts=ts, host=FIREWALL, action=action, src=src, dst=dst,
        proto=proto, spt=_ephemeral(rng), dpt=dpt, flags=flags,
    )


def _campaign_a(rng: random.Random) -> list[Event]:
    """Vertical SYN scan: 1023 denied ports on one host in ~9 minutes.

    Port 443 never appears in the deny log because it is permitted on
    10.0.4.12. That single missing port inside an otherwise contiguous run is
    the most valuable signal in the whole dataset.
    """
    events: list[Event] = []
    start = DAY + timedelta(hours=3, minutes=14)
    step = 0.52
    offset = 0.0
    for port in range(1, 1025):
        if port == 443:
            continue
        offset += step * rng.uniform(0.75, 1.25)
        events.append(_event(start + timedelta(seconds=offset), SCAN_A_SRC,
                             TARGET_HOST, port, rng))
    return events


def _campaign_b(rng: random.Random) -> list[Event]:
    """Horizontal sweep: 3 service ports across the whole /24 in ~11 minutes."""
    events: list[Event] = []
    start = DAY + timedelta(hours=4, minutes=2)
    offset = 0.0
    for host in range(1, 255):
        if host in SWEEP_MISSING_HOSTS:
            continue
        for port in (445, 139, 3389):
            offset += 0.9 * rng.uniform(0.7, 1.3)
            events.append(_event(start + timedelta(seconds=offset), SCAN_B_SRC,
                                 f"{INTERNAL_PREFIX}{host}", port, rng))
    return events


def _campaign_c(rng: random.Random) -> list[Event]:
    """Distributed low-and-slow: 6 sources, each far below any per-source
    threshold, converging on SSH across a whole day."""
    events: list[Event] = []
    for index, src in enumerate(SCAN_C_SRCS):
        start = DAY + timedelta(minutes=40 + index * 11)
        for k in range(8):
            ts = start + timedelta(minutes=k * 170)
            host = f"{INTERNAL_PREFIX}{rng.choice([31, 32, 33, 34])}"
            port = 22 if k % 2 == 0 else rng.choice([80, 8080])
            events.append(_event(ts, src, host, port, rng))
    return events


def _campaign_d(rng: random.Random) -> list[Event]:
    """Slow vertical scan: 40 ports, one every 33 minutes.

    Any 15-minute window contains at most one port, so a windowed threshold
    scores this at 1/20th of the trigger value. It is the campaign that a
    naive detector misses, and it is why the tool ships a long-baseline rule.
    """
    ports = [21, 22, 23, 25, 53, 67, 69, 80, 110, 111, 123, 135, 137, 138,
             139, 143, 161, 162, 179, 389, 445, 465, 512, 513, 514, 587, 631,
             636, 873, 993, 995, 1080, 1433, 1521, 2049, 2375, 3306, 3389,
             5432, 5900]
    events: list[Event] = []
    start = DAY + timedelta(minutes=20)
    for k, port in enumerate(ports):
        ts = start + timedelta(minutes=33 * k, seconds=rng.randint(0, 90))
        events.append(_event(ts, SCAN_D_SRC, TARGET_HOST, port, rng))
    return events


def _benign_backup(rng: random.Random) -> list[Event]:
    """A nightly job denied on 445 against 6 hosts every 10 minutes.

    Six hosts is below the 15-host sweep threshold, but it is exactly the shape
    of a horizontal scan. Raising sensitivity turns this into a false positive;
    that trade-off is the whole point of the sensitivity sweep command.
    """
    events: list[Event] = []
    start = DAY + timedelta(minutes=5)
    for cycle in range(144):
        ts = start + timedelta(minutes=10 * cycle)
        for host in range(2, 8):
            events.append(_event(ts + timedelta(seconds=rng.uniform(0, 20)),
                                 BACKUP_SRC, f"{INTERNAL_PREFIX}{host}", 445, rng))
    return events


def _benign_admin(rng: random.Random) -> list[Event]:
    """A human mistyping SSH ports five times in a row."""
    start = DAY + timedelta(hours=9, minutes=12)
    return [
        _event(start + timedelta(seconds=40 * i + rng.uniform(0, 15)), ADMIN_SRC,
               TARGET_HOST, port, rng)
        for i, port in enumerate([2222, 2022, 22222, 2223, 22022])
    ]


def _benign_noise(rng: random.Random) -> list[Event]:
    """Background denials: one to three strays per internal host, all day."""
    common = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5900, 8080, 9200]
    events: list[Event] = []
    for host in range(1, 41):
        src = f"{INTERNAL_PREFIX}{host}"
        for _ in range(rng.randint(1, 3)):
            ts = DAY + timedelta(minutes=rng.uniform(0, 1439))
            dst = f"{INTERNAL_PREFIX}{rng.randint(1, 40)}"
            events.append(_event(ts, src, dst, rng.choice(common), rng))
    return events


def generate(seed: int = 7, include_attacks: bool = True) -> tuple[list[Event], dict]:
    """Build the day of events and the matching ground-truth dict."""
    rng = random.Random(seed)
    events: list[Event] = []
    campaigns: list[dict] = []

    events += _benign_backup(rng)
    events += _benign_admin(rng)
    events += _benign_noise(rng)

    if include_attacks:
        a = _campaign_a(rng)
        b = _campaign_b(rng)
        c = _campaign_c(rng)
        d = _campaign_d(rng)
        events += a + b + c + d
        campaigns = [
            {
                "id": "A", "pattern": "vertical_port_scan",
                "sources": [SCAN_A_SRC], "target": TARGET_HOST,
                "events": len(a),
                "detail": "SYN scan of ports 1-1024 in ~9 min; 443 absent from the "
                          "deny log because it is permitted on the target",
            },
            {
                "id": "B", "pattern": "horizontal_sweep",
                "sources": [SCAN_B_SRC], "target": "10.0.4.0/24",
                "events": len(b),
                "detail": "ports 445/139/3389 across 252 hosts in ~11 min",
            },
            {
                "id": "C", "pattern": "distributed_low_and_slow",
                "sources": SCAN_C_SRCS, "target": "10.0.4.31-34",
                "events": len(c),
                "detail": "6 sources, 8 denies each, converging on port 22 all day",
            },
            {
                "id": "D", "pattern": "slow_port_scan",
                "sources": [SCAN_D_SRC], "target": TARGET_HOST,
                "events": len(d),
                "detail": "40 ports, one every 33 min: invisible to any 15-min window",
            },
        ]

    events.sort(key=lambda e: e.ts)
    truth = {
        "seed": seed,
        "synthetic": True,
        "firewall": FIREWALL,
        "window_utc": "2025-03-01T00:00:00Z .. 2025-03-02T00:00:00Z",
        "attack_campaigns": campaigns,
        "benign_sources": [BACKUP_SRC, ADMIN_SRC],
        "event_count": len(events),
        "note": "Ground truth is known only because this log is synthetic. "
                "Do not treat the scores as real-world accuracy.",
    }
    return events, truth


def write_log(events: list[Event], path: str) -> int:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(event.to_log_line() + "\n")
    return len(events)
