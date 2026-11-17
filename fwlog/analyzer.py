"""Detection engine: scan patterns, reputation view, and detection gaps.

Three things are produced for every run:

1. Findings - ranked per-source scan patterns with the evidence behind them.
2. A reputation view - what the source's address space implies, and what that
   implication would look like if it were wrong.
3. Detection gaps - what this log CANNOT tell you, quantified rather than
   asserted, so the reader knows where the blind spots are.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import reputation
from .models import AnalysisResult, Event, ScanConfig

# The sweep holds the port threshold at the default: on this data varying it
# moved nothing, and a dead axis in a sensitivity table is worse than no axis.
DEFAULT_MIN_PORTS = 20

LABELS = {
    "vertical_port_scan": "Vertical port scan (one target, many ports)",
    "horizontal_sweep": "Horizontal sweep (many targets, few ports)",
    "compound_scan": "Compound scan (many targets and many ports)",
    "slow_port_scan": "Slow vertical port scan (long baseline, sub-threshold per window)",
    "slow_horizontal_sweep": "Slow horizontal sweep (long baseline, sub-threshold per window)",
    "distributed_probe": "Distributed probe (many sources, one service port)",
}

RATIONALE = {
    "vertical_port_scan":
        "Distinct destination ports inside one window far exceed the threshold while "
        "the target set stays tiny: the signature of enumerating services on a host.",
    "horizontal_sweep":
        "Distinct destination hosts inside one window far exceed the threshold while "
        "the port set stays tiny: the signature of hunting one service across a subnet.",
    "compound_scan":
        "Both port and host breadth breach their thresholds in the same window: a full "
        "enumeration, not a single-service probe.",
    "slow_port_scan":
        "Total port breadth is high but no window ever reaches the trigger value, so a "
        "windowed threshold scores this far below threshold. Caught only by a "
        "long-baseline rule - and that rule is what a real attacker paces against.",
    "slow_horizontal_sweep":
        "Total host breadth is high but no window ever reaches the trigger value: a "
        "paced sweep that defeats any short-window detector.",
    "distributed_probe":
        "Each source stays under every per-source threshold, but the sources converge "
        "on the same service port. Per-source detection cannot see this at all.",
}


@dataclass
class SourceStats:
    src: str
    events: list[Event]
    ports: list[int]
    hosts: list[str]
    max_ports_in_window: int = 0
    max_hosts_in_window: int = 0
    sequential_ratio: float = 0.0
    arrival_cv: float = 0.0
    duration_min: float = 0.0
    rate_per_min: float = 0.0
    protocols: set[str] = field(default_factory=set)
    flags: set[str] = field(default_factory=set)

    @property
    def distinct_ports(self) -> int:
        return len(self.ports)

    @property
    def distinct_hosts(self) -> int:
        return len(self.hosts)

    @property
    def first(self) -> datetime:
        return self.events[0].ts

    @property
    def last(self) -> datetime:
        return self.events[-1].ts


def _max_distinct_in_window(events: list[Event], window_minutes: int, attr: str) -> int:
    """Largest number of distinct values of `attr` inside any sliding window."""
    if not events:
        return 0
    window = timedelta(minutes=window_minutes)
    counts: Counter = Counter()
    best = 0
    left = 0
    for right, event in enumerate(events):
        value = getattr(event, attr)
        if value is not None:
            counts[value] += 1
        while events[right].ts - events[left].ts > window:
            old = getattr(events[left], attr)
            if old is not None:
                counts[old] -= 1
                if counts[old] <= 0:
                    del counts[old]
            left += 1
        best = max(best, len(counts))
    return best


def _sequential_ratio(ports: list[int]) -> float:
    """Share of adjacent sorted ports that are exactly one apart (scanner order)."""
    ordered = sorted(set(ports))
    if len(ordered) < 2:
        return 0.0
    steps = sum(1 for a, b in zip(ordered, ordered[1:]) if b - a == 1)
    return steps / (len(ordered) - 1)


def _arrival_cv(events: list[Event]) -> float:
    """Coefficient of variation of inter-arrival time. Low = machine-paced."""
    if len(events) < 3:
        return 1.0
    deltas = [
        (b.ts - a.ts).total_seconds() for a, b in zip(events, events[1:])
    ]
    mean = statistics.fmean(deltas)
    if mean <= 0:
        return 1.0
    return min(1.0, statistics.pstdev(deltas) / mean)


def sequence_holes(values: list[int], min_run: int = 8) -> list[int]:
    """Single values missing from the middle of a long contiguous ascending run.

    In a deny log a hole is the tell: the scanner walked 1,2,3,...,442,444 - so
    something answered on 443 and the connection was permitted, never denied.
    """
    ordered = sorted(set(values))
    holes: list[int] = []
    for index in range(len(ordered) - 1):
        if ordered[index + 1] - ordered[index] != 2:
            continue
        start = index
        while start > 0 and ordered[start] - ordered[start - 1] == 1:
            start -= 1
        end = index + 1
        while end < len(ordered) - 1 and ordered[end + 1] - ordered[end] == 1:
            end += 1
        # A hole only counts inside a long contiguous run: one gap in a
        # two-port coincidence is noise, one gap in 1,024 ports is a finding.
        if end - start + 1 >= min_run:
            holes.append(ordered[index] + 1)
    return holes


def _host_octet(host: str) -> int | None:
    try:
        return int(host.rsplit(".", 1)[-1])
    except ValueError:
        return None


def host_holes(hosts: list[str], min_run: int = 8) -> list[str]:
    """Hosts missing from a dense single-/24 sweep - absent, or not blocking."""
    by_prefix: dict[str, list[int]] = defaultdict(list)
    for host in hosts:
        octet = _host_octet(host)
        if octet is None:
            continue
        by_prefix[host.rsplit(".", 1)[0]].append(octet)
    holes: list[str] = []
    for prefix, octets in by_prefix.items():
        for missing in sequence_holes(octets, min_run=min_run):
            holes.append(f"{prefix}.{missing}")
    return holes


def _stats(src: str, events: list[Event], config: ScanConfig) -> SourceStats:
    ports = sorted({e.dpt for e in events if e.dpt is not None})
    hosts = sorted({e.dst for e in events})
    span_min = max(0.0, (events[-1].ts - events[0].ts).total_seconds() / 60.0)
    return SourceStats(
        src=src,
        events=events,
        ports=ports,
        hosts=hosts,
        max_ports_in_window=_max_distinct_in_window(events, config.window_minutes, "dpt"),
        max_hosts_in_window=_max_distinct_in_window(events, config.window_minutes, "dst"),
        sequential_ratio=_sequential_ratio(ports),
        arrival_cv=_arrival_cv(events),
        duration_min=span_min,
        rate_per_min=len(events) / span_min if span_min > 0 else float(len(events)),
        protocols={e.proto for e in events},
        flags={e.flags for e in events if e.flags},
    )


def _severity(score: float) -> str:
    """Confidence bands, not damage bands. 0.55 is where the evidence stops
    being explainable by coincidence."""
    if score >= 0.80:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def _score_vertical(stats: SourceStats, config: ScanConfig) -> float:
    breadth = min(1.0, stats.max_ports_in_window / (config.min_distinct_ports * 2))
    regularity = 1.0 - stats.arrival_cv
    return min(1.0, 0.55 * breadth + 0.25 * stats.sequential_ratio + 0.20 * regularity)


def _score_horizontal(stats: SourceStats, config: ScanConfig) -> float:
    breadth = min(1.0, stats.max_hosts_in_window / (config.min_distinct_hosts * 2))
    single_service = 1.0 - min(1.0, stats.distinct_ports / 6.0)
    regularity = 1.0 - stats.arrival_cv
    return min(1.0, 0.50 * breadth + 0.30 * single_service + 0.20 * regularity)


def _score_slow(stats: SourceStats, config: ScanConfig) -> float:
    breadth = min(1.0, stats.distinct_ports / (config.min_distinct_ports * 4))
    patience = 1.0 - min(1.0, stats.max_ports_in_window / config.min_distinct_ports)
    return min(1.0, 0.45 * breadth + 0.35 * patience + 0.20 * stats.sequential_ratio)


def _finding(kind: str, stats: SourceStats, score: float, extra: dict | None = None) -> dict:
    evidence = {
        "events": len(stats.events),
        "distinct_dst_ports": stats.distinct_ports,
        "distinct_dst_hosts": stats.distinct_hosts,
        "targets": stats.hosts[:10],
        "ports_sample": sorted(set(stats.ports))[:20],
        "max_distinct_ports_in_window": stats.max_ports_in_window,
        "max_distinct_hosts_in_window": stats.max_hosts_in_window,
        "events_per_minute": round(stats.rate_per_min, 3),
        "sequential_port_ratio": round(stats.sequential_ratio, 3),
        "arrival_regularity": round(1.0 - stats.arrival_cv, 3),
        "protocols": sorted(stats.protocols),
        "tcp_flags": sorted(stats.flags),
    }
    if extra:
        evidence.update(extra)
    score = round(score, 3)
    return {
        "kind": kind,
        "label": LABELS[kind],
        "src": stats.src,
        "score": score,
        "severity": _severity(score),
        "first_seen": stats.first.isoformat().replace("+00:00", "Z"),
        "last_seen": stats.last.isoformat().replace("+00:00", "Z"),
        "duration_minutes": round(stats.duration_min, 1),
        "evidence": evidence,
        "rationale": RATIONALE[kind],
        "reputation": reputation.assess(stats.src, score),
    }


def _classify_source(stats: SourceStats, config: ScanConfig) -> list[dict]:
    findings: list[dict] = []
    vertical = (
        stats.max_ports_in_window >= config.min_distinct_ports
        and stats.distinct_hosts <= config.max_hosts_for_vertical
    )
    horizontal = (
        stats.max_hosts_in_window >= config.min_distinct_hosts
        and stats.distinct_ports <= config.max_ports_for_horizontal
    )
    holes_ports = sequence_holes(stats.ports)
    holes_hosts = host_holes(stats.hosts)

    if vertical and horizontal:
        findings.append(_finding("compound_scan", stats, _score_vertical(stats, config), {
            "coverage_holes_ports": holes_ports,
            "coverage_holes_hosts": holes_hosts,
        }))
    elif vertical:
        findings.append(_finding("vertical_port_scan", stats, _score_vertical(stats, config), {
            "coverage_holes_ports": holes_ports,
            "coverage_holes_hosts": [],
        }))
    elif horizontal:
        findings.append(_finding("horizontal_sweep", stats, _score_horizontal(stats, config), {
            "coverage_holes_ports": [],
            "coverage_holes_hosts": holes_hosts,
        }))
    elif config.enable_long_baseline:
        if (stats.distinct_ports >= config.min_distinct_ports
                and stats.max_ports_in_window < config.min_distinct_ports):
            findings.append(_finding("slow_port_scan", stats, _score_slow(stats, config), {
                "coverage_holes_ports": holes_ports,
                "coverage_holes_hosts": [],
                "windowed_rule_would_score": stats.max_ports_in_window,
                "windowed_rule_threshold": config.min_distinct_ports,
            }))
        elif (stats.distinct_hosts >= config.min_distinct_hosts
                and stats.max_hosts_in_window < config.min_distinct_hosts):
            findings.append(_finding("slow_horizontal_sweep", stats,
                                     _score_slow(stats, config), {
                "coverage_holes_ports": [],
                "coverage_holes_hosts": holes_hosts,
                "windowed_rule_would_score": stats.max_hosts_in_window,
                "windowed_rule_threshold": config.min_distinct_hosts,
            }))
    return findings


def _distributed_findings(events: list[Event], config: ScanConfig,
                          flagged: set[str]) -> list[dict]:
    """Sources that stay sub-threshold alone but converge on the same services.

    One finding per source-set, not per port: a campaign that probes SSH and two
    web ports from the same six hosts is one campaign, and splitting it into
    three findings would hide that.
    """
    by_port: dict[int, Counter] = defaultdict(Counter)
    by_port_targets: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for event in events:
        if event.dpt is not None:
            by_port[event.dpt][event.src] += 1
            by_port_targets[event.dpt][event.src].add(event.dst)

    clusters: dict[frozenset[str], dict[int, dict[str, int]]] = {}
    for port, counter in sorted(by_port.items()):
        # A single stray SYN is noise; a distributed probe means the same source
        # came back to the same service port more than once.
        qualifying = {
            src: count for src, count in counter.items()
            if count >= config.distributed_min_events_per_source
        }
        if len(qualifying) < config.distributed_min_sources:
            continue
        if max(qualifying.values()) > config.distributed_max_events_per_source:
            continue
        if set(qualifying) & flagged:
            continue
        # ... and they must converge on the same targets. Six unrelated hosts
        # that each happened to deny the same port twice are not a campaign.
        target_hits: Counter = Counter()
        for src in qualifying:
            target_hits.update(by_port_targets[port][src])
        shared_needed = max(2, -(-3 * len(qualifying) // 5))
        if not target_hits or max(target_hits.values()) < shared_needed:
            continue
        clusters.setdefault(frozenset(qualifying), {})[port] = qualifying

    findings: list[dict] = []
    for key, ports in sorted(clusters.items(), key=lambda item: -len(item[1])):
        srcs = sorted(key)
        ports_sorted = sorted(ports)
        per_port_medians = [statistics.median(counts.values()) for counts in ports.values()]
        breadth = min(1.0, len(srcs) / (config.distributed_min_sources * 2))
        persistence = min(1.0, max(per_port_medians) /
                          config.distributed_max_events_per_source)
        score = min(0.95, 0.60 * breadth + 0.40 * persistence)
        all_counts = [count for counts in ports.values() for count in counts.values()]
        totals: Counter = Counter()
        for counts in ports.values():
            totals.update(counts)
        shared: Counter = Counter()
        for port in ports:
            for src in srcs:
                shared.update(by_port_targets[port][src])
        shared_target, shared_count = (shared.most_common(1)[0] if shared else ("?", 0))
        findings.append({
            "kind": "distributed_probe",
            "label": LABELS["distributed_probe"],
            "src": f"{len(srcs)} sources -> port(s) {','.join(str(p) for p in ports_sorted)}",
            "sources": srcs,
            "target_ports": ports_sorted,
            "score": round(score, 3),
            "severity": _severity(score),
            "first_seen": "",
            "last_seen": "",
            "duration_minutes": 0.0,
            "evidence": {
                "distinct_sources": len(srcs),
                "events": sum(all_counts),
                "target_ports": ports_sorted,
                "events_per_port": {str(port): sum(counts.values())
                                    for port, counts in sorted(ports.items())},
                "max_events_per_source": max(all_counts),
                "min_events_per_source": min(all_counts),
                "per_source_events": dict(sorted(totals.items())),
                "shared_target": shared_target,
                "sources_on_shared_target": shared_count,
                "why_invisible": (
                    f"Every source is below the per-source thresholds "
                    f"({config.min_distinct_ports} ports / {config.min_distinct_hosts} "
                    f"hosts in {config.window_minutes} min), so per-source detection "
                    f"returns nothing."
                ),
            },
            "rationale": RATIONALE["distributed_probe"],
            "reputation": reputation.assess(srcs[0], score),
        })
    return findings



def _needed_window(stats: SourceStats, config: ScanConfig, attribute: str) -> int:
    """Window size that a windowed rule would need to reach the trigger value."""
    breadth = stats.distinct_ports if attribute == "dpt" else stats.distinct_hosts
    threshold = (config.min_distinct_ports if attribute == "dpt"
                 else config.min_distinct_hosts)
    if breadth <= 0 or stats.duration_min <= 0:
        return 0
    return int(round(stats.duration_min * threshold / breadth))


def _build_gaps(findings: list[dict], stats_by_src: dict[str, SourceStats],
                config: ScanConfig, unflagged: list[dict]) -> list[dict]:
    gaps: list[dict] = []

    holes = [
        (f["src"], f["evidence"].get("coverage_holes_ports") or [],
         f["evidence"].get("coverage_holes_hosts") or [])
        for f in findings
        if f["kind"] != "distributed_probe"
    ]
    holes = [h for h in holes if h[1] or h[2]]
    if holes:
        detail = "; ".join(
            f"{src}: port(s) {ports} / host(s) {hosts}"
            for src, ports, hosts in holes
        )
        observed = f"Interior holes in contiguous scan runs - {detail}"
        impact = (
            "A hole is a place the scanner went and no deny was logged. The likely "
            "reason is that the connection was permitted (or the host did not answer). "
            "This log cannot tell those apart, so the most interesting events of the "
            "day are the ones missing from it."
        )
    else:
        observed = "No interior holes found in any contiguous run."
        impact = (
            "Absence of holes is NOT evidence of no success: a scan that stops at the "
            "first open port leaves no trace in a deny log at all."
        )
    gaps.append({
        "id": "G1",
        "title": "Deny-only telemetry: the log ends where the attack succeeds",
        "severity": "high",
        "observed": observed,
        "impact": impact,
        "close": "Ship ACCEPT/ALLOW records (or netflow) alongside denies and re-run: "
                 "the hole becomes a confirmed success instead of an inference.",
    })

    slow = [f for f in findings if f["kind"].startswith("slow_")]
    if slow:
        parts = []
        for finding in slow:
            stats = stats_by_src[finding["src"]]
            attr = "dpt" if finding["kind"] == "slow_port_scan" else "dst"
            needed = _needed_window(stats, config, attr)
            parts.append(
                f"{finding['src']} peaks at {finding['evidence']['max_distinct_ports_in_window']} "
                f"distinct ports per {config.window_minutes} min against a threshold of "
                f"{config.min_distinct_ports}; catching it with a windowed rule needs a "
                f"window of ~{needed} min ({needed // 60}h {needed % 60}m)"
            )
        gaps.append({
            "id": "G2",
            "title": "Windowed thresholds lose to a patient scanner",
            "severity": "high",
            "observed": "; ".join(parts),
            "impact": "At any practical window the paced campaign scores far below "
                      "threshold and produces no alert, while the window is short "
                      "enough to stay alertable.",
            "close": "Keep a long-baseline rule (this tool's slow_* rule) with a "
                     "per-source baseline instead of a fixed window, and alert on the "
                     "change in a source's distinct-port total per hour.",
        })
    else:
        gaps.append({
            "id": "G2",
            "title": "Windowed thresholds lose to a patient scanner",
            "severity": "high",
            "observed": f"Nothing breached the long-baseline rule at "
                        f"{config.min_distinct_ports} distinct ports.",
            "impact": "A scanner spreading N ports over many hours stays invisible to "
                      "every windowed rule and, if N is also small, to this one.",
            "close": "Baseline each source's distinct-port total per hour and alert on "
                     "deviation from its own history, not on an absolute count.",
        })

    distributed = [f for f in findings if f["kind"] == "distributed_probe"]
    if distributed:
        observed = "; ".join(
            f"{f['evidence']['distinct_sources']} sources on port(s) "
            f"{','.join(str(p) for p in f['target_ports'])}, "
            f"up to {f['evidence']['max_events_per_source']} denies each"
            for f in distributed
        )
        gaps.append({
            "id": "G3",
            "title": "Distributed sources defeat every per-source threshold",
            "severity": "high",
            "observed": observed,
            "impact": "Each source looks like a stray denial. Aggregated they are a "
                      "coordinated sweep, but nothing in a per-source rule says so.",
            "close": "Add a cross-source rule keyed on destination port (this tool's "
                     "distributed_probe) and correlate on /24 or ASN, not on address.",
        })
    else:
        gaps.append({
            "id": "G3",
            "title": "Distributed sources defeat every per-source threshold",
            "severity": "medium",
            "observed": f"No port drew {config.distributed_min_sources}+ sub-threshold "
                        f"sources in this log.",
            "impact": "The rule is silent here, which does not mean the campaign is "
                      "absent - only that it was not present in this window.",
            "close": "Keep the cross-source rule on and widen the observation period; "
                     "distributed campaigns often span days.",
        })

    gaps.append({
        "id": "G4",
        "title": "Attribution assumes SRC is the attacker",
        "severity": "medium",
        "observed": "Every finding is attributed to the SRC address in the deny record.",
        "impact": "NAT, CGNAT, a proxy, cloud egress or a VPN concentrator makes that "
                  "address a middlebox. Blocking it punishes bystanders; investigating "
                  "it wastes the response window.",
        "close": "Join SRC against NAT/translation logs before any block action; record "
                 "post-NAT identity in the log itself.",
    })

    gaps.append({
        "id": "G5",
        "title": "No threat feed, so first-seen addresses are neither cleared nor condemned",
        "severity": "medium",
        "observed": "Reputation is derived from address space plus behaviour. "
                    "feed_consulted=false on every finding.",
        "impact": "A known-bad scanner scores like any noisy host on its first visit; a "
                  "compromised partner address is never pre-cleared.",
        "close": "Join findings against your own intel and asset inventory; re-run with "
                 "a known-bad list to raise severity for confirmed addresses.",
    })

    gaps.append({
        "id": "G6",
        "title": "Thresholds create false positives and a sub-threshold blind spot at once",
        "severity": "medium",
        "observed": (
            "Unflagged but pattern-adjacent sources: "
            + (", ".join(f"{u['src']} ({u['events']} denies, "
                         f"{u['distinct_dst_hosts']} hosts, "
                         f"{u['threshold_ratio']:.0%} of trigger)"
                         for u in unflagged[:3]) if unflagged else "none")
        ),
        "impact": "Lowering the threshold flags these benign shapes; raising it hides "
                  "the next paced campaign. One fixed threshold cannot do both.",
        "close": "Run 'fwscan sweep' to read the precision/recall curve before "
                 "choosing a threshold, and allow-list known job accounts by "
                 "source+port+schedule.",
    })

    gaps.append({
        "id": "G7",
        "title": "Fields the log does not carry",
        "severity": "low",
        "observed": "No allow records, no packet/byte counts, no user or asset identity, "
                    "no ASN/geo, no sampling flag, no sensor-independent correlation id.",
        "impact": "Scan vs flood vs retransmit cannot be separated; a permitted port is "
                  "invisible; a sampled log under-counts breadth and can drop a scan "
                  "below every threshold.",
        "close": "Log ALLOW on the same sensor, add packet counts and asset owner, and "
                 "record whether the export is sampled.",
    })
    return gaps


def _unflagged_volume(stats_by_src: dict[str, SourceStats], flagged: set[str],
                      config: ScanConfig) -> list[dict]:
    rows = []
    for src, stats in stats_by_src.items():
        if src in flagged or len(stats.events) < config.benign_volume_threshold:
            continue
        ratio = max(
            stats.max_ports_in_window / config.min_distinct_ports,
            stats.max_hosts_in_window / config.min_distinct_hosts,
        )
        rows.append({
            "src": src,
            "events": len(stats.events),
            "distinct_dst_hosts": stats.distinct_hosts,
            "distinct_dst_ports": stats.distinct_ports,
            "max_ports_in_window": stats.max_ports_in_window,
            "max_hosts_in_window": stats.max_hosts_in_window,
            "threshold_ratio": round(ratio, 3),
            "address_class": reputation.classify(src),
        })
    rows.sort(key=lambda r: (r["threshold_ratio"], r["events"]), reverse=True)
    return rows


def analyze(events: list[Event], config: ScanConfig | None = None,
            input_path: str = "<memory>", total_lines: int = 0,
            skipped: int = 0) -> AnalysisResult:
    config = config or ScanConfig()
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.src].append(event)

    stats_by_src = {
        src: _stats(src, sorted(src_events, key=lambda e: e.ts), config)
        for src, src_events in grouped.items()
    }

    findings: list[dict] = []
    for src in sorted(stats_by_src):
        findings.extend(_classify_source(stats_by_src[src], config))

    flagged = {f["src"] for f in findings}
    findings.extend(_distributed_findings(events, config, flagged))
    findings.sort(key=lambda f: f["score"], reverse=True)

    unflagged = _unflagged_volume(stats_by_src, flagged, config)
    gaps = _build_gaps(findings, stats_by_src, config, unflagged)

    time_range = (events[0].ts, events[-1].ts) if events else None
    protocol_mix = dict(Counter(e.proto for e in events).most_common())
    return AnalysisResult(
        config=config,
        input_path=input_path,
        event_count=len(events),
        total_lines=total_lines or len(events),
        skipped_lines=skipped,
        time_range=time_range,
        source_count=len(grouped),
        findings=findings,
        gaps=gaps,
        reputation_assumptions=reputation.assumptions(),
        unflagged_volume=unflagged,
        protocol_mix=protocol_mix,
        target_count=len({e.dst for e in events}),
    )


def sweep(events: list[Event], truth: dict | None = None) -> list[dict]:
    """Sensitivity sweep: the detection gap, measured instead of argued.

    Runs the same log through a grid of thresholds and reports what each setting
    catches and what it invents. With truth supplied it also scores recall and
    false positives against the planted campaigns.
    """
    attack_srcs: set[str] = set()
    for campaign in (truth or {}).get("attack_campaigns", []):
        attack_srcs.update(campaign["sources"])
    benign_srcs = set((truth or {}).get("benign_sources", []))

    campaigns = (truth or {}).get("attack_campaigns", [])
    rows: list[dict] = []
    for window in (5, 15, 60):
        for min_hosts in (6, 15):
            for baseline in (False, True):
                config = ScanConfig(
                    window_minutes=window,
                    min_distinct_ports=DEFAULT_MIN_PORTS,
                    min_distinct_hosts=min_hosts,
                    enable_long_baseline=baseline,
                )
                result = analyze(events, config)
                # Distributed findings name a source set, not one address.
                flagged = {
                    src for finding in result.findings
                    for src in (finding.get("sources") or [finding["src"]])
                }
                caught = {
                    campaign["id"] for campaign in campaigns
                    if set(campaign["sources"]) & flagged
                }
                missed = sorted(
                    campaign["id"] for campaign in campaigns
                    if campaign["id"] not in caught
                )
                false_pos = sorted(flagged & benign_srcs)
                unlabelled = sorted(flagged - attack_srcs - benign_srcs)
                rows.append({
                    "window_minutes": window,
                    "min_ports": DEFAULT_MIN_PORTS,
                    "min_hosts": min_hosts,
                    "long_baseline": baseline,
                    "flagged": len(flagged),
                    "campaigns_caught": sorted(caught),
                    "campaigns_missed": missed,
                    "false_positive_sources": false_pos,
                    "unlabelled_sources": unlabelled,
                    "recall": round(len(caught) / len(campaigns), 3) if campaigns else 0.0,
                    "false_positives": len(false_pos),
                })
    return rows

