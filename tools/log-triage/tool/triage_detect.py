"""Watchlist loading, behavioural detections, scoring, and orchestration."""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from triage_parse import build_iocs, sensitive_labels
from triage_types import (
    SEVERITY_RANK,
    SEVERITY_WEIGHT,
    Config,
    Event,
    Finding,
    IOC,
    Watchlist,
    iso_z,
    risk_level_for,
)

def _plural(count: int, singular: str, plural: str | None = None) -> str:
    if count == 1:
        return singular
    return plural if plural is not None else singular + "s"


SCANNER_UA_RE = re.compile(
    r"(?P<tool>sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|"
    r"gobuster|ffuf|acunetix|netsparker|openvas)\b",
    re.IGNORECASE,
)


def _normalise_entries(
    raw: Any, kind: str, warnings: list[str]
) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    if raw is None:
        return entries
    if isinstance(raw, dict):
        pairs = list(raw.items())
    elif isinstance(raw, list):
        pairs = [(value, {}) for value in raw]
    else:
        raise ValueError(f"watchlist category '{kind}' must be an object or list")

    for value, metadata in pairs:
        text = str(value).strip()
        if isinstance(metadata, str):
            metadata = {"label": metadata}
        elif not isinstance(metadata, dict):
            metadata = {"label": str(metadata)}
        else:
            metadata = dict(metadata)

        if kind == "ip":
            try:
                key = str(ipaddress.ip_address(text.strip("[]")))
            except ValueError:
                warnings.append(f"ignored invalid watchlist IP: {text!r}")
                continue
        elif kind == "domain":
            key = text.lower().rstrip(".")
            if "." not in key:
                warnings.append(f"ignored invalid watchlist domain: {text!r}")
                continue
        elif kind == "hash":
            key = text.lower()
            if len(key) not in {32, 40, 64} or not re.fullmatch(
                r"[0-9a-f]+", key
            ):
                warnings.append(f"ignored invalid watchlist hash: {text!r}")
                continue
        else:
            raise ValueError(f"unknown watchlist kind: {kind}")
        entries[key] = metadata
    return entries


def load_watchlist(path: Path | None) -> Watchlist:
    """Load the local JSON watchlist. Raises ValueError on malformed input."""
    if path is None:
        return Watchlist()
    if not path.exists():
        raise FileNotFoundError(f"watchlist not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"watchlist is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("watchlist root must be a JSON object")

    warnings: list[str] = []
    watchlist = Watchlist(source_path=str(path), warnings=warnings)
    watchlist.ips = _normalise_entries(
        data.get("ips", data.get("ipv4")), "ip", warnings
    )
    watchlist.domains = _normalise_entries(data.get("domains"), "domain", warnings)
    watchlist.hashes = _normalise_entries(data.get("hashes"), "hash", warnings)
    if watchlist.indicator_count == 0:
        warnings.append("watchlist contains no valid indicators")
    return watchlist


def cluster_events(events: Iterable[Event], window_seconds: int) -> list[list[Event]]:
    """Group timestamped events into clusters separated by more than a window."""
    ordered = sorted(
        (event for event in events if event.timestamp is not None),
        key=lambda event: (event.timestamp, event.line_no),
    )
    clusters: list[list[Event]] = []
    current: list[Event] = []
    for event in ordered:
        if not current:
            current = [event]
            continue
        gap = (event.timestamp - current[-1].timestamp).total_seconds()
        if gap <= window_seconds:
            current.append(event)
        else:
            clusters.append(current)
            current = [event]
    if current:
        clusters.append(current)
    return clusters


def _dedupe(values: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    result: list[int] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _finding(rule: str, title: str, severity: str, confidence: str,
             description: str, recommendation: str, mitre: list[str],
             source_ip: str | None, first_seen: datetime | None,
             last_seen: datetime | None, count: int,
             evidence_lines: Iterable[int], details: dict[str, Any]) -> Finding:
    return Finding(
        finding_id="",
        rule=rule,
        title=title,
        severity=severity,
        confidence=confidence,
        description=description,
        recommendation=recommendation,
        mitre=mitre,
        source_ip=source_ip,
        first_seen=first_seen,
        last_seen=last_seen,
        count=count,
        evidence_lines=_dedupe(evidence_lines),
        details=details,
    )


def detect_brute_force(events: list[Event], config: Config) -> list[Finding]:
    failed = [
        event for event in events
        if event.event == "ssh_failed_login" and event.src_ip and event.timestamp
    ]
    if not failed:
        failed = [
            event for event in events
            if event.event == "ssh_invalid_user" and event.src_ip and event.timestamp
        ]
    if not failed:
        failed = [
            event for event in events
            if event.event == "ssh_preauth_close" and event.src_ip and event.timestamp
        ]
    if not failed:
        return []

    successes = [
        event for event in events
        if event.event == "ssh_success_login" and event.src_ip and event.timestamp
    ]
    successes_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in successes:
        successes_by_ip[event.src_ip].append(event)

    failures_by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in failed:
        failures_by_ip[event.src_ip].append(event)

    findings: list[Finding] = []
    for source_ip, source_events in failures_by_ip.items():
        for cluster in cluster_events(source_events, config.window_seconds):
            if len(cluster) < config.brute_threshold:
                continue
            first, last = cluster[0], cluster[-1]
            usernames = sorted({event.username for event in cluster if event.username})
            span = max(1.0, (last.timestamp - first.timestamp).total_seconds())
            rate = round(len(cluster) / (span / 60.0), 2)

            success_window_end = last.timestamp + timedelta(
                seconds=config.success_window_seconds
            )
            successes_after = sorted(
                (
                    event for event in successes_by_ip.get(source_ip, [])
                    if first.timestamp <= event.timestamp <= success_window_end
                ),
                key=lambda event: event.timestamp,
            )
            success = successes_after[0] if successes_after else None
            spraying = len(usernames) >= 5

            if success is not None:
                severity = "critical"
                confidence = "high"
                title = (
                    f"SSH brute force succeeded for user '{success.username}' "
                    f"from {source_ip}"
                )
                description = (
                    f"{len(cluster)} failed SSH "
                    f"{_plural(len(cluster), 'authentication')} from {source_ip} "
                    f"between {iso_z(first.timestamp)} and {iso_z(last.timestamp)} "
                    f"were followed by a successful login as '{success.username}' "
                    f"at {iso_z(success.timestamp)}. This is consistent with a "
                    "successful password-guessing or password-spraying attack."
                )
                recommendation = (
                    "Treat the account and host as potentially compromised: "
                    "terminate sessions, rotate credentials and keys, review "
                    "post-login commands, and block the source address."
                )
            else:
                severity = (
                    "high"
                    if len(cluster) >= 2 * config.brute_threshold or spraying
                    else "medium"
                )
                confidence = "high" if spraying or len(cluster) >= 8 else "medium"
                title = f"SSH brute force / password spraying from {source_ip}"
                description = (
                    f"{len(cluster)} failed SSH "
                    f"{_plural(len(cluster), 'authentication')} from {source_ip} "
                    f"within {int((last.timestamp - first.timestamp).total_seconds())}s "
                    f"({len(usernames)} distinct "
                    f"{_plural(len(usernames), 'username')}). No successful login "
                    "from this source was observed in the configured success window."
                )
                recommendation = (
                    "Block the source address at the perimeter, enforce key-based "
                    "authentication, rate-limit sshd, and disable password logins "
                    "for privileged accounts."
                )

            findings.append(_finding(
                rule="brute_force",
                title=title,
                severity=severity,
                confidence=confidence,
                description=description,
                recommendation=recommendation,
                mitre=["T1110", "T1110.001", "T1110.003"],
                source_ip=source_ip,
                first_seen=first.timestamp,
                last_seen=last.timestamp,
                count=len(cluster),
                evidence_lines=[event.line_no for event in cluster],
                details={
                    "attempts": len(cluster),
                    "distinct_usernames": len(usernames),
                    "usernames": usernames[:20],
                    "pattern": "password_spraying" if spraying else "brute_force",
                    "window_seconds": config.window_seconds,
                    "observed_span_seconds": int(span),
                    "attempts_per_minute": rate,
                    "success_after_failures": success is not None,
                    "success_user": success.username if success else None,
                    "success_time": iso_z(success.timestamp) if success else None,
                },
            ))
    return findings


def detect_http_scan(events: list[Event], config: Config) -> list[Finding]:
    errors = [
        event for event in events
        if event.event == "http_request"
        and event.src_ip
        and event.timestamp
        and event.status is not None
        and event.status >= 400
    ]
    if not errors:
        return []

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in errors:
        by_ip[event.src_ip].append(event)

    findings: list[Finding] = []
    for source_ip, source_events in by_ip.items():
        for cluster in cluster_events(source_events, config.window_seconds):
            paths = sorted({event.path or "/" for event in cluster})
            if len(cluster) < config.scan_threshold and not (
                len(paths) >= 8 and len(cluster) >= 8
            ):
                continue
            first, last = cluster[0], cluster[-1]
            labels = sorted({
                label
                for event in cluster
                for label in sensitive_labels(event.path or "")
            })
            sensitive_paths = []
            for event in cluster:
                event_labels = sensitive_labels(event.path or "")
                if event_labels:
                    sensitive_paths.append({
                        "path": event.path,
                        "status": event.status,
                        "labels": event_labels,
                        "line": event.line_no,
                    })
            user_agents = sorted({
                event.user_agent for event in cluster if event.user_agent
            })
            status_counts = Counter(str(event.status) for event in cluster)

            severity = "high" if labels or len(paths) >= 10 or len(cluster) >= 15 else "medium"
            findings.append(_finding(
                rule="http_scanning",
                title=f"Web scanning from {source_ip} ({len(paths)} paths, {len(cluster)} errors)",
                severity=severity,
                confidence="high",
                description=(
                    f"{len(cluster)} HTTP 4xx/5xx "
                    f"{_plural(len(cluster), 'response')} were returned to "
                    f"{source_ip} between {iso_z(first.timestamp)} and "
                    f"{iso_z(last.timestamp)} across {len(paths)} distinct paths. "
                    f"Sensitive targets requested: {', '.join(labels) if labels else 'none'}. "
                    "The pattern is consistent with automated content discovery or "
                    "vulnerability scanning."
                ),
                recommendation=(
                    "Block the source at the edge, review web logs for successful "
                    "responses on the same paths, remove exposed files, and keep "
                    "the web server and plugins patched."
                ),
                mitre=["T1595", "T1595.002", "T1190"],
                source_ip=source_ip,
                first_seen=first.timestamp,
                last_seen=last.timestamp,
                count=len(cluster),
                evidence_lines=[event.line_no for event in cluster],
                details={
                    "distinct_paths": len(paths),
                    "paths": paths[:30],
                    "status_counts": dict(status_counts),
                    "sensitive_labels": labels,
                    "sensitive_paths": sensitive_paths[:20],
                    "user_agents": user_agents[:10],
                },
            ))
    return findings


def detect_sensitive_exposure(events: list[Event]) -> list[Finding]:
    hits = [
        event for event in events
        if event.event == "http_request"
        and event.status is not None
        and 200 <= event.status < 300
        and event.path
        and sensitive_labels(event.path)
    ]
    if not hits:
        return []

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in hits:
        by_ip[event.src_ip or "unknown"].append(event)

    findings: list[Finding] = []
    for source_ip, source_events in by_ip.items():
        exposed = []
        seen_paths: set[str] = set()
        for event in source_events:
            if event.path in seen_paths:
                continue
            seen_paths.add(event.path or "/")
            exposed.append({
                "path": event.path,
                "status": event.status,
                "labels": sensitive_labels(event.path or ""),
                "line": event.line_no,
            })
        first = min(
            (event.timestamp for event in source_events if event.timestamp),
            default=None,
        )
        last = max(
            (event.timestamp for event in source_events if event.timestamp),
            default=None,
        )
        findings.append(_finding(
            rule="sensitive_file_exposure",
            title=f"Sensitive path returned HTTP 2xx to {source_ip}",
            severity="critical",
            confidence="medium",
            description=(
                f"{len(source_events)} successful HTTP "
                f"{_plural(len(source_events), 'response')} returned "
                f"for sensitive paths requested from {source_ip}: "
                f"{', '.join(sorted(seen_paths))}. A 2xx status does not prove "
                "that useful content was served (for example, an SPA fallback can "
                "return 200), so response bodies should be checked immediately."
            ),
            recommendation=(
                "Verify the response body and access logs, remove or restrict the "
                "exposed files, rotate any credentials they contained, and block "
                "the source address."
            ),
            mitre=["T1552.001", "T1190"],
            source_ip=None if source_ip == "unknown" else source_ip,
            first_seen=first,
            last_seen=last,
            count=len(source_events),
            evidence_lines=[event.line_no for event in source_events],
            details={"exposed_paths": exposed[:20]},
        ))
    return findings


def detect_port_scan(events: list[Event], config: Config) -> list[Finding]:
    blocks = [
        event for event in events
        if event.event == "firewall_block"
        and event.src_ip
        and event.timestamp
        and event.dst_port is not None
    ]
    if not blocks:
        return []

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in blocks:
        by_ip[event.src_ip].append(event)

    findings: list[Finding] = []
    for source_ip, source_events in by_ip.items():
        for cluster in cluster_events(source_events, config.window_seconds):
            ports = sorted({event.dst_port for event in cluster if event.dst_port})
            if len(ports) < config.port_scan_threshold and len(cluster) < (
                config.port_scan_threshold * 2
            ):
                continue
            first, last = cluster[0], cluster[-1]
            severity = "high" if len(ports) >= 10 else "medium"
            findings.append(_finding(
                rule="port_scanning",
                title=f"Port scan from {source_ip} ({len(ports)} destination ports)",
                severity=severity,
                confidence="high",
                description=(
                    f"{len(cluster)} firewall "
                    f"{_plural(len(cluster), 'block')} for {source_ip} between "
                    f"{iso_z(first.timestamp)} and {iso_z(last.timestamp)} touched "
                    f"{len(ports)} distinct destination ports "
                    f"({', '.join(str(port) for port in ports[:20])}). Multiple "
                    "blocked connection attempts across services indicate network "
                    "reconnaissance."
                ),
                recommendation=(
                    "Keep the default-deny policy, block the source, and confirm "
                    "that no internal service is reachable from untrusted networks."
                ),
                mitre=["T1046", "T1595.001"],
                source_ip=source_ip,
                first_seen=first.timestamp,
                last_seen=last.timestamp,
                count=len(cluster),
                evidence_lines=[event.line_no for event in cluster],
                details={
                    "distinct_ports": len(ports),
                    "ports": ports,
                    "window_seconds": config.window_seconds,
                },
            ))
    return findings


def detect_scanner_user_agent(events: list[Event]) -> list[Finding]:
    hits = [
        event for event in events
        if event.user_agent and SCANNER_UA_RE.search(event.user_agent)
    ]
    if not hits:
        return []

    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in hits:
        tool = SCANNER_UA_RE.search(event.user_agent).group("tool").lower()
        grouped[(event.src_ip or "unknown", tool)].append(event)

    findings: list[Finding] = []
    for (source_ip, tool), source_events in grouped.items():
        timestamps = [event.timestamp for event in source_events if event.timestamp]
        first = min(timestamps) if timestamps else None
        last = max(timestamps) if timestamps else None
        severity = "high" if len(source_events) >= 20 else "medium"
        findings.append(_finding(
            rule="scanner_user_agent",
            title=f"Offensive scanner user-agent ('{tool}') from {source_ip}",
            severity=severity,
            confidence="high",
            description=(
                f"{len(source_events)} "
                f"{_plural(len(source_events), 'request')} used a user-agent associated with "
                f"the offensive tool '{tool}'. This is a direct signature of "
                "automated scanning or exploitation attempts."
            ),
            recommendation=(
                "Block or challenge the source, inspect the requested paths for "
                "successful exploitation, and consider filtering known scanner "
                "user-agents at the reverse proxy."
            ),
            mitre=["T1595", "T1595.002"],
            source_ip=None if source_ip == "unknown" else source_ip,
            first_seen=first,
            last_seen=last,
            count=len(source_events),
            evidence_lines=[event.line_no for event in source_events],
            details={"tool": tool, "user_agents": sorted({
                event.user_agent for event in source_events if event.user_agent
            })[:5]},
        ))
    return findings


def detect_watchlist_hits(iocs: list[IOC]) -> list[Finding]:
    findings: list[Finding] = []
    for ioc in iocs:
        if not ioc.watchlist:
            continue
        metadata = ioc.watchlist
        label = str(metadata.get("label", "Watchlisted indicator"))
        confidence = str(metadata.get("confidence", "medium")).lower()
        if confidence not in SEVERITY_RANK:
            confidence = "medium"
        severity = {"high": "high", "medium": "medium", "low": "low"}.get(
            confidence, "medium"
        )
        if ioc.kind == "hash":
            kind_label = "file hash"
            rule = "watchlist_hash"
            title = f"Watchlisted file hash observed: {ioc.value[:16]}..."
            mitre = ["T1204.002", "T1105"]
        elif ioc.kind == "domain":
            kind_label = "domain"
            rule = "watchlist_domain"
            title = f"Watchlisted domain observed: {ioc.value}"
            mitre = ["T1071.004", "T1568"]
        else:
            kind_label = "IPv4 address"
            rule = "watchlist_ip"
            title = f"Watchlisted IP observed: {ioc.value}"
            mitre = ["T1071"]
        findings.append(_finding(
            rule=rule,
            title=title,
            severity=severity,
            confidence=confidence,
            description=(
                f"The {kind_label} {ioc.value} matched the local watchlist "
                f"({label}) across {ioc.hits} log "
                f"{_plural(ioc.hits, 'line')}."
            ),
            recommendation=(
                "Correlate the indicator with endpoint and network telemetry, "
                "contain affected hosts, and update blocking controls. Treat the "
                "match as a lead until independently validated."
            ),
            mitre=mitre,
            source_ip=next(iter(ioc.source_ips)) if len(ioc.source_ips) == 1 else None,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            count=ioc.hits,
            evidence_lines=ioc.lines,
            details={
                "indicator": ioc.value,
                "indicator_type": ioc.kind,
                "watchlist_label": label,
                "watchlist_confidence": confidence,
                "source_ips": sorted(ioc.source_ips),
                "hosts": sorted(ioc.hosts),
            },
        ))
    return findings


def analyze(
    events: list[Event], watchlist: Watchlist, config: Config
) -> tuple[list[Finding], list[IOC], int, str, dict[str, Any]]:
    """Run all detectors and return findings, IOCs, score, level, and stats."""
    iocs = build_iocs(events, watchlist)
    findings: list[Finding] = []
    findings.extend(detect_brute_force(events, config))
    findings.extend(detect_http_scan(events, config))
    findings.extend(detect_sensitive_exposure(events))
    findings.extend(detect_port_scan(events, config))
    findings.extend(detect_scanner_user_agent(events))
    findings.extend(detect_watchlist_hits(iocs))

    findings.sort(key=lambda finding: (
        -SEVERITY_RANK[finding.severity],
        finding.first_seen or datetime.max,
        finding.title,
    ))
    for index, finding in enumerate(findings, start=1):
        finding.finding_id = f"F-{index:03d}"

    score = min(100, sum(SEVERITY_WEIGHT[finding.severity] for finding in findings))
    level = risk_level_for(score)
    stats = {
        "event_types": dict(Counter(event.event for event in events).most_common()),
        "source_types": dict(Counter(event.source_type for event in events).most_common()),
        "unparsed_lines": sum(
            1 for event in events if event.source_type == "unparsed"
        ),
        "malware_alerts": sum(1 for event in events if event.event == "malware_alert"),
    }
    return findings, iocs, score, level, stats
