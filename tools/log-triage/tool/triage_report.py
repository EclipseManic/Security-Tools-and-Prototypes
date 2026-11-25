"""Structured JSON and Markdown report rendering."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from triage_types import (
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    TOOL_NAME,
    TOOL_VERSION,
    Event,
    Finding,
    IOC,
    TriageResult,
    iso_z,
)

LIMITATIONS = [
    "Timestamps without an explicit zone are treated as UTC; syslog lines use "
    "the year supplied with --assume-year.",
    "Detection is behavioural and threshold-based, so tuning is required for "
    "each environment; the defaults target small lab logs.",
    "Only IPv4 addresses are inventoried as IOCs; IPv6 source addresses are "
    "parsed where the log format exposes them but are not aggregated.",
    "No packet payload, HTTP body, or file content is inspected. A 2xx response "
    "for a sensitive path is a lead that requires manual validation.",
    "Watchlist matching is local and static; the included watchlist is synthetic "
    "and is not a threat-intelligence feed.",
    "The tool is read-only and makes no network calls. It does not block, "
    "quarantine, or modify any system.",
    "Mixed log formats are supported on a best-effort basis; unknown lines are "
    "still scanned for indicators but are not correlated behaviourally.",
    "The input size is capped (default 50 MiB) because events are held in memory.",
]


def _ioc_dict(ioc: IOC) -> dict[str, Any]:
    return {
        "value": ioc.value,
        "kind": ioc.kind,
        "hash_type": ioc.hash_type,
        "scope": ioc.scope,
        "note": ioc.note,
        "hits": ioc.hits,
        "first_seen": iso_z(ioc.first_seen),
        "last_seen": iso_z(ioc.last_seen),
        "lines": ioc.lines,
        "contexts": dict(ioc.contexts),
        "source_ips": sorted(ioc.source_ips),
        "hosts": sorted(ioc.hosts),
        "watchlist": ioc.watchlist,
    }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.finding_id,
        "rule": finding.rule,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "source_ip": finding.source_ip,
        "first_seen": iso_z(finding.first_seen),
        "last_seen": iso_z(finding.last_seen),
        "count": finding.count,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "mitre": finding.mitre,
        "evidence_lines": finding.evidence_lines,
        "details": finding.details,
    }


def build_timeline(result: TriageResult, limit: int = 40) -> list[dict[str, Any]]:
    """Build a short, de-duplicated timeline from finding evidence lines."""
    events_by_line: dict[int, Event] = {
        event.line_no: event for event in result.events
    }
    entries: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for finding in result.findings:
        for line_no in finding.evidence_lines[:3]:
            key = (line_no, finding.finding_id)
            if key in seen or line_no not in events_by_line:
                continue
            seen.add(key)
            event = events_by_line[line_no]
            summary = " ".join(event.raw.split())
            entries.append({
                "time": iso_z(event.timestamp),
                "line": line_no,
                "finding_id": finding.finding_id,
                "event": event.event,
                "summary": summary[:220],
            })
    entries.sort(key=lambda entry: (entry["time"] is None, entry["time"] or "", entry["line"]))
    return entries[:limit]


def to_dict(result: TriageResult) -> dict[str, Any]:
    external = [ioc for ioc in result.iocs if ioc.scope == "external"]
    internal = [ioc for ioc in result.iocs if ioc.scope == "internal"]
    reserved = [ioc for ioc in result.iocs if ioc.scope == "reserved"]
    domains = [ioc for ioc in result.iocs if ioc.kind == "domain"]
    hashes = [ioc for ioc in result.iocs if ioc.kind == "hash"]
    urls = [ioc for ioc in result.iocs if ioc.kind == "url"]

    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in result.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    parsed_events = sum(
        count for source, count in result.stats.get("source_types", {}).items()
        if source != "unparsed"
    )
    watchlist_hits = sum(1 for ioc in result.iocs if ioc.watchlist)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": iso_z(result.generated_at),
        "input": {
            "path": result.display_path,
            "sha256": result.sha256,
            "size_bytes": result.size_bytes,
            "lines": result.line_count,
            "nonblank_lines": result.nonblank_lines,
            "parsed_events": parsed_events,
        },
        "config": {
            "window_seconds": result.config.window_seconds,
            "brute_threshold": result.config.brute_threshold,
            "scan_threshold": result.config.scan_threshold,
            "port_scan_threshold": result.config.port_scan_threshold,
            "success_window_seconds": result.config.success_window_seconds,
            "assume_year": result.config.assume_year,
            "max_bytes": result.config.max_bytes,
        },
        "watchlist": {
            "path": result.watchlist_path,
            "indicator_count": result.watchlist.indicator_count,
            "categories": result.watchlist.summary(),
            "warnings": result.watchlist.warnings,
        },
        "summary": {
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "findings_total": len(result.findings),
            "severity_counts": severity_counts,
            "ioc_counts": {
                "ipv4_external": len(external),
                "ipv4_internal": len(internal),
                "ipv4_reserved": len(reserved),
                "domains": len(domains),
                "hashes": len(hashes),
                "urls": len(urls),
                "watchlist_hits": watchlist_hits,
            },
            "unparsed_lines": result.stats.get("unparsed_lines", 0),
        },
        "findings": [_finding_dict(finding) for finding in result.findings],
        "iocs": {
            "ipv4_external": [_ioc_dict(ioc) for ioc in external],
            "ipv4_internal": [_ioc_dict(ioc) for ioc in internal],
            "ipv4_reserved": [_ioc_dict(ioc) for ioc in reserved],
            "domains": [_ioc_dict(ioc) for ioc in domains],
            "hashes": [_ioc_dict(ioc) for ioc in hashes],
            "urls": [_ioc_dict(ioc) for ioc in urls],
        },
        "timeline": build_timeline(result),
        "stats": result.stats,
        "limitations": LIMITATIONS,
    }


def _text(value: Any) -> str:
    """Escape HTML/control characters for prose and headings."""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value))
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\r", " ").replace("\n", " ")


def _md(value: Any) -> str:
    """Escape a value for a Markdown table cell."""
    return _text(value).replace("|", "\\|")


def _code(value: str) -> str:
    safe = (
        str(value)
        .replace("`", "'")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    return f"`{safe}`"


def _time(value: datetime | None) -> str:
    return iso_z(value) or "-"


def _contexts(ioc: IOC) -> str:
    values = [name for name, _count in ioc.contexts.most_common(4)]
    return ", ".join(values) if values else "-"


def _watchlist_note(ioc: IOC) -> str:
    if not ioc.watchlist:
        return "-"
    label = ioc.watchlist.get("label", "hit")
    return _md(f"hit: {label}")


def _event_table(result: TriageResult) -> list[str]:
    lines = [
        "## Event Breakdown",
        "",
        "| Source type | Events |",
        "|---|---:|",
    ]
    for source, count in result.stats.get("source_types", {}).items():
        lines.append(f"| {_md(source)} | {count} |")
    lines.extend([
        "",
        "| Event type | Events |",
        "|---|---:|",
    ])
    for event, count in result.stats.get("event_types", {}).items():
        lines.append(f"| {_md(event)} | {count} |")
    lines.append("")
    return lines


def _ioc_section(
    title: str, iocs: list[IOC], note_column: bool = False
) -> list[str]:
    lines = [f"### {title}", ""]
    if not iocs:
        lines.extend(["None observed.", ""])
        return lines
    if note_column:
        lines.extend([
            "| Value | Hits | First seen (UTC) | Last seen (UTC) | Contexts | Note | Watchlist |",
            "|---|---:|---|---|---|---|---|",
        ])
    else:
        lines.extend([
            "| Value | Hits | First seen (UTC) | Last seen (UTC) | Contexts | Watchlist |",
            "|---|---:|---|---|---|---|",
        ])
    for ioc in iocs:
        value = _code(ioc.value)
        first = _time(ioc.first_seen)
        last = _time(ioc.last_seen)
        contexts = _md(_contexts(ioc))
        watchlist = _watchlist_note(ioc)
        if note_column:
            lines.append(
                f"| {value} | {ioc.hits} | {first} | {last} | {contexts} | "
                f"{_md(ioc.note or '-')} | {watchlist} |"
            )
        else:
            lines.append(
                f"| {value} | {ioc.hits} | {first} | {last} | {contexts} | "
                f"{watchlist} |"
            )
    lines.append("")
    return lines


def render_markdown(result: TriageResult) -> str:
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in result.findings:
        severity_counts[finding.severity] += 1
    external = [ioc for ioc in result.iocs if ioc.scope == "external"]
    internal = [ioc for ioc in result.iocs if ioc.scope == "internal"]
    reserved = [ioc for ioc in result.iocs if ioc.scope == "reserved"]
    domains = [ioc for ioc in result.iocs if ioc.kind == "domain"]
    hashes = [ioc for ioc in result.iocs if ioc.kind == "hash"]
    urls = [ioc for ioc in result.iocs if ioc.kind == "url"]
    parsed_events = sum(
        count for source, count in result.stats.get("source_types", {}).items()
        if source != "unparsed"
    )
    watchlist_hits = sum(1 for ioc in result.iocs if ioc.watchlist)

    lines: list[str] = [
        "# Log Triage Report",
        "",
        f"**Tool:** {TOOL_NAME} v{TOOL_VERSION}  ",
        f"**Generated (UTC):** {iso_z(result.generated_at)}  ",
        f"**Input:** {_code(result.display_path)} "
        f"({result.size_bytes:,} bytes, {result.line_count:,} lines)  ",
        f"**SHA-256:** {_code(result.sha256)}  ",
    ]
    if result.watchlist.indicator_count:
        lines.append(
            f"**Watchlist:** {_code(result.watchlist_path or 'inline')} "
            f"({result.watchlist.indicator_count} indicators)  "
        )
    else:
        lines.append("**Watchlist:** not used  ")
    lines.extend([
        "",
        "## Risk Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Overall risk | **{result.risk_level.upper()}** "
        f"({result.risk_score}/100) |",
        f"| Findings | {len(result.findings)} "
        f"({severity_counts['critical']} critical, "
        f"{severity_counts['high']} high, "
        f"{severity_counts['medium']} medium, "
        f"{severity_counts['low']} low) |",
        f"| Parsed events | {parsed_events:,} / {result.nonblank_lines:,} non-blank lines |",
        f"| External IPv4 | {len(external)} |",
        f"| Internal IPv4 | {len(internal)} |",
        f"| Domains | {len(domains)} |",
        f"| File hashes | {len(hashes)} |",
        f"| URLs | {len(urls)} |",
        f"| Watchlist hits | {watchlist_hits} |",
        "",
    ])
    if result.findings:
        noun = "finding" if len(result.findings) == 1 else "findings"
        lines.append(
            f"**Assessment:** {len(result.findings)} {noun} produced a "
            f"{result.risk_level.upper()} risk score. The highest-severity items "
            "are listed first and should be validated using the evidence lines."
        )
    else:
        lines.append(
            "**Assessment:** no configured detections fired on this input. This "
            "does not prove the log is benign; review coverage and thresholds."
        )
    lines.append("")

    lines.extend([
        "## Findings",
        "",
    ])
    if not result.findings:
        lines.extend(["No findings.", ""])
    else:
        lines.extend([
            "| ID | Severity | Rule | Indicator / source | Count | First seen (UTC) |",
            "|---|---|---|---|---:|---|",
        ])
        for finding in result.findings:
            source = finding.source_ip or "-"
            lines.append(
                f"| {finding.finding_id} | **{finding.severity.upper()}** | "
                f"{_md(finding.rule)} | {_code(source)} | {finding.count} | "
                f"{_time(finding.first_seen)} |"
            )
        lines.append("")

        events_by_line = {event.line_no: event for event in result.events}
        for finding in result.findings:
            lines.extend([
                f"### {finding.finding_id} - {finding.severity.upper()} - "
                f"{_text(finding.title)}",
                "",
                f"- **Rule:** {_code(finding.rule)}",
                f"- **Confidence:** {finding.confidence}",
                f"- **Source:** {_code(finding.source_ip or 'not applicable')}",
                f"- **Count:** {finding.count}",
                f"- **First / last seen (UTC):** {_time(finding.first_seen)} / "
                f"{_time(finding.last_seen)}",
                f"- **MITRE ATT&CK:** {', '.join(finding.mitre) or '-'}",
                "",
                _text(finding.description),
                "",
                f"**Recommendation:** {_text(finding.recommendation)}",
                "",
                "**Evidence:**",
                "",
            ])
            evidence_rows = []
            for line_no in finding.evidence_lines[:4]:
                event = events_by_line.get(line_no)
                if event is None:
                    continue
                raw = " ".join(event.raw.split())
                if len(raw) > 260:
                    raw = raw[:257] + "..."
                evidence_rows.append(f"line {line_no}: {raw}")
            if evidence_rows:
                block = "\n".join(evidence_rows)
                runs = [len(match.group(0)) for match in re.finditer(r"`+", block)]
                fence_length = max(3, (max(runs) + 1) if runs else 3)
                fence = "`" * fence_length
                lines.extend([f"{fence}text", block, fence, ""])
            else:
                lines.extend(["No evidence lines available.", ""])

    lines.extend([
        "## Indicators of Compromise",
        "",
        "Indicators are extracted from every line, including lines that could "
        "not be parsed behaviourally. Internal addresses are shown for context "
        "and are not automatically malicious.",
        "",
    ])
    lines.extend(_ioc_section(
        "External IPv4", external, note_column=True
    ))
    lines.extend(_ioc_section(
        "Internal IPv4 (context only)", internal, note_column=True
    ))
    if reserved:
        lines.extend(_ioc_section("Reserved / special-purpose IPv4", reserved, note_column=True))
    lines.extend(_ioc_section("Domains", domains))
    lines.extend(_ioc_section("File Hashes", hashes))
    lines.extend(_ioc_section("URLs", urls))

    timeline = build_timeline(result)
    if timeline:
        lines.extend([
            "## Suspicious Event Timeline",
            "",
            "| Time (UTC) | Line | Finding | Event | Summary |",
            "|---|---:|---|---|---|",
        ])
        for entry in timeline:
            lines.append(
                f"| {entry['time'] or '-'} | {entry['line']} | "
                f"{entry['finding_id']} | {_md(entry['event'])} | "
                f"{_md(entry['summary'][:140])} |"
            )
        lines.append("")

    lines.extend(_event_table(result))
    lines.extend([
        "## Detection Method and Tuning",
        "",
        "| Rule | Logic | Default threshold |",
        "|---|---|---|",
        "| `brute_force` | Failed SSH logins clustered per source IP; optional "
        "successful login after the burst | "
        f"{result.config.brute_threshold} failures / "
        f"{result.config.window_seconds}s |",
        "| `http_scanning` | HTTP 4xx/5xx clustered per source IP, distinct paths "
        "and sensitive targets | "
        f"{result.config.scan_threshold} errors or 8 distinct paths / "
        f"{result.config.window_seconds}s |",
        "| `sensitive_file_exposure` | HTTP 2xx response for a sensitive path | "
        "any match |",
        "| `port_scanning` | Firewall blocks clustered per source IP by distinct "
        "destination port | "
        f"{result.config.port_scan_threshold} ports / "
        f"{result.config.window_seconds}s |",
        "| `scanner_user_agent` | User-agent matches a known offensive tool | any match |",
        "| `watchlist_*` | Extracted IOC matches the local JSON watchlist | any match |",
        "",
        "## Assumptions and Limitations",
        "",
    ])
    lines.extend([f"- {item}" for item in LIMITATIONS])
    lines.extend([
        "",
        "## Safety",
        "",
        "LogTriage is a defensive, read-only tool. It does not execute log "
        "content, make network requests, modify the input, or interact with any "
        "target. All sample indicators are synthetic or use reserved address "
        "space and the `.example` domain.",
        "",
        "---",
        "",
        f"Generated by {TOOL_NAME} v{TOOL_VERSION}. Defensive log triage; "
        "validate findings before acting.",
        "",
    ])
    return "\n".join(lines)
