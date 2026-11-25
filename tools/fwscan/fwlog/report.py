"""Rendering: human text, markdown, and JSON for both analysis and sweep."""

from __future__ import annotations

import json
from collections import defaultdict

from .models import AnalysisResult

WIDTH = 78
RULE = "=" * WIDTH
THIN = "-" * WIDTH


def _stamp(value) -> str:
    if value is None:
        return "n/a"
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_cells(finding: dict) -> tuple[str, str, str]:
    """(events, ports, hosts) for the summary table.

    A distributed finding has no single source, so its third cell counts the
    sources that converged instead of pretending to be a host count.
    """
    evidence = finding["evidence"]
    if finding["kind"] == "distributed_probe":
        return (
            str(evidence.get("events", 0)),
            str(len(finding.get("target_ports", []))),
            f"{evidence.get('distinct_sources', 0)} src",
        )
    return (
        str(evidence.get("events", 0)),
        str(evidence.get("distinct_dst_ports", 0)),
        str(evidence.get("distinct_dst_hosts", 0)),
    )


def _flagged_sources(findings: list[dict]) -> set[str]:
    """Addresses flagged, including the source sets behind distributed findings."""
    flagged: set[str] = set()
    for finding in findings:
        flagged.update(finding.get("sources") or [finding["src"]])
    return flagged


def _to_dict(result: AnalysisResult, truth: dict | None = None) -> dict:
    return {
        "tool": "fwscan",
        "schema": 1,
        "input": result.input_path,
        "meta": {
            "events_analysed": result.event_count,
            "lines_read": result.total_lines,
            "lines_skipped": result.skipped_lines,
            "first_seen": _stamp(result.time_range[0]) if result.time_range else None,
            "last_seen": _stamp(result.time_range[1]) if result.time_range else None,
            "distinct_sources": result.source_count,
            "distinct_targets": result.target_count,
            "protocol_mix": result.protocol_mix,
        },
        "config": result.config.to_dict(),
        "summary": {
            "findings": len(result.findings),
            "high": sum(1 for f in result.findings if f["severity"] == "high"),
            "medium": sum(1 for f in result.findings if f["severity"] == "medium"),
            "low": sum(1 for f in result.findings if f["severity"] == "low"),
            "patterns": sorted({f["kind"] for f in result.findings}),
            "detection_gaps": len(result.gaps),
        },
        "findings": result.findings,
        "reputation_assumptions": result.reputation_assumptions,
        "detection_gaps": result.gaps,
        "unflagged_sources": result.unflagged_volume,
        "ground_truth": truth,
    }


def render_json(result: AnalysisResult, truth: dict | None = None) -> str:
    return json.dumps(_to_dict(result, truth), indent=2, default=str)


def _header(result: AnalysisResult) -> list[str]:
    first, last = (result.time_range or (None, None))
    lines = [
        RULE,
        " FIREWALL DENY LOG - PORT SCAN ANALYSIS",
        RULE,
        f" Input            : {result.input_path}",
        f" Deny records     : {result.event_count} "
        f"(skipped {result.skipped_lines} of {result.total_lines} lines)",
        f" Observed window  : {_stamp(first)} .. {_stamp(last)}",
        f" Sources/targets  : {result.source_count} sources, "
        f"{result.target_count} destinations",
        f" Protocol mix     : {result.protocol_mix}",
        f" Detection        : window={result.config.window_minutes}m, "
        f"min_ports={result.config.min_distinct_ports}, "
        f"min_hosts={result.config.min_distinct_hosts}, "
        f"long_baseline={'on' if result.config.enable_long_baseline else 'off'}",
        "",
    ]
    return lines


def _summary(result: AnalysisResult) -> list[str]:
    lines = [" 1. SUMMARY", THIN]
    if not result.findings:
        lines.append(" No scan pattern breached the configured thresholds.")
        lines.append(" That is not a clean bill of health: see section 4.")
        lines.append("")
        return lines

    lines.append(f" {len(result.findings)} finding(s) across "
                 f"{len({f['kind'] for f in result.findings})} pattern type(s):")
    lines.append("")
    lines.append(f" {'#':<3}{'SOURCE':<26}{'PATTERN':<26}{'SCORE':>6} {'SEV':<7}"
                 f"{'EVENTS':>7}{'PORTS':>7}{'HOSTS':>7}")
    for index, finding in enumerate(result.findings, start=1):
        events, ports, hosts = _row_cells(finding)
        lines.append(
            f" {index:<3}{finding['src'][:25]:<26}{finding['kind'][:25]:<26}"
            f"{finding['score']:>6.2f} {finding['severity']:<7}"
            f"{events:>7}{ports:>7}{hosts:>7}"
        )
    lines.append("")
    return lines


def _finding_block(index: int, finding: dict, config) -> list[str]:
    evidence = finding["evidence"]
    rep = finding["reputation"]
    lines = [THIN]
    lines.append(f" FINDING {index} - {finding['kind']} - score {finding['score']:.2f} "
                 f"({finding['severity'].upper()})")
    lines.append(THIN)
    lines.append(f" Source          : {finding['src']}  "
                 f"[{rep['address_class']} / {rep['posture']}]")

    if finding["kind"] == "distributed_probe":
        lines.append(f" Sources         : {', '.join(finding['sources'])}")
        lines.append(f" Target ports    : "
                     f"{','.join(str(p) for p in finding['target_ports'])}")
        low = evidence["min_events_per_source"]
        high = evidence["max_events_per_source"]
        lines.append(f" {'Per-source':<16}: "
                     + (f"{low} denies each" if low == high
                        else f"{low}-{high} denies each"))
        lines.append(f" Why invisible   : {evidence['why_invisible']}")
    else:
        lines.append(f" Active          : {finding['first_seen']} .. "
                     f"{finding['last_seen']} ({finding['duration_minutes']} min)")
        lines.append(f" Volume          : {evidence['events']} denies "
                     f"({evidence['events_per_minute']}/min), "
                     f"proto={','.join(evidence['protocols']) or '?'}"
                     + (f" flags={','.join(evidence['tcp_flags'])}"
                        if evidence['tcp_flags'] else ""))
        lines.append(f" Breadth         : {evidence['distinct_dst_ports']} dst ports "
                     f"across {evidence['distinct_dst_hosts']} host(s)")
        lines.append(f" {f'In {config.window_minutes}m window':<16}: "
                     f"{evidence['max_distinct_ports_in_window']} distinct ports "
                     f"(trigger {config.min_distinct_ports}), "
                     f"{evidence['max_distinct_hosts_in_window']} distinct hosts "
                     f"(trigger {config.min_distinct_hosts})")
        lines.append(f" Ordering        : {evidence['sequential_port_ratio']:.0%} of "
                     f"adjacent ports consecutive; arrival regularity "
                     f"{evidence['arrival_regularity']:.2f}")
        if evidence["targets"]:
            more = ("" if evidence["distinct_dst_hosts"] <= len(evidence["targets"])
                    else f" (+{evidence['distinct_dst_hosts'] - len(evidence['targets'])} more)")
            lines.append(f" Targets         : {', '.join(evidence['targets'])}{more}")
        if evidence["ports_sample"]:
            lines.append(f" Ports (sample)  : "
                         f"{', '.join(str(p) for p in evidence['ports_sample'])}")
        if "windowed_rule_would_score" in evidence:
            lines.append(f" Windowed rule   : would score "
                         f"{evidence['windowed_rule_would_score']} against a trigger of "
                         f"{evidence['windowed_rule_threshold']} -> no alert. This is a "
                         f"detection gap, not a low-confidence finding.")

    lines.append(f" Why flagged     : {finding['rationale']}")

    holes_ports = evidence.get("coverage_holes_ports") or []
    holes_hosts = evidence.get("coverage_holes_hosts") or []
    if holes_ports or holes_hosts:
        lines.append(" COVERAGE HOLE   : " + "; ".join(
            part for part in (
                f"port(s) {holes_ports} absent from a contiguous run"
                if holes_ports else "",
                f"host(s) {holes_hosts} absent from a contiguous sweep"
                if holes_hosts else "",
            ) if part
        ))
        lines.append("                   -> most likely permitted (or non-answering). "
                     "A deny log cannot tell which.")
        lines.append("                   -> verify against ALLOW records before "
                     "calling this a blocked attack.")
    lines.append(f" Reputation      : {rep['note']}")
    lines.append(f" Basis           : {rep['basis']} (confidence {rep['confidence']}, "
                 f"feed_consulted={str(rep['feed_consulted']).lower()})")
    lines.append("")
    return lines


def render_text(result: AnalysisResult, truth: dict | None = None) -> str:
    lines = _header(result)
    lines += _summary(result)

    if result.findings:
        lines += [" 2. SCAN PATTERN DETAIL", ""]
        for index, finding in enumerate(result.findings, start=1):
            lines += _finding_block(index, finding, result.config)

    lines += [" 3. SOURCE REPUTATION ASSUMPTION", THIN,
              " No reputation feed is consulted. Attribution rests on these assumptions,",
              " stated so they can be argued with:", ""]
    for item in result.reputation_assumptions:
        lines.append(f" {item['id']}. {item['assumption']}")
        lines.append(f"     because   : {item['because']}")
        lines.append(f"     breaks if : {item['breaks_when']}")
        lines.append(f"     effect    : {item['effect']}")
        lines.append(f"     validate  : {item['validate']}")
        lines.append("")

    lines += [" 4. DETECTION GAPS", THIN,
              " What this log cannot tell you, and what it would take to close it.", ""]
    for gap in result.gaps:
        lines.append(f" {gap['id']} [{gap['severity']}] {gap['title']}")
        lines.append(f"     observed : {gap['observed']}")
        lines.append(f"     impact   : {gap['impact']}")
        lines.append(f"     close    : {gap['close']}")
        lines.append("")

    lines += [" 5. NEXT STEPS", THIN,
              " 1. Pull ALLOW records for the coverage holes above - that is where a",
              "    denied scan turns into a permitted one.",
              " 2. Confirm the source identity against NAT logs before blocking anything.",
              " 3. Run 'fwscan sweep' to pick a threshold from measured precision/recall",
              "    instead of taste.",
              " 4. Keep the long-baseline and cross-source rules on; they are the only",
              "    rules that catch campaigns A/B/D in this dataset.",
              ""]

    if truth:
        lines += [" GROUND TRUTH (synthetic data only - not real-world accuracy)",
                  THIN]
        attack = {s for c in truth.get("attack_campaigns", []) for s in c["sources"]}
        flagged = _flagged_sources(result.findings)
        for campaign in truth.get("attack_campaigns", []):
            hit = bool(set(campaign["sources"]) & flagged)
            lines.append(f"  campaign {campaign['id']} ({campaign['pattern']}): "
                         f"{'DETECTED' if hit else 'MISSED'}")
        lines.append(f"  benign sources flagged (false positives): "
                     f"{sorted(flagged & set(truth.get('benign_sources', []))) or 'none'}")
        lines.append(f"  planted attack sources covered: "
                     f"{len(attack & flagged)}/{len(attack)}")
        lines.append("")
    return "\n".join(lines)


def render_markdown(result: AnalysisResult, truth: dict | None = None) -> str:
    first, last = (result.time_range or (None, None))
    out = [
        "# Firewall deny log - port scan analysis",
        "",
        f"- **Input:** `{result.input_path}`",
        f"- **Deny records:** {result.event_count} "
        f"(skipped {result.skipped_lines} of {result.total_lines} lines)",
        f"- **Window:** {_stamp(first)} .. {_stamp(last)}",
        f"- **Sources / destinations:** {result.source_count} / {result.target_count}",
        f"- **Detection:** window {result.config.window_minutes}m, "
        f"min_ports {result.config.min_distinct_ports}, "
        f"min_hosts {result.config.min_distinct_hosts}, long_baseline "
        f"{'on' if result.config.enable_long_baseline else 'off'}",
        "",
        "## 1. Summary",
        "",
    ]
    if result.findings:
        out += ["| # | Source | Pattern | Score | Severity | Events | Ports | Hosts |",
                "|---|--------|---------|-------|----------|--------|-------|-------|"]
        for index, finding in enumerate(result.findings, start=1):
            events, ports, hosts = _row_cells(finding)
            out.append(
                f"| {index} | `{finding['src']}` | {finding['kind']} | "
                f"{finding['score']:.2f} | {finding['severity']} | "
                f"{events} | {ports} | {hosts} |"
            )
    else:
        out.append("No scan pattern breached the configured thresholds.")
    out.append("")

    if result.findings:
        out += ["## 2. Scan pattern detail", ""]
        for index, finding in enumerate(result.findings, start=1):
            evidence = finding["evidence"]
            rep = finding["reputation"]
            out.append(f"### {index}. `{finding['src']}` - {finding['kind']} "
                       f"(score {finding['score']:.2f}, {finding['severity']})")
            out.append("")
            out.append(f"- **Rationale:** {finding['rationale']}")
            if finding["kind"] == "distributed_probe":
                out.append(f"- **Sources:** {', '.join(finding['sources'])}")
                out.append(f"- **Target ports:** "
                           f"{', '.join(str(p) for p in finding['target_ports'])}")
                out.append(f"- **Why invisible:** {evidence['why_invisible']}")
            else:
                out.append(f"- **Active:** {finding['first_seen']} .. "
                           f"{finding['last_seen']} ({finding['duration_minutes']} min)")
                out.append(f"- **Volume:** {evidence['events']} denies "
                           f"({evidence['events_per_minute']}/min)")
                out.append(f"- **Breadth:** {evidence['distinct_dst_ports']} ports / "
                           f"{evidence['distinct_dst_hosts']} hosts")
                out.append(f"- **In {result.config.window_minutes}m window:** "
                           f"{evidence['max_distinct_ports_in_window']} ports, "
                           f"{evidence['max_distinct_hosts_in_window']} hosts")
                out.append(f"- **Ordering:** {evidence['sequential_port_ratio']:.0%} "
                           f"consecutive, regularity "
                           f"{evidence['arrival_regularity']:.2f}")
                if "windowed_rule_would_score" in evidence:
                    out.append(f"- **Windowed rule:** would score "
                               f"{evidence['windowed_rule_would_score']} vs trigger "
                               f"{evidence['windowed_rule_threshold']} -> silent")
            holes_ports = evidence.get("coverage_holes_ports") or []
            holes_hosts = evidence.get("coverage_holes_hosts") or []
            if holes_ports or holes_hosts:
                out.append(f"- **Coverage hole:** ports {holes_ports or 'none'}, "
                           f"hosts {holes_hosts or 'none'} - probable permitted port, "
                           f"verify against ALLOW logs")
            out.append(f"- **Reputation:** {rep['address_class']} / {rep['posture']} "
                       f"({rep['basis']})")
            out.append("")

    out += ["## 3. Source reputation assumption", ""]
    for item in result.reputation_assumptions:
        out.append(f"**{item['id']}. {item['assumption']}**")
        out.append("")
        out.append(f"- because: {item['because']}")
        out.append(f"- breaks if: {item['breaks_when']}")
        out.append(f"- effect: {item['effect']}")
        out.append(f"- validate: {item['validate']}")
        out.append("")

    out += ["## 4. Detection gaps", ""]
    for gap in result.gaps:
        out.append(f"### {gap['id']} [{gap['severity']}] {gap['title']}")
        out.append("")
        out.append(f"- **Observed:** {gap['observed']}")
        out.append(f"- **Impact:** {gap['impact']}")
        out.append(f"- **Close it:** {gap['close']}")
        out.append("")

    if truth:
        out += ["## Ground truth (synthetic data only)", ""]
        flagged = _flagged_sources(result.findings)
        for campaign in truth.get("attack_campaigns", []):
            hit = bool(set(campaign["sources"]) & flagged)
            out.append(f"- Campaign {campaign['id']} ({campaign['pattern']}): "
                       f"{'DETECTED' if hit else 'MISSED'}")
        out.append("")
    return "\n".join(out)


def render_sweep_text(rows: list[dict], truth: dict | None = None) -> str:
    lines = [RULE,
             " THRESHOLD SWEEP - the detection gap, measured",
             RULE,
             " Same log, different settings. 'caught' counts planted campaigns found;",
             " 'fp' counts benign sources wrongly flagged.",
             ""]
    if truth:
        campaigns = truth.get("attack_campaigns", [])
        lines.append(f" Planted campaigns: "
                     + ", ".join(f"{c['id']}={c['pattern']}" for c in campaigns))
        lines.append("")
    lines.append(f" {'WIN':>4} {'PORTS':>6} {'HOSTS':>6} {'BASELINE':>9} {'FLAG':>5} "
                 f"{'CAUGHT':>7} {'RECALL':>7} {'FP':>3}  MISSED / FALSE POSITIVES")
    lines.append(" " + "-" * (WIDTH - 1))
    for row in rows:
        missed = ",".join(row["campaigns_missed"]) or "-"
        false_pos = ",".join(row["false_positive_sources"]) or "-"
        lines.append(
            f" {row['window_minutes']:>4} {row['min_ports']:>6} {row['min_hosts']:>6} "
            f"{('on' if row['long_baseline'] else 'off'):>9} {row['flagged']:>5} "
            f"{len(row['campaigns_caught']):>7} {row['recall']:>7.0%} "
            f"{row['false_positives']:>3}  missed={missed} fp={false_pos}"
        )
    lines.append("")
    groups: dict[tuple, set] = defaultdict(set)
    for row in rows:
        groups[(row["min_hosts"], row["long_baseline"])].add(tuple(row["campaigns_caught"]))
    if all(len(outcomes) == 1 for outcomes in groups.values()):
        lines.append(" Window size changed nothing here: the fast campaigns breach any window")
        lines.append(" of 5 min or more, and the paced one breaches none of them. The levers")
        lines.append(" that actually move the result are the host threshold and the baseline")
        lines.append(" rule - which is the point.")
        lines.append("")
    lines.append(" Read it as a curve, not a scoreboard: every row that catches more also")
    lines.append(" invents more, and no single row catches everything.")
    lines.append("")
    return "\n".join(lines)


def render_sweep_markdown(rows: list[dict]) -> str:
    out = ["| Window (min) | min_ports | min_hosts | Long baseline | Flagged | Caught "
           "| Recall | False positives | Missed |",
           "|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        out.append(
            f"| {row['window_minutes']} | {row['min_ports']} | {row['min_hosts']} | "
            f"{'on' if row['long_baseline'] else 'off'} | {row['flagged']} | "
            f"{','.join(row['campaigns_caught']) or '-'} | {row['recall']:.0%} | "
            f"{row['false_positives']} | {','.join(row['campaigns_missed']) or '-'} |"
        )
    return "\n".join(out)
