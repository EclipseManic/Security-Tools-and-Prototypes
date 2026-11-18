#!/usr/bin/env python3
"""LogTriage - defensive log triage CLI.

Reads a text log, extracts IOCs, detects brute-force/scanning behaviour, and
writes structured Markdown and JSON reports. Standard library only; read-only
and network-free by design.

Example:
    python tool/log_triage.py --input sample_input/triage_sample.log \
        --out-dir sample_output
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from triage_detect import analyze, load_watchlist
from triage_parse import ingest_file
from triage_report import render_markdown, to_dict
from triage_types import (
    DEFAULT_MAX_BYTES,
    SEVERITY_RANK,
    TOOL_NAME,
    TOOL_VERSION,
    Config,
    TriageResult,
    display_path,
    utc_now,
)

ANSI = {
    "critical": "\033[1;91m",
    "high": "\033[93m",
    "medium": "\033[96m",
    "low": "\033[94m",
    "clean": "\033[92m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _use_color(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _paint(text: str, colour: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{ANSI.get(colour, '')}{text}{ANSI['reset']}"


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.2f} MiB"


def _watchlist_path(args: argparse.Namespace) -> Path | None:
    if args.no_watchlist:
        return None
    if args.watchlist is not None:
        return args.watchlist
    default = Path(__file__).with_name("watchlist.json")
    return default if default.exists() else None


def _write_outputs(
    result: TriageResult, out_dir: Path, prefix: str, fmt: str
) -> dict[str, Path]:
    if not prefix or prefix in {".", ".."} or "/" in prefix or "\\" in prefix:
        raise ValueError("output prefix must be a plain filename without separators")
    out_dir.mkdir(parents=True, exist_ok=True)
    input_path = result.input_path.resolve()
    written: dict[str, Path] = {}
    if fmt in {"both", "json"}:
        json_path = out_dir / f"{prefix}.json"
        if json_path.resolve() == input_path:
            raise ValueError("refusing to overwrite the input file with JSON output")
        json_path.write_text(
            json.dumps(to_dict(result), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        written["json"] = json_path
    if fmt in {"both", "md"}:
        markdown_path = out_dir / f"{prefix}.md"
        if markdown_path.resolve() == input_path:
            raise ValueError("refusing to overwrite the input file with Markdown output")
        markdown_path.write_text(
            render_markdown(result) + "\n", encoding="utf-8", newline="\n"
        )
        written["markdown"] = markdown_path
    return written


def _print_summary(
    result: TriageResult, written: dict[str, Path], color: bool
) -> None:
    severity_counts = Counter(finding.severity for finding in result.findings)
    ioc_counts = {
        "external": sum(1 for ioc in result.iocs if ioc.scope == "external"),
        "internal": sum(1 for ioc in result.iocs if ioc.scope == "internal"),
        "domains": sum(1 for ioc in result.iocs if ioc.kind == "domain"),
        "hashes": sum(1 for ioc in result.iocs if ioc.kind == "hash"),
        "urls": sum(1 for ioc in result.iocs if ioc.kind == "url"),
    }
    source_counts = result.stats.get("source_types", {})
    parsed = sum(
        count for source, count in source_counts.items() if source != "unparsed"
    )
    print(f"{_paint(TOOL_NAME, 'bold', color)} v{TOOL_VERSION} | "
          "defensive log triage (read-only)")
    print("=" * 66)
    print(f"Input     : {result.display_path} "
          f"({_human_size(result.size_bytes)}, {result.line_count:,} lines)")
    print(f"Parsed    : {parsed:,} events | "
          f"ssh={source_counts.get('ssh', 0)}, http={source_counts.get('http', 0)}, "
          f"dns={source_counts.get('dns', 0)}, "
          f"firewall={source_counts.get('firewall', 0)}, "
          f"edr={source_counts.get('edr', 0)}")
    print(f"IOCs      : {ioc_counts['external']} external IPv4, "
          f"{ioc_counts['internal']} internal IPv4, "
          f"{ioc_counts['domains']} domains, {ioc_counts['hashes']} hashes, "
          f"{ioc_counts['urls']} URLs")
    if result.watchlist.indicator_count:
        print(f"Watchlist : {result.watchlist.indicator_count} indicators | "
              f"{sum(1 for ioc in result.iocs if ioc.watchlist)} matching IOCs")
    else:
        print("Watchlist : not used")

    severity_line = ", ".join(
        f"{severity_counts[level]} {level}"
        for level in ("critical", "high", "medium", "low")
        if severity_counts[level]
    ) or "none"
    risk = result.risk_level.upper()
    print(f"Risk      : {_paint(risk, result.risk_level, color)} "
          f"({result.risk_score}/100) | {len(result.findings)} findings "
          f"({severity_line})")
    for finding in result.findings[:6]:
        label = _paint(f"[{finding.severity.upper()}]", finding.severity, color)
        print(f"  {label} {finding.finding_id} {finding.title}")
    if len(result.findings) > 6:
        print(f"  ... {len(result.findings) - 6} more in the report")

    print("Outputs")
    labels = {"json": "JSON", "markdown": "Markdown"}
    for kind, path in written.items():
        print(f"  {labels[kind]:<9}: {display_path(path)}")
    for warning in result.watchlist.warnings:
        print(f"  warning: {warning}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_triage.py",
        description=(
            "Defensive log triage: extract IPv4/domain/hash IOCs, detect "
            "brute-force and scanning patterns, and write Markdown + JSON."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python tool/log_triage.py --input sample_input/triage_sample.log\n"
            "  python tool/log_triage.py -i auth.log -o reports --format json\n"
            "  python tool/log_triage.py -i auth.log --fail-on high\n\n"
            "Exit codes: 0 success, 1 --fail-on threshold reached, 2 input error."
        ),
    )
    parser.add_argument("-i", "--input", type=Path, required=True,
                        help="input log file (text)")
    parser.add_argument("-o", "--out-dir", type=Path, default=Path("sample_output"),
                        help="output directory (default: sample_output)")
    parser.add_argument("--output-prefix", default="triage",
                        help="output filename prefix (default: triage)")
    parser.add_argument("--format", choices=("both", "json", "md"), default="both",
                        help="output format (default: both)")
    parser.add_argument("--watchlist", type=Path, default=None,
                        help="JSON watchlist (default: tool/watchlist.json if present)")
    parser.add_argument("--no-watchlist", action="store_true",
                        help="disable watchlist matching")
    parser.add_argument("--window", type=int, default=20,
                        help="correlation window in seconds (default: 20)")
    parser.add_argument("--brute-threshold", type=int, default=5,
                        help="failed SSH logins per window (default: 5)")
    parser.add_argument("--scan-threshold", type=int, default=10,
                        help="HTTP errors per window (default: 10)")
    parser.add_argument("--port-scan-threshold", type=int, default=8,
                        help="distinct blocked ports per window (default: 8)")
    parser.add_argument("--success-window", type=int, default=300,
                        help="seconds after a burst to look for success (default: 300)")
    parser.add_argument("--assume-year", type=int, default=datetime.now().year,
                        help="year for syslog timestamps without a year")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"maximum input size (default: {DEFAULT_MAX_BYTES})")
    parser.add_argument("--fail-on", choices=("low", "medium", "high", "critical"),
                        default=None,
                        help="exit 1 if the overall risk reaches this level")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the console summary")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {TOOL_VERSION}")
    return parser


def run(args: argparse.Namespace) -> int:
    config = Config(
        window_seconds=args.window,
        brute_threshold=args.brute_threshold,
        scan_threshold=args.scan_threshold,
        port_scan_threshold=args.port_scan_threshold,
        success_window_seconds=args.success_window,
        assume_year=args.assume_year,
        max_bytes=args.max_bytes,
    )
    config.validate()

    events, line_count, nonblank, size, sha256 = ingest_file(args.input, config)
    watchlist_path = _watchlist_path(args)
    watchlist = load_watchlist(watchlist_path)
    findings, iocs, score, level, stats = analyze(events, watchlist, config)

    result = TriageResult(
        input_path=args.input,
        display_path=display_path(args.input),
        size_bytes=size,
        sha256=sha256,
        line_count=line_count,
        nonblank_lines=nonblank,
        events=events,
        findings=findings,
        iocs=iocs,
        risk_score=score,
        risk_level=level,
        config=config,
        watchlist=watchlist,
        watchlist_path=(
            display_path(watchlist_path) if watchlist_path is not None else None
        ),
        generated_at=utc_now(),
        stats=stats,
    )
    written = _write_outputs(result, args.out_dir, args.output_prefix, args.format)
    color = _use_color(args.no_color)
    if not args.quiet:
        _print_summary(result, written, color)

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if SEVERITY_RANK.get(result.risk_level, -1) >= threshold:
            return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
