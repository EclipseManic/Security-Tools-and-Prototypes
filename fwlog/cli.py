"""Command line interface: generate, analyze, sweep, demo."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, analyzer, generator, parser, report
from .models import ScanConfig


def _config_from_args(args) -> ScanConfig:
    return ScanConfig(
        window_minutes=args.window,
        min_distinct_ports=args.min_ports,
        min_distinct_hosts=args.min_hosts,
        enable_long_baseline=not args.no_long_baseline,
    )


def _load_truth(path: str | None) -> dict | None:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write(text: str, path: str | None) -> None:
    if path:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text if text.endswith("\n") else text + "\n")
        print(f"written: {path}")
    else:
        print(text)


def cmd_generate(args) -> int:
    events, truth = generator.generate(seed=args.seed, include_attacks=not args.no_attacks)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    count = generator.write_log(events, args.out)
    truth["log_path"] = args.out
    if args.truth:
        os.makedirs(os.path.dirname(args.truth) or ".", exist_ok=True)
        with open(args.truth, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(truth, handle, indent=2)
    print(f"generated {count} deny records -> {args.out}")
    for campaign in truth["attack_campaigns"]:
        print(f"  planted {campaign['id']}: {campaign['pattern']} "
              f"({campaign['events']} events, {len(campaign['sources'])} source(s))")
    if args.truth:
        print(f"ground truth -> {args.truth}")
    return 0


def cmd_analyze(args) -> int:
    if not os.path.exists(args.log):
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        return 2
    parsed = parser.parse_file(args.log, default_year=args.year)
    if not parsed.events:
        print(f"error: no usable deny records in {args.log} "
              f"({parsed.skipped} lines skipped)", file=sys.stderr)
        for sample in parsed.skipped_samples:
            print(f"  skipped: {sample}", file=sys.stderr)
        return 2

    config = _config_from_args(args)
    result = analyzer.analyze(
        parsed.events, config, input_path=args.log,
        total_lines=parsed.total_lines, skipped=parsed.skipped,
    )
    truth = _load_truth(args.truth)

    if args.format == "json":
        text = report.render_json(result, truth)
    elif args.format == "markdown":
        text = report.render_markdown(result, truth)
    else:
        text = report.render_text(result, truth)
    _write(text, args.out)

    if args.fail_on_findings and any(f["severity"] == "high" for f in result.findings):
        return 3
    return 0


def cmd_sweep(args) -> int:
    if not os.path.exists(args.log):
        print(f"error: log file not found: {args.log}", file=sys.stderr)
        return 2
    parsed = parser.parse_file(args.log, default_year=args.year)
    if not parsed.events:
        print(f"error: no usable deny records in {args.log}", file=sys.stderr)
        return 2
    truth = _load_truth(args.truth)
    rows = analyzer.sweep(parsed.events, truth)
    if args.format == "json":
        text = json.dumps(rows, indent=2, default=str)
    elif args.format == "markdown":
        text = report.render_sweep_markdown(rows)
    else:
        text = report.render_sweep_text(rows, truth)
    _write(text, args.out)
    return 0


def cmd_demo(args) -> int:
    os.makedirs(args.dir, exist_ok=True)
    log_path = os.path.join(args.dir, "deny.log")
    truth_path = os.path.join(args.dir, "truth.json")
    events, truth = generator.generate(seed=args.seed)
    count = generator.write_log(events, log_path)
    truth["log_path"] = log_path
    with open(truth_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(truth, handle, indent=2)

    print(f"[1/3] generated {count} synthetic deny records -> {log_path}")
    print(f"      ground truth -> {truth_path}")
    print()

    parsed = parser.parse_file(log_path, default_year=args.year)
    config = ScanConfig()
    result = analyzer.analyze(parsed.events, config, input_path=log_path,
                              total_lines=parsed.total_lines, skipped=parsed.skipped)
    print("[2/3] analysis")
    print(report.render_text(result, truth))

    print("[3/3] threshold sweep")
    print(report.render_sweep_text(analyzer.sweep(parsed.events, truth), truth))
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="fwscan",
        description="Analyze synthetic firewall deny logs for port scanning: "
                    "identify the scan pattern, state the source-reputation "
                    "assumption, and quantify the detection gap.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python fwscan.py demo\n"
            "  python fwscan.py generate --out data/deny.log --truth data/truth.json\n"
            "  python fwscan.py analyze --log data/deny.log --truth data/truth.json\n"
            "  python fwscan.py analyze --log data/deny.log --format json --out out.json\n"
            "  python fwscan.py sweep --log data/deny.log --truth data/truth.json\n"
        ),
    )
    root.add_argument("--version", action="version", version=f"fwscan {__version__}")
    subs = root.add_subparsers(dest="command", required=True)

    gen = subs.add_parser("generate", help="write a synthetic deny log with planted campaigns")
    gen.add_argument("--out", default=os.path.join("data", "deny.log"))
    gen.add_argument("--truth", default=os.path.join("data", "truth.json"),
                     help="where to write ground truth ('' to skip)")
    gen.add_argument("--seed", type=int, default=7)
    gen.add_argument("--no-attacks", action="store_true",
                     help="benign-only log, useful for false-positive checks")
    gen.set_defaults(func=cmd_generate)

    for name, func, help_text in (
        ("analyze", cmd_analyze, "detect scan patterns, reputation view and gaps"),
        ("sweep", cmd_sweep, "run a threshold grid to measure the detection gap"),
    ):
        sub = subs.add_parser(name, help=help_text)
        sub.add_argument("--log", required=True, help="deny log to analyse")
        sub.add_argument("--truth", default=None, help="optional ground-truth JSON")
        sub.add_argument("--format", choices=("text", "json", "markdown"), default="text")
        sub.add_argument("--out", default=None, help="write the report to a file")
        sub.add_argument("--year", type=int, default=2025,
                         help="year to assume for BSD syslog timestamps")
        if name == "analyze":
            sub.add_argument("--window", type=int, default=15, help="sliding window, minutes")
            sub.add_argument("--min-ports", type=int, default=20,
                             help="distinct dst ports in a window that triggers a vertical scan")
            sub.add_argument("--min-hosts", type=int, default=15,
                             help="distinct dst hosts in a window that triggers a sweep")
            sub.add_argument("--no-long-baseline", action="store_true",
                             help="disable the slow-scan rule (shows the gap it closes)")
            sub.add_argument("--fail-on-findings", action="store_true",
                             help="exit 3 when a high-severity finding exists")
        sub.set_defaults(func=func)

    demo = subs.add_parser("demo", help="generate, analyze and sweep in one go")
    demo.add_argument("--dir", default="data")
    demo.add_argument("--seed", type=int, default=7)
    demo.add_argument("--year", type=int, default=2025)
    demo.set_defaults(func=cmd_demo)
    return root


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
