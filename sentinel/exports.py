"""Exports: CSV for spreadsheets, JSON for evidence exchange, HTML for reports."""

from __future__ import annotations

import csv
import html
from datetime import datetime
from typing import Any, Iterable

from . import config, storage

HEADERS = {
    "name": "Name",
    "service_name": "Service",
    "display_name": "Display name",
    "description": "Description",
    "category": "Category",
    "state": "State",
    "start_mode": "Startup",
    "account": "Account",
    "service_type": "Service type",
    "process_id": "PID",
    "command_line": "Command line",
    "exe_path": "Executable path",
    "executable_path": "Executable path",
    "file_exists": "File exists",
    "signature": "Signature",
    "signature_status": "Signature",
    "signer": "Signer",
    "company": "Company",
    "version": "Version",
    "sha256": "SHA-256",
    "unquoted_path": "Unquoted path",
    "user_writable": "User-writable path",
    "outside_protected": "Outside protected roots",
    "runtime": "Runtime",
    "runtime_source": "Runtime source",
    "run_count": "Runs",
    "last_activity": "Last activity",
    "last_activity_time": "Last activity time",
    "last_stop_time": "Last stop",
    "last_duration": "Last duration",
    "threat_score": "Threat score",
    "threat_level": "Threat level",
    "reliability_score": "Reliability score",
    "reliability_level": "Reliability level",
    "threat_reasons_text": "Threat reasons",
    "reliability_reasons_text": "Reliability reasons",
    "recommendation": "Recommendation",
    "notes": "Notes",
    "time": "Time",
    "event_id": "Event",
    "activity": "Activity",
    "severity": "Severity",
    "detail": "Detail",
    "source": "Source",
    "change_type": "Change",
    "field": "Field",
    "old_value": "Old value",
    "new_value": "New value",
    "reason": "Reason",
    "decision": "Decision",
    "analyst": "Analyst",
    "timestamp": "Timestamp",
    "hostname": "Host",
    "evidence_complete": "Evidence complete",
    "id": "ID",
}

def _flatten(value: Any) -> Any:
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_flatten(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple)):
        parts = []
        for item in value:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or _flatten(item)))
            else:
                parts.append(str(item))
        return " | ".join(part for part in parts if part)
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None:
        return ""
    return value


_CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (a real risk for service names,
    descriptions and analyst notes that end up in Excel)."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] not in _CSV_DANGEROUS:
        return value
    try:
        float(value)
        return value  # plain negative number, not a formula
    except ValueError:
        return "'" + value


def _columns(rows: list[dict]) -> list[str]:
    ordered: list[str] = []
    for row in rows:
        for key in row:
            if key not in ordered and key not in {"raw_events", "threat_reasons", "reliability_reasons"}:
                ordered.append(key)
    return ordered


def export(report_name: str, rows: Iterable[dict], fmt: str = "Csv") -> dict:
    data = [row for row in rows]
    fmt = (fmt or "Csv").capitalize()
    if fmt not in {"Csv", "Json", "Html"}:
        raise ValueError(f"Unsupported export format '{fmt}'.")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    extension = fmt.lower()
    path = config.export_dir() / f"{report_name}_{stamp}.{extension}"
    # Two analysts exporting in the same second must not overwrite each other.
    duplicate = 1
    while path.exists():
        path = config.export_dir() / f"{report_name}_{stamp}_{duplicate}.{extension}"
        duplicate += 1

    if fmt == "Csv":
        columns = _columns(data)
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow([HEADERS.get(column, column.replace("_", " ").title()) for column in columns])
            for row in data:
                writer.writerow([_csv_safe(_flatten(row.get(column))) for column in columns])
    elif fmt == "Json":
        payload = {
            "report": report_name,
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "hostname": _hostname(),
            "row_count": len(data),
            "rows": [{key: _flatten(value) for key, value in row.items()} for row in data],
        }
        storage.write_json(path, payload)
    else:
        path.write_text(_html_report(report_name, data), encoding="utf-8")

    storage.log("INFO", f"Exported {report_name} ({fmt}) to {path}")
    return {
        "file": path.name,
        "path": str(path),
        "format": fmt,
        "rows": len(data),
        "size": path.stat().st_size if path.exists() else 0,
    }


def _hostname() -> str:
    import socket

    return socket.gethostname()


def _html_report(report_name: str, rows: list[dict]) -> str:
    columns = _columns(rows)
    severity_key = "severity" if any("severity" in row for row in rows) else "threat_level"

    head = "".join(
        f"<th>{html.escape(HEADERS.get(column, column.replace('_', ' ').title()))}</th>" for column in columns
    )
    body_rows = []
    for row in rows:
        level = str(row.get(severity_key) or "").casefold()
        cells = []
        for column in columns:
            value = html.escape(str(_flatten(row.get(column))))
            if column == severity_key and level:
                cells.append(f'<td><span class="badge {html.escape(level)}">{value}</span></td>')
            else:
                cells.append(f"<td>{value}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ServiceSentinel - {html.escape(report_name)}</title>
<style>
:root {{ color-scheme: light; }}
body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 28px; color: #16212b; background: #fff; }}
h1 {{ color: #0b7285; margin-bottom: 4px; font-size: 22px; }}
.meta {{ color: #5b6b77; margin-bottom: 18px; font-size: 13px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
th {{ background: #0b7285; color: #fff; text-align: left; position: sticky; top: 0; }}
th, td {{ border: 1px solid #cbd5dc; padding: 6px 8px; vertical-align: top; }}
tr:nth-child(even) td {{ background: #f4f7f9; }}
.badge {{ display: inline-block; padding: 1px 7px; border-radius: 9px; font-weight: 600; font-size: 11px; }}
.badge.critical {{ background: #b3123b; color: #fff; }}
.badge.high {{ background: #d9480f; color: #fff; }}
.badge.medium {{ background: #f0a202; color: #241a00; }}
.badge.low {{ background: #cfe3ea; color: #0b3a48; }}
.badge.informational {{ background: #e6ebee; color: #33454f; }}
</style>
</head>
<body>
<h1>ServiceSentinel report: {html.escape(report_name)}</h1>
<div class="meta">Computer: {html.escape(_hostname())} | Generated: {generated} | Rows: {len(rows)}</div>
<table>
<thead><tr>{head}</tr></thead>
<tbody>{''.join(body_rows)}</tbody>
</table>
</body>
</html>
"""
