from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.logging import get_logger
from app.models.file import (
    FileCategory,
    FileRecord,
    FileSensitivity,
    ScanJob,
)
from app.models.insight import ScanInsight

logger = get_logger(__name__)

REPORT_TYPES = {
    "executive_summary": {"label": "Executive Summary", "formats": ["html", "json"]},
    "full_inventory": {"label": "Full File Inventory", "formats": ["csv", "json"]},
    "sensitivity_audit": {"label": "Sensitivity Audit", "formats": ["csv"]},
    "duplicate_files": {"label": "Duplicate Files Report", "formats": ["csv"]},
    "largest_files": {"label": "Largest Files", "formats": ["csv"]},
    "category_distribution": {"label": "Category Distribution", "formats": ["html", "json"]},
}


class ReportService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_available_reports(self) -> list[dict[str, Any]]:
        return [
            {"id": k, **v}
            for k, v in REPORT_TYPES.items()
        ]

    async def generate_report(self, report_type: str, fmt: str) -> tuple[str, str, str]:
        if report_type not in REPORT_TYPES:
            raise ValueError(f"Unknown report type: {report_type}")
        if fmt not in REPORT_TYPES[report_type]["formats"]:
            raise ValueError(f"Format {fmt} not supported for {report_type}")

        generator = getattr(self, f"_{report_type}", None)
        if not generator:
            raise ValueError(f"Report generator not implemented: {report_type}")

        data = await generator()

        if fmt == "json":
            content = json.dumps(data, indent=2, default=str)
            media_type = "application/json"
            ext = "json"
        elif fmt == "csv":
            content, ext = self._to_csv(data)
            media_type = "text/csv"
        elif fmt == "html":
            content = self._to_html(data, REPORT_TYPES[report_type]["label"])
            media_type = "text/html"
            ext = "html"
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        filename = f"{report_type}.{ext}"
        return content, media_type, filename

    async def _executive_summary(self) -> dict[str, Any]:
        result = await self.db.execute(
            select(
                func.count(FileRecord.id).label("total_files"),
                func.coalesce(func.sum(FileRecord.size), 0).label("total_size"),
            )
        )
        row = result.one()
        total_files = row.total_files
        total_size = int(row.total_size)

        cat_result = await self.db.execute(
            select(FileCategory.category, func.count().label("cnt"))
            .group_by(FileCategory.category)
            .order_by(func.count().desc())
        )
        categories = [{"category": r.category, "count": r.cnt} for r in cat_result]

        sens_result = await self.db.execute(
            select(FileSensitivity.sensitivity_level, func.count().label("cnt"))
            .group_by(FileSensitivity.sensitivity_level)
            .order_by(func.count().desc())
        )
        sensitivities = [{"level": r.sensitivity_level, "count": r.cnt} for r in sens_result]

        scan_result = await self.db.execute(
            select(ScanJob).order_by(ScanJob.created_at.desc()).limit(10)
        )
        scans = [
            {
                "id": s.id,
                "path": s.path,
                "status": s.status,
                "total_files": s.total_files,
                "scanned_files": s.scanned_files,
                "error_count": s.error_count,
                "started_at": str(s.started_at) if s.started_at else None,
                "completed_at": str(s.completed_at) if s.completed_at else None,
            }
            for s in scan_result.scalars()
        ]

        insights_result = await self.db.execute(
            select(ScanInsight).order_by(ScanInsight.scan_job_id.desc()).limit(20)
        )
        insights = [
            {
                "scan_job_id": i.scan_job_id,
                "type": i.insight_type,
                "content": i.content,
            }
            for i in insights_result.scalars()
        ]

        return {
            "generated_at": str(datetime.now(timezone.utc)),
            "total_files": total_files,
            "total_size_bytes": total_size,
            "total_size_readable": self._format_size(total_size),
            "categories": categories,
            "sensitivity_levels": sensitivities,
            "recent_scans": scans,
            "ai_insights": insights,
        }

    async def _full_inventory(self) -> list[dict[str, Any]]:
        result = await self.db.execute(
            select(FileRecord)
            .options(
                joinedload(FileRecord.category),
                joinedload(FileRecord.sensitivity),
            )
            .order_by(FileRecord.path)
            .limit(10000)
        )
        files = result.unique().scalars().all()
        return [
            {
                "path": f.path,
                "name": f.name,
                "extension": f.extension,
                "size": f.size,
                "size_readable": self._format_size(f.size),
                "mime_type": f.mime_type,
                "sha256": f.sha256,
                "entropy": f.entropy,
                "category": f.category.category if f.category else None,
                "sensitivity": f.sensitivity.sensitivity_level if f.sensitivity else None,
                "modified_at": str(f.modified_at) if f.modified_at else None,
            }
            for f in files
        ]

    async def _sensitivity_audit(self) -> list[dict[str, Any]]:
        result = await self.db.execute(
            select(FileRecord)
            .options(joinedload(FileRecord.sensitivity), joinedload(FileRecord.sensitive_findings))
            .join(FileSensitivity)
            .order_by(FileSensitivity.risk_score.desc())
            .limit(5000)
        )
        files = result.unique().scalars().all()
        rows = []
        for f in files:
            findings = [
                {
                    "type": sf.finding_type,
                    "value": sf.value,
                    "severity": sf.severity,
                    "count": sf.count,
                }
                for sf in (f.sensitive_findings or [])
            ]
            rows.append({
                "path": f.path,
                "name": f.name,
                "sensitivity_level": f.sensitivity.sensitivity_level if f.sensitivity else "Unknown",
                "risk_score": f.sensitivity.risk_score if f.sensitivity else 0.0,
                "findings_count": len(findings),
                "findings": json.dumps(findings, default=str),
            })
        return rows

    async def _duplicate_files(self) -> list[dict[str, Any]]:
        subq = (
            select(FileRecord.sha256, func.count().label("cnt"))
            .where(FileRecord.sha256.isnot(None))
            .group_by(FileRecord.sha256)
            .having(func.count() > 1)
            .subquery()
        )
        result = await self.db.execute(
            select(FileRecord, subq.c.cnt)
            .join(subq, FileRecord.sha256 == subq.c.sha256)
            .order_by(subq.c.cnt.desc(), FileRecord.sha256)
            .limit(5000)
        )
        rows = []
        for f, cnt in result:
            rows.append({
                "sha256": f.sha256,
                "path": f.path,
                "size": f.size,
                "size_readable": self._format_size(f.size),
                "duplicate_count": cnt,
            })
        return rows

    async def _largest_files(self) -> list[dict[str, Any]]:
        result = await self.db.execute(
            select(FileRecord)
            .order_by(FileRecord.size.desc())
            .limit(100)
        )
        files = result.scalars().all()
        return [
            {
                "path": f.path,
                "name": f.name,
                "extension": f.extension,
                "size": f.size,
                "size_readable": self._format_size(f.size),
                "mime_type": f.mime_type,
                "sha256": f.sha256,
            }
            for f in files
        ]

    async def _category_distribution(self) -> dict[str, Any]:
        result = await self.db.execute(
            select(FileCategory.category, func.count().label("cnt"))
            .group_by(FileCategory.category)
            .order_by(func.count().desc())
        )
        categories = [{"category": r.category, "count": r.cnt} for r in result]

        subcat_result = await self.db.execute(
            select(FileCategory.category, FileCategory.subcategory, func.count().label("cnt"))
            .where(FileCategory.subcategory.isnot(None))
            .group_by(FileCategory.category, FileCategory.subcategory)
            .order_by(FileCategory.category, func.count().desc())
        )
        subcategories: dict[str, list[dict]] = {}
        for r in subcat_result:
            key = r.category
            if key not in subcategories:
                subcategories[key] = []
            subcategories[key].append({"subcategory": r.subcategory, "count": r.cnt})

        return {
            "generated_at": str(datetime.now(timezone.utc)),
            "categories": categories,
            "subcategories": subcategories,
        }

    def _to_csv(self, data: Any) -> tuple[str, str]:
        output = io.StringIO()
        if isinstance(data, dict):
            self._dict_to_csv(data, output)
            ext = "csv"
        elif isinstance(data, list) and data:
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
            ext = "csv"
        else:
            output.write(json.dumps(data, indent=2, default=str))
            ext = "json"
        return output.getvalue(), ext

    def _dict_to_csv(self, data: dict, output: io.StringIO) -> None:
        writer = csv.writer(output)
        for key, value in data.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                writer.writerow([key])
                sub_writer = csv.DictWriter(output, fieldnames=value[0].keys())
                sub_writer.writeheader()
                sub_writer.writerows(value)
                writer.writerow([])
            elif not isinstance(value, list):
                writer.writerow([key, str(value)])

    # ── HTML helpers ──────────────────────────────────────────────────────────

    def _to_html(self, data: Any, title: str) -> str:
        body = self._render_html_body(data, title)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{self._e(title)} - Security Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #f1f5f9; color: #1e293b; line-height: 1.6;
  }}
  .report-header {{
    background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
    color: #fff; padding: 2.5rem 2rem; text-align: center;
  }}
  .report-header h1 {{ font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em; }}
  .report-header .subtitle {{ font-size: 0.9rem; opacity: .75; margin-top: .35rem; }}
  .report-container {{ max-width: 1100px; margin: 0 auto; padding: 1.5rem 1rem; }}
  .section {{
    background: #fff; border-radius: .75rem; box-shadow: 0 1px 3px rgba(0,0,0,.08);
    margin-bottom: 1.5rem; overflow: hidden;
  }}
  .section-header {{
    padding: 1rem 1.5rem; border-bottom: 1px solid #e2e8f0;
    font-size: 1.05rem; font-weight: 600; display: flex; align-items: center; gap: .5rem;
  }}
  .section-body {{ padding: 1.25rem 1.5rem; }}

  /* ── stat cards ─────────────────────────────────── */
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 1rem; }}
  .stat-card {{
    background: #fff; border-radius: .65rem; box-shadow: 0 1px 3px rgba(0,0,0,.08);
    padding: 1.25rem; text-align: center; border-top: 3px solid #2563eb;
  }}
  .stat-card .icon {{ font-size: 1.5rem; margin-bottom: .25rem; }}
  .stat-card .value {{ font-size: 1.65rem; font-weight: 800; color: #0f172a; }}
  .stat-card .label {{ font-size: .78rem; color: #64748b; }}

  /* ── bar chart ──────────────────────────────────── */
  .bar-chart {{ margin: .25rem 0; }}
  .bar-row {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .6rem; }}
  .bar-label {{ width: 120px; font-size: .82rem; font-weight: 500; flex-shrink: 0; text-align: right; color: #334155; }}
  .bar-track {{ flex: 1; height: 22px; background: #e2e8f0; border-radius: 11px; overflow: hidden; }}
  .bar-fill {{
    height: 100%; border-radius: 11px; display: flex; align-items: center;
    justify-content: flex-end; padding-right: 8px;
    font-size: .72rem; font-weight: 600; color: #fff; min-width: 36px;
    transition: width .3s ease;
  }}
  .bar-count {{ width: 44px; font-size: .82rem; font-weight: 600; color: #475569; flex-shrink: 0; }}

  /* ── sensitivity badges ─────────────────────────── */
  .badge {{
    display: inline-block; padding: .15rem .55rem; border-radius: 999px;
    font-size: .72rem; font-weight: 600; letter-spacing: .02em;
  }}
  .badge-critical {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}
  .badge-high {{ background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }}
  .badge-medium {{ background: #fffbeb; color: #a16207; border: 1px solid #fde68a; }}
  .badge-low {{ background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }}
  .badge-none {{ background: #f8fafc; color: #64748b; border: 1px solid #e2e8f0; }}

  /* ── tables ─────────────────────────────────────── */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ text-align: left; padding: .6rem .75rem; background: #f8fafc; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; white-space: nowrap; vertical-align: middle; }}
  td {{ padding: .55rem .75rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; line-height: 1.5; word-break: break-word; }}
  tr:hover td {{ background: #f8fafc; }}
  .table-wrap table th:first-child,
  .table-wrap table td:first-child {{ padding-left: 1rem; }}
  .table-wrap table th:last-child,
  .table-wrap table td:last-child {{ padding-right: 1rem; }}
  .num-cell {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
  .text-muted {{ color: #94a3b8; font-style: italic; }}
  .status-badge {{
    display: inline-block; padding: .1rem .5rem; border-radius: 999px;
    font-size: .72rem; font-weight: 600;
  }}
  .status-completed {{ background: #f0fdf4; color: #15803d; }}
  .status-running {{ background: #eff6ff; color: #1d4ed8; }}
  .status-pending {{ background: #fffbeb; color: #a16207; }}
  .status-failed {{ background: #fef2f2; color: #b91c1c; }}
  .status-paused {{ background: #f8fafc; color: #64748b; }}

  /* ── AI insight cards ───────────────────────────── */
  .insight-card {{
    border-left: 4px solid #2563eb; background: #f8fafc; border-radius: .5rem;
    padding: 1rem 1.25rem; margin-bottom: .75rem;
  }}
  .insight-card:last-child {{ margin-bottom: 0; }}
  .insight-card .insight-meta {{ font-size: .75rem; color: #64748b; margin-bottom: .25rem; }}
  .insight-card .insight-content {{ font-size: .88rem; color: #1e293b; white-space: pre-wrap; }}

  /* ── donut chart (SVG) ──────────────────────────── */
  .donut-wrap {{ display: flex; align-items: center; gap: 2rem; justify-content: center; flex-wrap: wrap; }}
  .donut-legend {{ display: flex; flex-direction: column; gap: .35rem; }}
  .legend-item {{ display: flex; align-items: center; gap: .5rem; font-size: .82rem; }}
  .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}

  /* ── responsive ─────────────────────────────────── */
  @media (max-width: 640px) {{
    .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .bar-label {{ width: 80px; font-size: .75rem; }}
    .bar-fill {{ font-size: .65rem; }}
    .report-header h1 {{ font-size: 1.35rem; }}
    .section-header {{ font-size: .95rem; }}
  }}

  /* ── utility ────────────────────────────────────── */
  .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: .8rem; }}
  .text-muted {{ color: #64748b; }}
  .text-sm {{ font-size: .82rem; }}
  .mt-1 {{ margin-top: .5rem; }}
  .mt-2 {{ margin-top: 1rem; }}
  .mb-1 {{ margin-bottom: .5rem; }}
  .flex {{ display: flex; }}
  .flex-wrap {{ flex-wrap: wrap; }}
  .gap-1 {{ gap: .5rem; }}
  .gap-2 {{ gap: 1rem; }}
  .w-full {{ width: 100%; }}
</style>
</head>
<body>
<div class="report-header">
  <h1>📋 {self._e(title)}</h1>
  <p class="subtitle">Generated on {now_utc} &bull; File Intelligence Platform</p>
</div>
<div class="report-container">
{body}
</div>
</body>
</html>"""

    def _e(self, s: Any) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── bar-chart palette ─────────────────────────────────────────────────────
    _palette = [
        "#2563eb", "#8b5cf6", "#06b6d4", "#10b981", "#f59e0b",
        "#ef4444", "#ec4899", "#84cc16", "#14b8a6", "#f97316",
        "#6366f1", "#d946ef", "#0ea5e9", "#22c55e", "#eab308",
    ]

    def _bar_fill(self, label: str, count: int, total: int, idx: int) -> str:
        pct = (count / total * 100) if total else 0
        color = self._palette[idx % len(self._palette)]
        return (
            f'<div class="bar-row">'
            f'<div class="bar-label">{self._e(label)}</div>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" style="width:{pct:.1f}%;background:{color}">{pct:.0f}%</div>'
            f'</div>'
            f'<div class="bar-count">{count}</div>'
            f'</div>'
        )

    def _bar_chart(self, items: list[dict], label_key: str, count_key: str) -> str:
        if not items:
            return "<p class='text-muted'>No data</p>"
        total = sum(item.get(count_key, 0) or 0 for item in items)
        bars = "".join(
            self._bar_fill(item.get(label_key, ""), int(item.get(count_key, 0)), total, i)
            for i, item in enumerate(items)
        )
        return f'<div class="bar-chart">{bars}</div>'

    # ── SVG donut chart ───────────────────────────────────────────────────────
    def _donut_chart(self, items: list[dict], label_key: str, count_key: str) -> str:
        if not items:
            return "<p class='text-muted'>No data</p>"
        total = sum(item.get(count_key, 0) or 0 for item in items)
        if total == 0:
            return "<p class='text-muted'>No data</p>"

        size = 180
        cx = cy = size // 2
        r = 72
        stroke_width = 28

        segments: list[str] = []
        offset = 0
        circumference = 2 * 3.14159 * r

        legend_items: list[str] = []
        for i, item in enumerate(items):
            count = int(item.get(count_key, 0))
            pct = count / total
            if pct == 0:
                continue
            dash = pct * circumference
            color = self._palette[i % len(self._palette)]
            segments.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{color}" stroke-width="{stroke_width}" '
                f'stroke-dasharray="{dash:.1f} {circumference - dash:.1f}" '
                f'stroke-dashoffset="{-offset:.1f}" '
                f'transform="rotate(-90 {cx} {cy})" />'
            )
            offset += dash
            label = self._e(item.get(label_key, ""))
            legend_items.append(
                f'<div class="legend-item">'
                f'<span class="legend-dot" style="background:{color}"></span>'
                f'{label} <strong>{count}</strong> <span class="text-muted">({pct*100:.0f}%)</span>'
                f'</div>'
            )

        if not segments:
            return "<p class='text-muted'>No data</p>"

        return (
            f'<div class="donut-wrap">'
            f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e2e8f0" stroke-width="{stroke_width}" />'
            f'{"".join(segments)}'
            f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" '
            f'font-size="24" font-weight="800" fill="#0f172a">{total}</text>'
            f'</svg>'
            f'<div class="donut-legend">{"".join(legend_items)}</div>'
            f'</div>'
        )

    # ── summary cards ────────────────────────────────────────────────────────
    def _summary_cards(self, cards: list[tuple[str, str, str]]) -> str:
        rows = []
        for icon, value, label in cards:
            rows.append(
                f'<div class="stat-card">'
                f'<div class="icon">{icon}</div>'
                f'<div class="value">{self._e(value)}</div>'
                f'<div class="label">{self._e(label)}</div>'
                f'</div>'
            )
        return f'<div class="stat-grid">{"".join(rows)}</div>'

    # ── status badge helper ───────────────────────────────────────────────────
    def _status_badge(self, status: str) -> str:
        cls = status.lower().replace(" ", "-")
        return f'<span class="status-badge status-{cls}">{self._e(status)}</span>'

    # ── sensitivity badge ─────────────────────────────────────────────────────
    def _sensitivity_badge(self, level: str) -> str:
        cls = level.lower().replace(" ", "-")
        return f'<span class="badge badge-{cls}">{self._e(level)}</span>'

    # ── AI insight card ───────────────────────────────────────────────────────
    def _insight_card(self, insight: dict) -> str:
        scan_id = self._e(insight.get("scan_job_id", ""))
        itype = self._e(insight.get("type", ""))
        content = insight.get("content", {})
        if not isinstance(content, dict):
            body = f"<p>{self._e(content)}</p>"
        elif itype == "executive_summary":
            summary = content.get("summary", "")
            body = f"<p>{self._e(summary)}</p>"
        else:
            items = content.get("items", [])
            if isinstance(items, list) and items:
                cleaned = []
                for item in items:
                    if "file_name" in item:
                        cleaned.append({k: v for k, v in item.items() if k != "id"})
                    else:
                        cleaned.append(item)
                body = self._table_from_list(cleaned)
            else:
                body = f"<p class='text-muted'>{self._e(str(items))}</p>"
        return (
            f'<div class="insight-card">'
            f'<div class="insight-meta">Scan #{scan_id} &bull; {itype}</div>'
            f'<div class="insight-content">{body}</div>'
            f'</div>'
        )

    # ── main body renderer ─────────────────────────────────────────────────────
    def _render_html_body(self, data: Any, title: str) -> str:
        if isinstance(data, dict):
            return self._render_dict(data)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return self._section("Data", self._table_from_list(data))
        return f"<pre>{json.dumps(data, indent=2, default=str)}</pre>"

    def _section(self, heading: str, body: str) -> str:
        return (
            f'<div class="section">'
            f'<div class="section-header">{self._e(heading)}</div>'
            f'<div class="section-body">{body}</div>'
            f'</div>'
        )

    def _render_dict(self, data: dict) -> str:
        parts: list[str] = []

        # executive_summary
        if "total_files" in data:
            cards = [
                ("📁", str(data["total_files"]), "Total Files"),
                ("💾", str(data.get("total_size_readable", self._format_size(data.get("total_size_bytes", 0)))), "Total Size"),
                ("🔍", str(len(data.get("recent_scans", []))), "Recent Scans"),
                ("📊", str(len(data.get("categories", []))), "Categories"),
            ]
            parts.append(self._section("Summary", self._summary_cards(cards)))

        # Category distribution
        categories = data.get("categories", [])
        if categories:
            parts.append(self._section(
                "📂 Category Distribution",
                self._bar_chart(categories, "category", "count")
            ))

        # Sensitivity levels
        sens = data.get("sensitivity_levels", [])
        if sens:
            parts.append(self._section(
                "🔒 Sensitivity Distribution",
                self._donut_chart(sens, "level", "count")
            ))

        # Recent scans
        scans = data.get("recent_scans", [])
        if scans:
            rows: list[str] = []
            for s in scans:
                status = self._status_badge(s.get("status", ""))
                rows.append(
                    f"<tr>"
                    f"<td>{self._e(s.get('id', ''))}</td>"
                    f"<td>{self._e(s.get('path', ''))}</td>"
                    f"<td>{status}</td>"
                    f"<td>{self._e(s.get('total_files', ''))}</td>"
                    f"<td>{self._e(s.get('scanned_files', ''))}</td>"
                    f"<td>{self._e(s.get('error_count', 0))}</td>"
                    f"<td style='white-space:nowrap'>{self._e(s.get('started_at', '') or '')}</td>"
                    f"</tr>"
                )
            table = (
                '<div class="table-wrap"><table>'
                "<thead><tr><th>ID</th><th>Path</th><th>Status</th><th>Total</th><th>Scanned</th><th>Errors</th><th>Started</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody>"
                "</table></div>"
            )
            parts.append(self._section("🕐 Recent Scans", table))

        # AI insights
        insights = data.get("ai_insights", [])
        if insights:
            cards = "".join(self._insight_card(i) for i in insights)
            parts.append(self._section("🤖 AI Insights", cards))

        # ── generic keys that haven't been handled ──────────────────────────
        skip_keys = {
            "generated_at", "total_files", "total_size_bytes", "total_size_readable",
            "categories", "sensitivity_levels", "recent_scans", "ai_insights",
        }
        for key, value in data.items():
            if key in skip_keys:
                continue
            if isinstance(value, list) and value and isinstance(value[0], dict):
                parts.append(self._section(
                    key.replace("_", " ").title(),
                    self._table_from_list(value)
                ))
            elif isinstance(value, dict):
                parts.append(self._section(
                    key.replace("_", " ").title(),
                    self._render_dict(value)
                ))
            else:
                parts.append(
                    f'<p><strong>{self._e(key.replace("_", " ").title())}:</strong> '
                    f'{self._e(value)}</p>'
                )

        return "\n".join(parts)

    # ── table renderer ────────────────────────────────────────────────────────
    def _table_from_list(self, items: list[dict]) -> str:
        if not items:
            return "<p class='text-muted'>No data</p>"
        keys = list(items[0].keys())
        numeric_keys = set()
        sample = items[0]
        for k in keys:
            v = sample.get(k)
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                numeric_keys.add(k)
        rows: list[str] = []
        for item in items:
            cells = []
            for k in keys:
                cls = ' class="num-cell"' if k in numeric_keys else ""
                cells.append(f"<td{cls}>{self._cell_value(item.get(k, ''))}</td>")
            rows.append(f"<tr>{''.join(cells)}</tr>")
        headers = "".join(f"<th>{self._e(k.replace('_', ' ').title())}</th>" for k in keys)
        return f'<div class="table-wrap"><table><thead><tr>{headers}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'

    def _cell_value(self, v: Any) -> str:
        if v is None:
            return '<span class="text-muted">—</span>'
        if isinstance(v, list):
            s = ", ".join(str(x) for x in v)
        else:
            s = str(v)
        if len(s) > 120:
            s = s[:120] + "…"
        return self._e(s)

    # ── size formatting ───────────────────────────────────────────────────────
    def _format_size(self, size: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
