"""
core/reporter.py
Renders the AI evaluation in three formats:
  1. Terminal (rich, detailed, paginated)
  2. HTML (dark theme, professional)
  3. PDF (reportlab)
  4. JSON (raw dump)

The AI output is now much more detailed — the reporter must display ALL of it.
"""

from __future__ import annotations

import datetime as _dt
import html as _html
import json
from pathlib import Path
from typing import Any

from config import REPORT_DIR, APP_NAME, APP_VERSION
from core.recorder import SessionLog
from core import ui
from rich.panel import Panel


def _safe_slug(text: str) -> str:
    keep = [c for c in text.lower().strip() if c.isalnum() or c in "-_ "]
    return "".join(keep).replace(" ", "_")[:40] or "session"


def _ts() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def _as_list(value: Any) -> list[Any]:
    """Coerce an evaluation field to a list (strings are single items)."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _get(ev: dict, key: str, default: Any = "") -> Any:
    v = ev.get(key, default)
    return v if v not in (None, "") else default


def _esc(value: Any) -> str:
    """HTML-escape AI/model-derived strings before injecting into HTML or PDF
    (reportlab Paragraphs parse mini-HTML, so the same escaping applies)."""
    return _html.escape(str(value or ""), quote=True)


# ======================================================================== #
# 1. Terminal — detailed, section-by-section
# ======================================================================== #
def render_terminal(session: SessionLog, ev: dict) -> None:
    ui.clear_screen()
    score = int(_get(ev, "score", 0))
    grade = str(_get(ev, "grade", ""))
    verdict = str(_get(ev, "final_verdict", ""))
    overall = str(_get(ev, "overall_assessment", ""))

    # ── Score header ──
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "dark_orange"
    else:
        color = "red"

    ui.console.rule("[bold cyan]AI INCIDENT RESPONSE EVALUATION[/bold cyan]")
    ui.console.print()
    ui.console.print(
        Panel(
            f"[bold {color}]SCORE: {score}/100[/bold {color}]   "
            f"[bold]Grade: {grade}[/bold]\n\n"
            f"{overall}",
            border_style=color,
            title="[bold]ASSESSMENT[/bold]",
        )
    )
    ui.console.print()

    # ── Leadership Summary ── (role-aware executive brief)
    if session.user_role or ev.get("executiveBrief") or ev.get("executive_brief"):
        role_label = session.user_role.title() if session.user_role else "Analyst"
        exec_brief = ev.get("executiveBrief") or ev.get("executive_brief") or ""
        ui.console.rule(f"[bold cyan]LEADERSHIP SUMMARY — Role: {role_label}[/bold cyan]")
        if exec_brief:
            ui.print_panel(str(exec_brief), title="[bold]Executive Brief[/bold]", border="yellow")
        else:
            ui.print_panel(
                f"Evaluated from the perspective of: [bold]{role_label}[/bold]\n"
                f"Category: {session.incident_category or 'N/A'}",
                title="[bold]Role Context[/bold]",
                border="cyan",
            )
        ui.console.print()

    # ── Final verdict ──
    if verdict:
        ui.print_panel(verdict, title="[bold]Final Verdict[/bold]", border="white")
        ui.console.print()

    # ── Phase-by-phase breakdown ──
    phases = _get(ev, "phase_evaluations", []) or []
    if phases:
        ui.console.rule("[bold magenta]PHASE-BY-PHASE ANALYSIS[/bold magenta]")
        ui.console.print()
        for p in phases:
            if not isinstance(p, dict):
                continue
            num = p.get("phase_number", "?")
            title = p.get("phase_title", "")
            correctness = p.get("correctness", 0)
            action_type = p.get("user_action_type", "")
            user_action = str(p.get("user_action", ""))[:100]

            c_color = "green" if correctness >= 8 else "yellow" if correctness >= 5 else "red"
            ui.console.print(
                f"  [bold cyan]Phase {num}[/bold cyan]: {title}   "
                f"[bold {c_color}]{correctness}/10[/bold {c_color}]   "
                f"[dim]{action_type}[/dim]"
            )
            ui.console.print(f"    [white]Action:[/white] {user_action}")
            # Support both compact ('analysis') and verbose ('detailed_analysis' + sub-fields) schemas
            analysis = str(p.get("analysis") or p.get("detailed_analysis") or "")
            if analysis:
                ui.console.print(f"    [dim]{analysis}[/dim]")
            what_right = str(p.get("what_did_right", ""))
            if what_right:
                ui.console.print(f"    [green]✓ What they did right:[/green] {what_right}")
            what_wrong = str(p.get("what_did_wrong", ""))
            if what_wrong:
                ui.console.print(f"    [red]✗ What was wrong:[/red] {what_wrong}")
            improve = str(p.get("how_to_improve", ""))
            if improve:
                ui.console.print(f"    [yellow]💡 How to improve:[/yellow] {improve}")
            mitre_rel = str(p.get("mitre_relevance", ""))
            if mitre_rel:
                ui.console.print(f"    [dim]MITRE: {mitre_rel}[/dim]")
            ui.console.print()

    # ── Strengths & Weaknesses ──
    strengths = _as_list(_get(ev, "strengths", []))
    if strengths:
        ui.console.rule("[bold green]STRENGTHS[/bold green]")
        for s in strengths:
            ui.console.print(f"  [green]✓[/green] {s}")
        ui.console.print()

    weaknesses = _as_list(_get(ev, "weaknesses", []))
    if weaknesses:
        ui.console.rule("[bold red]WEAKNESSES[/bold red]")
        for w in weaknesses:
            ui.console.print(f"  [red]✗[/red] {w}")
        ui.console.print()

    # ── Tightening recommendations ──
    tightening = _get(ev, "tightening_recommendations", []) or []
    if tightening:
        ui.console.rule("[bold yellow]TIGHTENING RECOMMENDATIONS[/bold yellow]")
        for item in tightening:
            if isinstance(item, dict):
                area = item.get("area", "")
                gap = item.get("current_gap", "")
                rec = item.get("recommendation", "")
                pri = item.get("priority", "")
                ref = item.get("reference", "")
                ui.console.print(
                    f"  [bold yellow]![/bold yellow] [{pri}] [cyan]{area}[/cyan]"
                )
                ui.console.print(f"      [dim]Gap:[/dim] {gap}")
                ui.console.print(f"      [white]Fix:[/white] {rec}")
                if ref:
                    ui.console.print(f"      [dim]Ref:[/dim] {ref}")
                ui.console.print()
            else:
                ui.console.print(f"  [yellow]![/yellow] {item}")
                ui.console.print()

    # ── Missed opportunities ──
    missed = _as_list(_get(ev, "missed_opportunities", []))
    if missed:
        ui.console.rule("[bold]MISSED OPPORTUNITIES[/bold]")
        for m in missed:
            ui.console.print(f"  • {m}")
        ui.console.print()

    # ── Tools & Frameworks ── (field name varies by schema version)
    used = _as_list(_get(ev, "tools_used", []) or _get(ev, "tools_and_frameworks_used", []))
    missing = _as_list(_get(ev, "tools_missing", []) or _get(ev, "tools_and_frameworks_missing", []))
    if used or missing:
        ui.console.rule("[bold cyan]TOOLS & FRAMEWORKS[/bold cyan]")
        for t in used:
            ui.console.print(f"  [green]✓ Used:[/green] {t}")
        for t in missing:
            ui.console.print(f"  [red]✗ Missing:[/red] {t}")
        ui.console.print()

    # ── Communication assessment ──
    comm_grade = str(_get(ev, "communication_grade", ""))
    comm_fb = str(_get(ev, "communication_feedback", ""))
    if comm_grade:
        ui.console.rule("[bold]COMMUNICATION ASSESSMENT[/bold]")
        ui.console.print(f"  Grade: [bold]{comm_grade}[/bold]")
        if comm_fb:
            ui.console.print(f"  {comm_fb}")
        ui.console.print()

    # ── Incident timeline recommendation ──
    tl_rec = str(_get(ev, "incident_timeline_recommendation", ""))
    if tl_rec:
        ui.console.rule("[bold]TIMELINE RECOMMENDATION[/bold]")
        ui.console.print(f"  {tl_rec}")
        ui.console.print()

    # ── Next training scenarios ── (field name varies)
    nxt = _as_list(_get(ev, "next_training", []) or _get(ev, "next_training_scenarios", []))
    if nxt:
        ui.console.rule("[bold blue]NEXT TRAINING RECOMMENDATIONS[/bold blue]")
        for n in nxt:
            ui.console.print(f"  [blue]→[/blue] {n}")
        ui.console.print()

    ui.console.rule("[bold cyan]END OF EVALUATION[/bold cyan]")


# ======================================================================== #
# 2. HTML
# ======================================================================== #
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0f1115; color:#e4e6eb; margin:0; padding:24px; max-width:1100px; margin:auto; }}
h1 {{ color:#4dd0e1; border-bottom:2px solid #2a2f36; padding-bottom:8px; }}
h2 {{ color:#81c784; margin-top:32px; }} h3 {{ color:#ffb74d; margin-top:16px; }}
.meta {{ color:#9aa0a6; font-size:14px; }}
.score {{ font-size:56px; font-weight:bold; color:{score_color}; display:inline; }}
.grade {{ font-size:22px; color:{grade_color}; margin-left:16px; }}
.panel {{ background:#1a1d24; border:1px solid #2a2f36; border-radius:8px; padding:16px 20px; margin:12px 0; }}
.ok {{ border-left:4px solid #4caf50; }} .warn {{ border-left:4px solid #ff9800; }}
.bad {{ border-left:4px solid #f44336; }} .info {{ border-left:4px solid #2196f3; }}
.phase {{ background:#12151a; border:1px solid #2a2f36; border-radius:8px; padding:14px 18px; margin:10px 0; }}
table {{ width:100%; border-collapse:collapse; margin:12px 0; }}
th, td {{ padding:8px 10px; text-align:left; border-bottom:1px solid #2a2f36; font-size:14px; }}
th {{ color:#4dd0e1; }}
code {{ background:#2a2f36; padding:2px 6px; border-radius:3px; font-family:Consolas,monospace; }}
.footer {{ margin-top:40px; color:#5f6368; font-size:12px; border-top:1px solid #2a2f36; padding-top:10px; }}
</style>
</head>
<body>
<h1>🛡️ {app_name} — IR Evaluation Report</h1>
<div class="meta">
  <strong>Incident:</strong> {incident}<br>
  <strong>Analyst:</strong> {user_name}<br>
  <strong>Category:</strong> {category}<br>
  <strong>Generated:</strong> {generated}
</div>
<div class="panel info">
  <span class="score">{score}/100</span><span class="grade">{grade}</span>
  <p><em>{assessment}</em></p>
    <p><strong>Verdict:</strong> {verdict}</p>
  </div>
  {leadership}
  {body}
<div class="footer">{app_name} v{version} — Simulation only, educational use.</div>
</body>
</html>"""


def render_html(session: SessionLog, ev: dict) -> Path:
    score = int(_get(ev, "score", 0))
    grade = str(_get(ev, "grade", ""))
    assessment = str(_get(ev, "overall_assessment", ""))
    verdict = str(_get(ev, "final_verdict", ""))
    sc = "#4caf50" if score >= 80 else "#ff9800" if score >= 50 else "#f44336"
    gc = sc

    # Body sections
    body = ""

    # Phase evaluations
    phases = _get(ev, "phase_evaluations", []) or []
    if phases:
        body += "<h2>Phase-by-Phase Analysis</h2>"
        for p in phases:
            if not isinstance(p, dict):
                continue
            corr = p.get("correctness", 0)
            cc = "#4caf50" if corr >= 8 else "#ff9800" if corr >= 5 else "#f44336"
            analysis = p.get("analysis") or p.get("detailed_analysis") or ""
            body += f"""<div class="phase">
<b>Phase {_esc(p.get('phase_number','?'))}: {_esc(p.get('phase_title',''))}</b>
<span style="color:{cc};font-weight:bold"> {corr}/10</span><br>
<b>Action:</b> {_esc(p.get('user_action',''))} <em>({_esc(p.get('user_action_type',''))})</em><br>
<b>Ideal:</b> {_esc(p.get('ideal_action',''))}<br>
<p style="margin:6px 0">{_esc(analysis)}</p>
"""
            for key, color in [("what_did_right","#4caf50"), ("what_did_wrong","#f44336"), ("how_to_improve","#ff9800")]:
                v = str(p.get(key, ""))
                if v:
                    body += f'<p style="color:{color};margin:2px 0"><b>{key.replace("_"," ").title()}:</b> {_esc(v)}</p>\n'
            body += "</div>\n"

    # Strengths / Weaknesses
    for title, cls, key in [("Strengths","ok","strengths"), ("Weaknesses","bad","weaknesses")]:
        items = _get(ev, key, []) or []
        if items:
            body += f"<h2>{title}</h2>"
            for i in items:
                body += f'<div class="panel {cls}">• {_esc(i)}</div>'

    # Tightening
    tightening = _get(ev, "tightening_recommendations", []) or []
    if tightening:
        body += "<h2>Tightening Recommendations</h2>"
        for item in tightening:
            if isinstance(item, dict):
                pri = item.get("priority", "")
                gap = item.get("gap") or item.get("current_gap") or ""
                rec = item.get("recommendation", "")
                ref = item.get("reference", "")
                body += f"""<div class="panel warn">
<b>[{_esc(pri)}] {_esc(item.get('area',''))}</b><br>
<em>Gap:</em> {_esc(gap)}<br>
<b>Fix:</b> {_esc(rec)}"""
                if ref:
                    body += f"<br><em>Ref:</em> <code>{_esc(ref)}</code>"
                body += "</div>"
            else:
                body += f'<div class="panel warn">• {_esc(item)}</div>'

    # More sections
    for title, key, fallback in [
        ("Missed Opportunities", "missed_opportunities", None),
        ("Tools & Frameworks Used", "tools_used", "tools_and_frameworks_used"),
        ("Missing Tools & Frameworks", "tools_missing", "tools_and_frameworks_missing"),
        ("Next Training Scenarios", "next_training", "next_training_scenarios"),
    ]:
        items = _as_list(_get(ev, key, []) or (_get(ev, fallback, []) if fallback else []))
        if items:
            body += f"<h2>{title}</h2>"
            for i in items:
                body += f'<div class="panel info">• {_esc(i)}</div>'

    # Communication
    comm = str(_get(ev, "communication_grade", ""))
    if comm:
        body += f"<h2>Communication Assessment</h2><div class='panel info'><b>Grade:</b> {_esc(comm)}<br>{_esc(_get(ev,'communication_feedback',''))}</div>"

    # Leadership Summary (role-aware)
    leadership = ""
    if session.user_role or ev.get("executiveBrief") or ev.get("executive_brief"):
        role_label = session.user_role.title() if session.user_role else "Analyst"
        exec_brief = str(ev.get("executiveBrief") or ev.get("executive_brief") or "")
        leadership = f'<div class="panel warn"><b>Leadership Summary — Role: {_esc(role_label)}</b><br>'
        if exec_brief:
            leadership += f'<p>{_esc(exec_brief)}</p>'
        else:
            leadership += f'<p>Evaluated from the perspective of: <b>{_esc(role_label)}</b></p>'
        leadership += '</div>'

    # Timeline recommendation
    tl = str(_get(ev, "incident_timeline_recommendation", ""))
    if tl:
        body += f"<h2>Incident Timeline Recommendation</h2><div class='panel'>{_esc(tl)}</div>"

    # Action log table
    body += "<h2>Recorded Action Log</h2><table><tr><th>#</th><th>Time</th><th>Phase</th><th>Type</th><th>Action</th></tr>"
    for a in session.actions:
        body += f"<tr><td>{_esc(a.phase_number)}</td><td>{_esc(a.timestamp)}</td><td>{_esc(a.phase_title)}</td><td>{_esc(a.choice_type)}</td><td>{_esc(a.user_response[:80])}</td></tr>"
    body += "</table>"

    html = _HTML_TEMPLATE.format(
        title=_esc(f"{session.incident_title} Report"),
        app_name=APP_NAME, version=APP_VERSION,
        incident=_esc(session.incident_title),
        category=_esc(session.incident_category),
        user_name=_esc(session.user_name),
        generated=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score=score, score_color=sc, grade=_esc(grade), grade_color=gc,
        assessment=_esc(assessment), verdict=_esc(verdict),
        leadership=leadership,
        body=body,
    )
    path = REPORT_DIR / f"report_{_safe_slug(session.incident_title)}_{_ts()}.html"
    path.write_text(html, encoding="utf-8")
    return path


# ======================================================================== #
# 3. PDF
# ======================================================================== #
def render_pdf(session: SessionLog, ev: dict) -> Path | None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    except ImportError:
        ui.write_warn("reportlab not installed — skipping PDF.")
        return None

    score = int(_get(ev, "score", 0))
    grade = str(_get(ev, "grade", ""))
    overall = str(_get(ev, "overall_assessment", ""))

    path = REPORT_DIR / f"report_{_safe_slug(session.incident_title)}_{_ts()}.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    h1, h2, h3 = styles["Heading1"], styles["Heading2"], styles["Heading3"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)
    h1.textColor = colors.HexColor("#0d47a1")
    h2.textColor = colors.HexColor("#1565c0")
    h3.textColor = colors.HexColor("#37474f")

    story = []
    story.append(Paragraph(f"{APP_NAME} — IR Evaluation Report", h1))
    story.append(Paragraph(
        f"<b>Incident:</b> {_esc(session.incident_title)}<br/>"
        f"<b>Analyst:</b> {_esc(session.user_name)}<br/>"
        f"<b>Generated:</b> {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
        f"<b>Tool:</b> {APP_NAME} v{APP_VERSION}", body))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<font size=28><b>{score}/100</b></font>  <font size=14>{_esc(grade)}</font>", body))
    story.append(Paragraph(f"<i>{_esc(overall)}</i>", body))
    story.append(Spacer(1, 12))

    # Leadership Summary (role-aware executive brief)
    if session.user_role or ev.get("executiveBrief") or ev.get("executive_brief") or session.executive_brief:
        role_label = session.user_role.title() if session.user_role else "Analyst"
        exec_brief = str(ev.get("executiveBrief") or ev.get("executive_brief") or session.executive_brief or "")
        story.append(Paragraph(f"Leadership Summary — Role: {_esc(role_label)}", h2))
        if exec_brief:
            story.append(Paragraph(_esc(exec_brief), body))
        else:
            story.append(Paragraph(f"Evaluated from the perspective of: {_esc(role_label)}", body))
        story.append(Spacer(1, 6))

    # Phase table
    phases = _get(ev, "phase_evaluations", []) or []
    if phases:
        story.append(Paragraph("Phase-by-Phase Analysis", h2))
        for p in phases:
            if not isinstance(p, dict):
                continue
            story.append(Paragraph(f"Phase {_esc(p.get('phase_number','?'))}: {_esc(p.get('phase_title',''))} — {_esc(p.get('correctness','?'))}/10", h3))
            story.append(Paragraph(f"<b>Action:</b> {_esc(p.get('user_action',''))} ({_esc(p.get('user_action_type',''))})", body))
            story.append(Paragraph(f"<b>Ideal:</b> {_esc(p.get('ideal_action',''))}", small))
            analysis = str(p.get("analysis") or p.get("detailed_analysis") or "")
            if analysis:
                story.append(Paragraph(_esc(analysis), body))
            story.append(Spacer(1, 6))

    # Log table
    story.append(Paragraph("Action Log", h2))
    rows = [["#", "Time", "Phase", "Type", "Action"]]
    for a in session.actions:
        rows.append([str(a.phase_number), a.timestamp, a.phase_title[:30], a.choice_type, a.user_response[:60]])
    t = Table(rows, colWidths=[8*mm, 20*mm, 35*mm, 18*mm, 90*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1565c0")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#cccccc")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    story.append(t)

    # Sections
    for title, key, fallback in [
        ("Strengths","strengths",None),
        ("Weaknesses","weaknesses",None),
        ("Missed Opportunities","missed_opportunities",None),
        ("Next Steps","next_training","next_training_scenarios"),
    ]:
        items = _as_list(_get(ev, key, []) or (_get(ev, fallback, []) if fallback else []))
        if items:
            story.append(Paragraph(title, h2))
            for i in items:
                story.append(Paragraph(f"• {_esc(i)}", body))

    tightening = _get(ev, "tightening_recommendations", []) or []
    if tightening:
        story.append(Paragraph("Tightening Recommendations", h2))
        for item in tightening:
            if isinstance(item, dict):
                gap = item.get("gap") or item.get("current_gap") or ""
                story.append(Paragraph(
                    f"[{_esc(item.get('priority',''))}] {_esc(item.get('area',''))}: "
                    f"{_esc(item.get('recommendation',''))}"
                    + (f"<br/><font size=8 color='#777777'>Gap: {_esc(gap)}</font>" if gap else ""),
                    body,
                ))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc")))
    story.append(Paragraph("Generated by {app} — Simulation only.".format(app=APP_NAME), small))
    doc.build(story)
    return path


# ======================================================================== #
# 4. JSON
# ======================================================================== #
def render_json(session: SessionLog, ev: dict) -> Path:
    path = REPORT_DIR / f"report_{_safe_slug(session.incident_title)}_{_ts()}.json"
    payload = {"session": session.to_dict(), "evaluation": ev}
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


# ======================================================================== #
# Top-level
# ======================================================================== #
def generate_all(session: SessionLog, ev: dict) -> dict[str, Path | None]:
    render_terminal(session, ev)

    html_path = render_html(session, ev)
    pdf_path = render_pdf(session, ev)
    json_path = render_json(session, ev)

    ui.console.print()
    ui.write_success(f"HTML  report: [cyan]{html_path}[/cyan]")
    if pdf_path:
        ui.write_success(f"PDF   report: [cyan]{pdf_path}[/cyan]")
    else:
        ui.write_warn("PDF skipped (reportlab not installed).")
    ui.write_success(f"JSON  report: [cyan]{json_path}[/cyan]")

    return {"html": html_path, "pdf": pdf_path, "json": json_path}
