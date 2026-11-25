"""
core/ui.py
Rich-powered terminal UI helpers for the blue-team incident-response trainer.

Design principles (per user request):
  - NO instant feedback on user actions. The script never tells the user
    whether their action was right or wrong — only the AI does, at the end.
  - Clear the screen after each action to keep the view uncluttered.
  - At each phase the user may either pick a listed option OR type their own
    free-text response (open-ended).
"""

from __future__ import annotations

import os
from typing import Optional, Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Confirm

from config import APP_NAME, APP_TAGLINE, APP_VERSION, DISCLAIMER

try:
    import sys as _sys
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

console = Console(force_terminal=True, color_system="auto", legacy_windows=False)

ROLE_DESCRIPTIONS = {
    "analyst": "Tier-1 SOC Analyst — Triage alerts, scope breaches, identify compromised accounts.",
    "incident_manager": "Incident Manager — Coordinate forensics, evidence preservation, and stakeholder communications.",
    "ciso": "CISO — Assess regulatory obligations, engage legal counsel, and prepare board-level updates.",
    "executive": "Executive (CEO/CFO) — Receive war-room updates on business impact, resource needs, and communication plan.",
}


def write_role_header(role: str, scenario_meta=None) -> None:
    """Print a role-specific intro banner before the briefing."""
    desc = ROLE_DESCRIPTIONS.get(role, "")
    if scenario_meta:
        roles_available = getattr(scenario_meta, "roles", ["analyst"])
        if role not in roles_available:
            ui_warn_msg = f"Note: '{role}' is not in this scenario's available roles — using best-fit."
            console.print(f"[dim]{ui_warn_msg}[/dim]")
    title = role.title()
    panel = Panel(
        f"[bold white]{title}[/bold white]\n[dim]{desc}[/dim]",
        border_style="yellow",
        title="[bold]SOC ROLE SELECTED[/bold]",
    )
    console.print(panel)
    console.print()


# --------------------------------------------------------------------------- #
# Screen
# --------------------------------------------------------------------------- #
def clear_screen() -> None:
    """Clear the terminal. Works on Windows and POSIX."""
    os.system("cls" if os.name == "nt" else "clear")


# --------------------------------------------------------------------------- #
# Banner / headers
# --------------------------------------------------------------------------- #
def banner() -> None:
    ascii_art = r"""
   ___   _____  __  __ _____ _   _ _____      _    ___   ___ ___  ___
  / _ \ / _ \ \/ / |_   _| | | | ____|    / \  | _ ) / _ \   \/ __|
 | | | | | | \  /    | | | |_| |  _|     / _ \ | _ \| | | | |) \__ \
 | |_| | |_| /  \    | | |  _  | |___   / ___ \| ___) |_| |_|  _ <|___/
  \__\_\\___/_/\_\   |_| |_| |_|_____| /_/   \_\_____\___/|_| \_\   |
"""
    console.print(
        Panel(
            f"[bold cyan]{ascii_art}[/bold cyan]\n"
            f"[bold white]{APP_NAME}[/bold white]  [dim]v{APP_VERSION}[/dim]\n"
            f"[italic]{APP_TAGLINE}[/italic]",
            border_style="cyan",
            title="[bold cyan]BLUE TEAM IR TRAINER[/bold cyan]",
        )
    )
    console.print(DISCLAIMER)
    console.print()


def write_phase(title: str, situation: Optional[str] = None, phase_num: Optional[int] = None) -> None:
    """Print a phase header (no feedback, just context)."""
    header = (
        f"[bold magenta][INCIDENT PHASE {phase_num}][/bold magenta] [bold white]{title}[/bold white]"
        if phase_num is not None
        else f"[bold magenta]{title}[/bold magenta]"
    )
    console.rule(header, style="magenta")
    if situation:
        console.print(Panel(situation, border_style="cyan", title="[cyan]Situation[/cyan]"))


def write_mitre(tactic: str, technique: str) -> None:
    """Print a MITRE ATT&CK mapping line (context only, no judgment)."""
    console.print(f"  [bold red][MITRE][/bold red] Tactic: [cyan]{tactic}[/cyan] | "
                  f"Technique: [cyan]{technique}[/cyan]")


def write_info(msg: str) -> None:
    console.print(f"  [dim][INFO][/dim] {msg}")


def write_success(msg: str) -> None:
    console.print(f"  [bold green]✓[/bold green] {msg}")


def write_warn(msg: str) -> None:
    console.print(f"  [bold yellow]![/bold yellow] {msg}")


def write_error(msg: str) -> None:
    console.print(f"  [bold red]✗[/bold red] {msg}")


# --------------------------------------------------------------------------- #
# Menus & prompts
# --------------------------------------------------------------------------- #
def print_menu(title: str, options: list[str]) -> None:
    table = Table(title=title, border_style="cyan", show_lines=False)
    table.add_column("#", style="bold green", width=4)
    table.add_column("Option", style="white")
    for i, opt in enumerate(options, 1):
        table.add_row(str(i), opt)
    console.print(table)


def print_role_menu(title: str, options: list[str]) -> None:
    """Print a role selection menu with descriptions."""
    table = Table(title=title, border_style="yellow", show_lines=False, show_header=False)
    table.add_column("#", style="bold green", width=4)
    table.add_column("Role", style="white")
    table.add_column("Description", style="dim")
    for i, opt in enumerate(options, 1):
        desc = ROLE_DESCRIPTIONS.get(opt.lower(), "")
        table.add_row(str(i), opt.title(), desc)
    console.print(table)


def ask_index(prompt_text: str, n: int) -> int:
    """Ask for a 1..n choice, looping until valid. Returns the chosen index (1-based)."""
    while True:
        raw = console.input(f"[bold cyan]{prompt_text}[/bold cyan] (1-{n}) > ").strip()
        if raw.isdigit() and 1 <= int(raw) <= n:
            return int(raw)
        console.print(f"[bold red]Enter a number between 1 and {n}.[/bold red]")


def wait_for_enter(prompt_text: str = "Press ENTER to continue...") -> None:
    Prompt.ask(f"[bold cyan]{prompt_text}[/bold cyan]", default="")


# --------------------------------------------------------------------------- #
# Format v2 — free-text guidance & input
# --------------------------------------------------------------------------- #
GUIDANCE_LABELS = {"what": "WHAT DID YOU GET", "action": "WHAT WOULD YOU DO", "why": "WHY"}


def write_guidance_frame(guidance: dict[str, str]) -> None:
    """Print the 3-part guided-answering frame (format v2)."""
    if not guidance:
        return
    console.print()
    for key, label in GUIDANCE_LABELS.items():
        text = guidance.get(key, "")
        if text:
            console.print(f"[bold cyan]{label}[/bold cyan]")
            console.print(f"  {text}")
    console.print()


def _has_substance(raw: str) -> bool:
    """True if the free-text answer is a real response (not empty/gibberish)."""
    text = raw.strip()
    if len(text) < 8:
        return False
    unique = set(text.lower().replace(" ", ""))
    if len(unique) <= 2:
        return False
    if len(text.split()) < 2:
        return False
    return True


def prompt_free_text(
    prompt_text: str,
    hints: list[str] | None = None,
    reference_answer: str = "",
) -> dict:
    """
    Format v2 input loop: free text only, no options.

    - '?' reveals the next progressive hint (hint fading)
    - '??' reveals the reference answer (marks looked_up)
    - empty/gibberish answers are re-prompted (max 2), then accepted as-is
    - never judges the answer — feedback stays deferred

    Returns {"response", "hints_used", "looked_up"}.
    """
    hints = list(hints or [])
    revealed = 0
    looked_up = False
    retries = 0

    console.print(f"\n[bold cyan]?[/bold cyan] {prompt_text}")
    console.print("[dim]   Answer freely. '?' reveals the next hint, '??' reveals the reference answer.[/dim]")

    while True:
        raw = console.input("[bold]Your action > [/bold]").strip()

        if raw in ("?", "??"):
            if raw == "?":
                if revealed < len(hints):
                    console.print(f"[dim][HINT {revealed + 1}/{len(hints)}][/dim] {hints[revealed]}")
                    revealed += 1
                else:
                    console.print("[dim]No more hints for this phase.[/dim]")
            else:
                if reference_answer:
                    looked_up = True
                    print_panel(reference_answer, title="Reference Answer", border="yellow")
                else:
                    console.print("[dim]No reference answer for this phase.[/dim]")
            continue

        if not _has_substance(raw):
            if retries < 2:
                retries += 1
                console.print("[bold yellow]! That looks too short or empty — describe your concrete action.[/bold yellow]")
                continue
            console.print("[dim]Accepted as-is.[/dim]")

        return {"response": raw, "hints_used": revealed, "looked_up": looked_up}


def print_markdown(text: str) -> None:
    """Render markdown text (AI output)."""
    console.print(Markdown(text))


def print_panel(text: str, title: str = "", border: str = "cyan") -> None:
    console.print(Panel(text, title=title, border_style=border))


# --------------------------------------------------------------------------- #
# Session-level menus
# --------------------------------------------------------------------------- #
def print_main_menu(options: list[str]) -> None:
    """Print the top-level session menu."""
    table = Table(title="AI Evolution — Main Menu", border_style="cyan", show_lines=False)
    table.add_column("#", style="bold green", width=4)
    table.add_column("Option", style="white")
    for i, opt in enumerate(options, 1):
        table.add_row(str(i), opt)
    console.print(table)


def print_resume_prompt(user_name: str, last_run: dict[str, Any] | None) -> bool:
    """Show a one-liner resume prompt. Returns True if user wants to continue."""
    if last_run is None:
        return True
    score = last_run.get("score", "?")
    grade = last_run.get("grade", "?")
    scenario = last_run.get("scenario_id", "Unknown")
    console.print(
        f"\n[bold green]Welcome back, {user_name}![/bold green]\n"
        f"  Last session: [bold]{score}/100[/bold] ([italic]{grade}[/italic]) — {scenario}\n"
    )
    return Confirm.ask("Continue from here?", default=True)


def print_domain_picker(
    all_domains: list[str],
    current: list[str],
) -> list[str]:
    """Multi-select domain picker. User toggles domains with numbers, confirms with ENTER."""
    selected = set(current)
    while True:
        console.print(f"\n[bold cyan]Choose Training Domains[/bold cyan]")
        console.print("[dim]Enter a number to toggle, or press ENTER to confirm selection:[/dim]\n")
        for i, d in enumerate(all_domains, 1):
            mark = "[bold green]✓[/bold green]" if d in selected else "[dim]  [/dim]"
            console.print(f"  {mark} [bold green]{i}.[/bold green] {d}")
        console.print()
        raw = console.input("[bold cyan]Select > [/bold cyan]").strip()
        if not raw:
            if not selected:
                console.print("[bold red]Select at least one domain.[/bold red]")
                continue
            return sorted(selected)
        if raw.isdigit() and 1 <= int(raw) <= len(all_domains):
            d = all_domains[int(raw) - 1]
            if d in selected:
                selected.discard(d)
            else:
                selected.add(d)
        else:
            console.print(f"[bold red]Enter a number 1-{len(all_domains)} or press ENTER.[/bold red]")


def print_progress_view(perf: list[dict[str, Any]] | dict[str, Any]) -> None:
    """Show per-domain progress summary."""
    if isinstance(perf, dict):
        perf = [perf] if perf else []

    if not perf:
        console.print("\n[dim]No training data yet. Complete scenarios to see progress here.[/dim]")
        return

    table = Table(title="Your Progress", border_style="cyan", show_lines=False)
    table.add_column("Domain", style="white", overflow="fold")
    table.add_column("Avg Score", style="cyan", justify="right")
    table.add_column("Runs", style="green", justify="right")
    table.add_column("Weakest Technique", style="yellow")
    table.add_column("Last Practiced", style="dim")

    for row in perf:
        avg = row.get("avg_score", 0)
        avg_str = f"{avg:.0f}/100" if avg else "?"
        runs = row.get("total_runs", 0)
        weakest = row.get("weakest_technique", "—") or "—"
        last = row.get("last_practiced", "—") or "—"
        table.add_row(row.get("domain", "?"), avg_str, str(runs), weakest, last)

    console.print(table)


def print_recommendation(reason: str) -> None:
    """Show the adaptive next-step recommendation (P6) after a run."""
    console.print()
    console.print(
        Panel(
            f"[bold white]{reason}[/bold white]",
            title="[bold cyan]Recommended Next[/bold cyan]",
            border_style="cyan",
            expand=False,
        )
    )


def print_learner_summary(level: str, streak: int, next_reason: str = "") -> None:
    """Show learner level, practice streak and the pending recommendation (P6)."""
    console.print()
    console.print(f"[bold]Learner level:[/bold] [cyan]{level}[/cyan]   "
                  f"[bold]Practice streak:[/bold] [green]{streak}[/green] day(s)")
    if next_reason:
        console.print(f"[dim]Next up: {next_reason}[/dim]")
