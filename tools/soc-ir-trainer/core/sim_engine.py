"""
core/sim_engine.py
Format-v2 simulation engine: drives a scenario phase by phase.

Per-phase loop:
    clear → write_phase(title, situation)       ← one small alert
         → write_guidance_frame(guidance)       ← 3-part, phase-specific focus
         → write_hint(hint)
         → ui.prompt_free_text()                ← free text, '?'/ '??' reveals,
                                                  gibberish re-prompt (max 2)
         → score via response_scorer            ← offline, instant, no API key
         → reveal followup_good | followup_weak ← branch on score (>=6 good)
         → record(phase, score, parts, hints, looked_up)
         → next | next_weak

Never judges the user's answer during the run — feedback stays deferred to
the end-of-run AI evaluation.
"""

from __future__ import annotations

import json
from typing import Optional

from core import ui
from core.recorder import Recorder
from core import response_scorer
from scenarios.base import Phase, Scenario

GOOD_THRESHOLD = response_scorer.GOOD_THRESHOLD


def _brief_text(scenario: Scenario) -> str:
    if scenario.meta.format_version >= 2 and scenario.meta.opening:
        return (
            f"[bold]{scenario.meta.incident_title}[/bold]\n\n"
            f"{scenario.meta.opening}"
        )
    return (
        f"[bold]{scenario.meta.incident_title}[/bold]\n\n"
        f"{scenario.meta.incident_summary}"
    )


def _write_briefing(scenario: Scenario, ui_mod, recorder: Recorder) -> None:
    m = scenario.meta
    ui_mod.clear_screen()
    ui_mod.write_phase(
        f"INCIDENT BRIEFING — {m.incident_title}",
        situation=_brief_text(scenario),
        phase_num=0,
    )
    ui_mod.write_info(f"Difficulty: [bold]{m.difficulty}[/bold]")
    if m.kill_chain:
        ui_mod.write_info(f"Kill chain observed: {' -> '.join(m.kill_chain)}")
    if m.mitre_tactics:
        ui_mod.write_info(f"MITRE tactics: {', '.join(m.mitre_tactics)}")
    ui_mod.write_info(f"Detected via: {m.detected_via or 'unknown'}")
    ui_mod.write_info(
        f"Known compromised assets: "
        f"{', '.join(m.compromised_assets) or 'under investigation'}"
    )
    ui_mod.write_info(
        f"SOC Tier: [bold]{m.soc_tier}[/bold] | "
        f"Roles available: {', '.join(m.roles) or 'analyst'}"
    )
    role_title = scenario.user_role.replace("_", " ").title()
    ui_mod.write_info(f"Current role: [bold]{role_title}[/bold]")

    rb = scenario._role_briefing()
    if rb:
        ui_mod.console.print()
        ui_mod.print_panel(rb, title=f"[bold]Role Briefing — {role_title}[/bold]", border="yellow")

    ui_mod.console.print()
    ui_mod.write_info(f"You are the [bold]{role_title}[/bold] on call. Take action at each phase.")
    ui_mod.write_warn("No feedback will be given during the run — the AI evaluates at the end.")
    ui_mod.wait_for_enter("Press ENTER to receive the first alert...")


def _run_freeform_phase(
    scenario: Scenario,
    phase: Phase,
    phase_num: int,
    recorder: Recorder,
    ui_mod,
) -> dict:
    """One format-v2 phase: guidance, free text, score, followup, record."""
    effective_prompt = scenario._phase_prompt(phase)

    if phase.guidance:
        ui_mod.write_guidance_frame(phase.guidance)
    if phase.hint:
        ui_mod.write_info(f"Hint: [italic]{phase.hint}[/italic]")

    result = ui_mod.prompt_free_text(
        effective_prompt,
        hints=phase.hints,
        reference_answer=phase.reference_answer,
    )

    scored = response_scorer.score_response(
        result["response"],
        phase.ideal_concepts,
        reference_answer=phase.reference_answer,
    )

    # Reveal the phase outcome — the narrative continues either way.
    followup = (
        phase.followup_good if scored["good"] else phase.followup_weak
    ) or ""
    if followup:
        ui_mod.console.print()
        ui_mod.print_panel(followup, title="[bold]Where things stand[/bold]", border="cyan")

    ideal_action, ideal_why = response_scorer.split_reference_answer(phase.reference_answer)
    recorder.record(
        phase_number=phase_num,
        phase_title=phase.title,
        situation=phase.situation,
        mitre_tactic=phase.mitre_tactic,
        mitre_technique=phase.mitre_technique,
        prompt=effective_prompt,
        choice_type="freeform",
        user_response=result["response"],
        options_presented=[],
        ideal_answer=ideal_action or phase.reference_answer or "(no reference answer defined)",
        reference_explanation=ideal_why,
        response_score=scored["score"],
        parts_json=json.dumps({
            "parts": scored["parts"],
            "coverage": scored.get("coverage", 0.0),
            "phrase_coverage": scored.get("phrase_coverage", 0.0),
            "matched_terms": scored.get("matched_terms", []),
            "missing_terms": scored.get("missing_terms", []),
        }),
        hints_used=result["hints_used"],
        looked_up=result["looked_up"],
    )

    ui_mod.console.print()
    shown = result["response"]
    ui_mod.write_info(
        f"Action recorded: [bold]{shown[:80]}{'...' if len(shown) > 80 else ''}[/bold]"
    )
    if result["looked_up"]:
        ui_mod.write_info("[dim]Reference answer was revealed during this phase.[/dim]")
    ui_mod.wait_for_enter("Press ENTER to continue...")

    return scored


def _resolve_next(scenario: Scenario, phase: Phase, index: int, scored: dict) -> Optional[Phase]:
    """Resolve the next phase: good/weak id navigation, fallback to sequential."""
    next_id = phase.next if scored["good"] else (phase.next_weak or phase.next)
    if next_id:
        nxt = scenario.phase_by_id(next_id)
        if nxt is not None:
            return nxt
    nxt = index + 1
    return scenario.phases[nxt] if nxt < len(scenario.phases) else None


def run_scenario(
    scenario: Scenario,
    recorder: Recorder,
    *,
    ui_module=None,
) -> dict:
    """Run a scenario through the free-text engine. Returns a phase summary."""
    ui_mod = ui_module or ui
    _write_briefing(scenario, ui_mod, recorder)

    summary: list[dict] = []
    visited: set[str] = set()
    phase: Optional[Phase] = scenario.phases[0] if scenario.phases else None
    index = 0

    while phase is not None:
        key = phase.id or f"#{index}"
        if key in visited:
            # navigation loop guard — stop instead of looping forever
            break
        visited.add(key)

        ui_mod.clear_screen()
        ui_mod.write_phase(phase.title, situation=phase.situation, phase_num=index + 1)
        if phase.mitre_tactic or phase.mitre_technique:
            ui_mod.write_mitre(phase.mitre_tactic, phase.mitre_technique)

        scored = _run_freeform_phase(scenario, phase, index + 1, recorder, ui_mod)
        last_action = recorder.session.actions[-1] if recorder.session.actions else None
        summary.append({
            "phase_number": index + 1,
            "phase_title": phase.title,
            "score": scored["score"],
            "hints_used": last_action.hints_used if last_action else 0,
            "looked_up": last_action.looked_up if last_action else False,
            "branch": "good" if scored["good"] else "weak",
        })

        phase = _resolve_next(scenario, phase, index, scored)
        index += 1

    scored_phases = [s for s in summary if s["score"] is not None]
    return {
        "phases": summary,
        "total_phases": len(summary),
        "scored_phases": len(scored_phases),
        "avg_score": (
            round(sum(s["score"] for s in scored_phases) / len(scored_phases), 1)
            if scored_phases
            else 0.0
        ),
        "strong": sum(1 for s in scored_phases if s["score"] >= GOOD_THRESHOLD),
    }
