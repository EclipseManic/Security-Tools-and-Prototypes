"""Content-quality invariants for the curated corpus.

These guard the deterministic upgrade in tools/upgrade_content.py: every
scenario must be a complete-enough drill (4-6 phases, one recovery, one
lessons), advertise all four SOC roles with briefings, and carry complete
executive briefs/guidance instead of truncated placeholders.
"""

from __future__ import annotations

from scenarios.loader import SCENARIO_BY_ID

ROLES = {"analyst", "incident_manager", "ciso", "executive"}


def test_phase_count_is_four_to_six() -> None:
    problems = [
        f"{sid}: {len(cls.phases)} phases"
        for sid, cls in SCENARIO_BY_ID.items()
        if not 4 <= len(cls.phases) <= 6
    ]
    assert not problems, "\n".join(problems)


def test_every_scenario_has_recovery_and_lessons() -> None:
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        types = [p.phase_type for p in cls.phases]
        if types.count("recovery") != 1:
            problems.append(f"{sid}: recovery={types.count('recovery')}")
        if types.count("lessons") != 1:
            problems.append(f"{sid}: lessons={types.count('lessons')}")
        if types[0] != "triage":
            problems.append(f"{sid}: starts with {types[0]}")
    assert not problems, "\n".join(problems)


def test_recovery_precedes_lessons() -> None:
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        types = [p.phase_type for p in cls.phases]
        if types.index("recovery") > types.index("lessons"):
            problems.append(f"{sid}: recovery after lessons")
    assert not problems, "\n".join(problems)


def test_all_roles_and_briefings_present() -> None:
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        roles = set(cls.meta.roles or [])
        if roles != ROLES:
            problems.append(f"{sid}: roles {sorted(roles)}")
        if set(cls.meta.role_briefings or {}) != ROLES:
            problems.append(f"{sid}: briefings {sorted(cls.meta.role_briefings or {})}")
        if any(not (cls.meta.role_briefings or {}).get(r, "").strip() for r in ROLES):
            problems.append(f"{sid}: empty briefing")
    assert not problems, "\n".join(problems)


def test_executive_briefs_are_complete() -> None:
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        brief = (cls.meta.executive_brief or "").strip()
        if len(brief) < 600:
            problems.append(f"{sid}: brief too short ({len(brief)})")
        if brief.endswith(("...", "\u2026")):
            problems.append(f"{sid}: brief still truncated")
    assert not problems, "\n".join(problems)


def test_guidance_and_hints_are_populated() -> None:
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        for phase in cls.phases:
            label = f"{sid}/{phase.id or phase.title}"
            if not phase.hint.strip():
                problems.append(f"{label}: empty hint")
            for key in ("what", "action", "why"):
                if not str(phase.guidance.get(key, "")).strip():
                    problems.append(f"{label}: empty guidance.{key}")
            if not phase.prompt.strip():
                problems.append(f"{label}: empty prompt")
            if not phase.reference_answer.strip():
                problems.append(f"{label}: empty reference answer")
    assert not problems, "\n".join(problems)
