"""Scenario corpus schema + loader reload guarantees."""

from __future__ import annotations

import scenarios.loader as loader
from core.scenario_generator import _MAX_PHASES, _MIN_PHASES, _validate_scenario
from scenarios.loader import PHASE_TYPES, SCENARIO_BY_ID


def test_corpus_loads() -> None:
    assert loader.TOTAL_SCENARIOS == 133
    assert len(loader.ALL_CATEGORIES) == 7
    assert len(SCENARIO_BY_ID) == 133


def test_every_scenario_is_playable() -> None:
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        if not cls.phases:
            problems.append(f"{sid}: no phases")
            continue
        ids = [p.id for p in cls.phases if p.id]
        if len(ids) != len(set(ids)):
            problems.append(f"{sid}: duplicate phase ids")
        for phase in cls.phases:
            label = f"{sid}/{phase.id or phase.title}"
            if not phase.id:
                problems.append(f"{label}: missing id")
            if phase.phase_type and phase.phase_type not in PHASE_TYPES:
                problems.append(f"{label}: bad phase_type {phase.phase_type}")
            if not phase.reference_answer and not phase.ideal_concepts:
                problems.append(f"{label}: no scoring target")
            if phase.next and phase.next not in ids:
                problems.append(f"{label}: next -> unknown {phase.next}")
    assert not problems, "\n".join(problems)


def test_reload_keeps_shared_dict_identity() -> None:
    categories = loader.ALL_CATEGORIES
    by_id = loader.SCENARIO_BY_ID
    before = loader.TOTAL_SCENARIOS
    returned_categories, returned_by_id = loader.reload()
    assert returned_categories is categories
    assert returned_by_id is by_id
    assert loader.TOTAL_SCENARIOS == before
    assert len(loader.SCENARIO_BY_ID) == before


def _phase(index: int) -> dict:
    return {
        "id": f"phase_{index}",
        "phase_type": "triage",
        "title": f"Phase {index}",
        "situation": "situation",
        "guidance": {"what": "w", "action": "a", "why": "y"},
        "hint": "hint",
        "ideal_concepts": ["a", "b", "c", "d", "e"],
        "reference_answer": "reference",
        "followup_good": "good",
        "followup_weak": "weak",
        "next": "",
    }


def _scenario(phase_count: int) -> dict:
    return {
        "id": "synthetic",
        "name": "Synthetic",
        "category": "Endpoint",
        "format_version": 2,
        "incident": {"title": "t", "opening": "o", "summary": "s"},
        "phases": [_phase(i) for i in range(1, phase_count + 1)],
    }


def test_generator_accepts_four_to_six_phases() -> None:
    for count in range(_MIN_PHASES, _MAX_PHASES + 1):
        errors = _validate_scenario(_scenario(count), "Endpoint")
        assert not any("phases" in e for e in errors), (count, errors)


def test_generator_rejects_too_few_or_too_many_phases() -> None:
    too_few = _validate_scenario(_scenario(_MIN_PHASES - 1), "Endpoint")
    assert any("at least" in e for e in too_few), too_few
    too_many = _validate_scenario(_scenario(_MAX_PHASES + 1), "Endpoint")
    assert any("at most" in e for e in too_many), too_many


def test_generator_rejects_unknown_category() -> None:
    data = _scenario(4)
    data["category"] = "Nonexistent Domain"
    errors = _validate_scenario(data, "Nonexistent Domain")
    assert any("category" in e for e in errors), errors
