"""Adaptive engine: difficulty progression + technique matching."""

from __future__ import annotations

import pytest

from core.adaptive import difficulty_for_level, find_scenarios_for_technique


@pytest.mark.parametrize(
    "level, expected",
    [
        ("Needs Work", "Easy"),
        ("Novice", "Easy"),
        ("Intermediate", "Medium"),
        ("Proficient", "Hard"),
        ("Expert", "Hard"),
        ("", "Medium"),
        (None, "Medium"),
    ],
)
def test_difficulty_for_level(level, expected: str) -> None:
    assert difficulty_for_level(level) == expected


def test_find_scenario_by_canonical_technique() -> None:
    cls = find_scenarios_for_technique("T1040", domains=["Network"])
    assert cls is not None
    assert any(p.mitre_technique.startswith("T1040") for p in cls.phases)
