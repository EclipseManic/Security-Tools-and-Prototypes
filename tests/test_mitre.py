"""MITRE canonicalization + domain-map tests."""

from __future__ import annotations

import pytest

from core.mitre import (
    base_technique,
    canonical_technique,
    display_technique,
    load_domain_map,
    parse_technique,
    same_technique,
    technique_id,
    technique_in_domain,
)
from scenarios.loader import SCENARIO_BY_ID


@pytest.mark.parametrize(
    "raw, expected_id, expected_name",
    [
        ("T1110.004 Credential Stuffing", "T1110.004", "Credential Stuffing"),
        ("T1110.004 — Credential Stuffing", "T1110.004", "Credential Stuffing"),
        ("T1040 — Network Sniffing", "T1040", "Network Sniffing"),
        ("Credential Stuffing", "", "Credential Stuffing"),
        ("", "", ""),
    ],
)
def test_parse_technique(raw: str, expected_id: str, expected_name: str) -> None:
    assert parse_technique(raw) == (expected_id, expected_name)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("T1110.004 — Credential Stuffing", "T1110.004"),
        ("T1110.004 Credential Stuffing", "T1110.004"),
        ("Credential Stuffing", "name:credential stuffing"),
        ("T1040", "T1040"),
        ("", ""),
    ],
)
def test_canonical_technique(raw: str, expected: str) -> None:
    assert canonical_technique(raw) == expected


def test_display_technique() -> None:
    assert display_technique("T1110.004", "Credential Stuffing") == (
        "T1110.004 — Credential Stuffing"
    )
    assert display_technique("T1110.004") == "T1110.004"
    assert display_technique("T1110.004 — Credential Stuffing") == (
        "T1110.004 — Credential Stuffing"
    )


def test_base_technique() -> None:
    assert base_technique("T1110.004") == "T1110"
    assert base_technique("T1110") == "T1110"


def test_same_technique_parent_matches_subtechnique() -> None:
    assert same_technique("T1110", "T1110.004")
    assert same_technique("T1110.004", "T1110")
    assert same_technique("T1110.004 — Credential Stuffing", "T1110.004")
    # Sibling sub-techniques are different techniques.
    assert not same_technique("T1110.004", "T1110.002")
    assert not same_technique("T1110", "")
    assert not same_technique("", "T1110")


def test_domain_map_loads() -> None:
    domain_map = load_domain_map()
    assert len(domain_map) == 7
    assert "Endpoint" in domain_map
    assert all(isinstance(v, list) and v for v in domain_map.values())


def test_technique_in_domain() -> None:
    assert technique_in_domain("T1110.004 — Credential Stuffing", "Identity & Access")
    assert technique_in_domain("T1190 — Exploit Public-Facing Application", "Web App")
    assert not technique_in_domain("T1190", "AI & ML")


def test_every_scenario_technique_is_mapped() -> None:
    """The shipped map must cover every technique used by the curated corpus."""
    problems: list[str] = []
    for sid, cls in SCENARIO_BY_ID.items():
        category = cls.meta.category
        for phase in cls.phases:
            raw = (phase.mitre_technique or "").strip()
            if not raw:
                continue
            if not technique_id(raw):
                problems.append(f"{sid}: '{raw}' has no MITRE id")
            elif not technique_in_domain(raw, category):
                problems.append(f"{sid}: '{raw}' not in {category}")
    assert not problems, "\n".join(problems)
