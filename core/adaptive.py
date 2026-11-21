"""
core/adaptive.py
Pedagogical engine (P6). After each run:

1. Pull the learner's mastery rows and rank weak techniques:
   - only techniques below Proficient (spec: level < Proficient)
   - spaced re-practice: techniques unpracticed > 7 days get priority
   - otherwise weakest first: (level rank asc, avg_score asc, recency asc)
2. Map a technique to a scenario the user can play:
   - existing scenario within the user's domains that exercises the technique
   - difficulty progression: Needs Work/Novice -> Easy, Intermediate -> Medium,
     Proficient -> Hard (fall back to any difficulty when nothing matches)
3. If no scenario covers the technique -> recommend generation instead.
4. Build a transparent reason string for the user (and `runs.next_scenario_reason`).
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Optional

from scenarios import ALL_CATEGORIES
from core.mitre import same_technique

_LEVEL_RANK = {
    "Needs Work": 0,
    "Novice": 1,
    "Intermediate": 2,
    "Proficient": 3,
    "Expert": 4,
}

# Difficulty progression: technique mastery level -> recommended scenario difficulty
_DIFFICULTY_FOR_LEVEL = {
    "Needs Work": "Easy",
    "Novice": "Easy",
    "Intermediate": "Medium",
    "Proficient": "Hard",
    "Expert": "Hard",
}

_DAYS_STALE = 7  # spaced re-practice threshold


def difficulty_for_level(level: Optional[str]) -> str:
    """Map a learner/technique level to the scenario difficulty to practice with."""
    return _DIFFICULTY_FOR_LEVEL.get(level or "", "Medium")


def _techniques_match(a: str, b: str) -> bool:
    """True when two technique strings refer to the same MITRE technique.

    Delegates to core.mitre so the adaptive engine and the mastery store use
    exactly the same parent/sub-technique rules.
    """
    return same_technique(a, b)


def _scenario_has_technique(scenario_cls: Any, technique: str) -> bool:
    return any(_techniques_match(p.mitre_technique, technique) for p in scenario_cls.phases)


def find_scenarios_for_technique(
    technique: str,
    domains: Optional[list[str]] = None,
    preferred_difficulty: Optional[str] = None,
) -> Optional[type]:
    """Find an existing scenario exercising `technique`, restricted to `domains`
    (None = any). Prefers `preferred_difficulty` (difficulty progression), else
    the first match."""
    candidates: list[type] = []
    for cat_name, scns in ALL_CATEGORIES.items():
        if domains and cat_name not in domains:
            continue
        for cls in scns:
            if _scenario_has_technique(cls, technique):
                candidates.append(cls)
    if not candidates:
        return None
    if preferred_difficulty:
        for c in candidates:
            if c.meta.difficulty == preferred_difficulty:
                return c
    return candidates[0]


def domain_for_technique(technique: str, domains: list[str]) -> Optional[str]:
    """Which of the user's domains contains a scenario exercising `technique`?"""
    for cat_name in domains:
        for cls in ALL_CATEGORIES.get(cat_name, []):
            if _scenario_has_technique(cls, technique):
                return cat_name
    return None


def _ranked_weak_techniques(db, user_name: str, domains: list[str]) -> list[dict[str, Any]]:
    """Merge per-domain weak technique lists (already ordered by mastery) and
    re-sort with spaced-re-practice priority: stale (>7 days) first, then
    level rank asc, avg_score asc, last_practiced asc."""
    by_tech = {m["technique"]: m for m in db.get_mastery(user_name)}
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dom in domains or []:
        for tech in db.get_weak_techniques(user_name, dom):
            row = by_tech.get(tech)
            if row is None or tech in seen:
                continue
            seen.add(tech)
            merged.append(row)

    cutoff = date.today() - timedelta(days=_DAYS_STALE)

    def key(row: dict[str, Any]) -> tuple:
        try:
            last = date.fromisoformat(row["last_practiced"][:10])
        except (ValueError, TypeError):
            last = date.today()
        stale = 0 if last < cutoff else 1
        return (
            stale,
            _LEVEL_RANK.get(row.get("level", ""), 99),
            row.get("avg_score", 0),
            row.get("last_practiced", ""),
        )

    return sorted(merged, key=key)


def recommend_next(db, user_name: str, domains: list[str]) -> dict[str, Any]:
    """Compute the next training recommendation.

    Returns dict:
      mode: 'play' | 'generate' | 'none'
      technique: targeted weak technique (or None)
      scenario_cls: existing scenario to play (play mode only)
      reason: human-readable transparency string
    """
    weak = _ranked_weak_techniques(db, user_name, domains or [])
    if not weak:
        return {
            "mode": "none",
            "technique": None,
            "scenario_cls": None,
            "reason": "No weak techniques yet — run a scenario to start building your profile.",
        }

    target = weak[0]
    technique: str = target["technique"]
    level: str = target.get("level", "Novice")
    avg: float = target.get("avg_score", 0)
    last_practiced = target.get("last_practiced", "")

    try:
        last = date.fromisoformat(last_practiced[:10])
        days_ago = (date.today() - last).days
    except (ValueError, TypeError):
        days_ago = 0

    if days_ago > _DAYS_STALE:
        why = (
            f"you average {avg:.0f}/100 on {technique} ({level}) and "
            f"haven't practiced it in {days_ago} days"
        )
    else:
        why = f"you average {avg:.0f}/100 on {technique} ({level})"

    desired = difficulty_for_level(level)
    cls = find_scenarios_for_technique(technique, domains, preferred_difficulty=desired)

    if cls is not None:
        diff_note = f" Difficulty set to [{cls.meta.difficulty}] for your {level} level."
        return {
            "mode": "play",
            "technique": technique,
            "scenario_cls": cls,
            "reason": (
                f"Next: '{cls.meta.incident_title}' — because {why}. "
                f"It's your weakest technique in this domain.{diff_note}"
            ),
        }

    return {
        "mode": "generate",
        "technique": technique,
        "scenario_cls": None,
        "reason": (
            f"No existing scenario targets {technique} — generate a custom one. "
            f"Reason: {why}."
        ),
    }


__all__ = [
    "recommend_next",
    "difficulty_for_level",
    "find_scenarios_for_technique",
    "domain_for_technique",
]
