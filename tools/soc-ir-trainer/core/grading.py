"""
core/grading.py
Single source of truth for grade bands (fixes the 3-scale drift).

One constant module used by the AI evaluator, the DB recompute, and the
reporter. Bands: 90-100 Expert, 70-89 Proficient, 50-69 Intermediate,
30-49 Novice, 0-29 Needs Work.
"""

from __future__ import annotations

GRADE_BANDS: list[tuple[int, str]] = [
    (90, "Expert"),
    (70, "Proficient"),
    (50, "Intermediate"),
    (30, "Novice"),
    (0, "Needs Work"),
]

BANDS_TEXT = ", ".join(
    f"{lo}-{hi} {label}"
    for (lo, label), (hi, _) in zip(GRADE_BANDS, GRADE_BANDS[1:] + [(100, "")])
)


def grade_for(score: int | float) -> str:
    """Map a 0-100 score to its grade band label."""
    for thresh, grade in GRADE_BANDS:
        if score >= thresh:
            return grade
    return "Needs Work"
