"""AI fallback (offline debrief) math and output shape."""

from __future__ import annotations

import json

from core.ai_evaluator import _fallback
from core.grading import grade_for
from core.recorder import Recorder


def _recorder(scores: list[float], *, hints: list[int] | None = None,
              reveals: list[bool] | None = None) -> Recorder:
    rec = Recorder()
    rec.set_context(
        user_name="Tester",
        incident_title="Test Incident",
        incident_category="Network",
        incident_summary="x",
    )
    hints = hints or [0] * len(scores)
    reveals = reveals or [False] * len(scores)
    for index, score in enumerate(scores, start=1):
        rec.record(
            phase_number=index,
            phase_title=f"Phase {index}",
            situation="x",
            mitre_tactic="TA0001",
            mitre_technique="T1040 — Network Sniffing",
            prompt="What do you do?",
            choice_type="freeform",
            user_response="some answer",
            options_presented=[],
            ideal_answer="ideal",
            reference_explanation="because",
            response_score=score,
            parts_json=json.dumps({
                "parts": {"what": score, "action": score, "why": score},
                "missing_terms": ["firewall", "contain"],
            }),
            hints_used=hints[index - 1],
            looked_up=reveals[index - 1],
        )
    return rec


def _fallback_for(scores: list[float], **kwargs):
    return _fallback(_recorder(scores, **kwargs).session, "no key")


def test_offline_average_drives_score() -> None:
    ev = _fallback_for([8.0, 4.0])
    assert ev["fallback"] is True
    assert ev["offline_avg"] == 6.0
    assert ev["assist_penalty"] == 0
    assert ev["score"] == 60
    assert ev["grade"] == grade_for(60)
    assert len(ev["phase_evaluations"]) == 2
    assert ev["phase_evaluations"][0]["offline_score"] == 8


def test_assist_penalty_is_capped() -> None:
    # 2 hints (6) + 1 reveal (10) = 16, capped at 15.
    ev = _fallback_for([8.0, 4.0], hints=[1, 1], reveals=[True, False])
    assert ev["assist_penalty"] == 15
    assert ev["score"] == 45
    assert ev["grade"] == "Novice"
    assert any("Assist penalty" in w for w in ev["weaknesses"])


def test_perfect_run_scores_100() -> None:
    ev = _fallback_for([10.0, 10.0])
    assert ev["score"] == 100
    assert ev["grade"] == "Expert"
    assert len(ev["strengths"]) == 2


def test_legacy_unscored_phases_are_reported() -> None:
    ev = _fallback_for([-1.0, -1.0])
    assert ev["offline_avg"] == 0.0
    assert ev["score"] == 0
    assert any("legacy data" in w for w in ev["weaknesses"])


def test_weak_phase_evaluation_mentions_missing_terms() -> None:
    ev = _fallback_for([3.0])
    phase = ev["phase_evaluations"][0]
    assert phase["correctness"] == 3
    assert "Missing:" in phase["analysis"]
    assert "firewall" in phase["what_did_wrong"]


def test_output_shape_matches_report_contract() -> None:
    ev = _fallback_for([6.0])
    for key in (
        "score", "grade", "overall_assessment", "final_verdict",
        "phase_evaluations", "strengths", "weaknesses",
        "tightening_recommendations", "missed_opportunities",
        "next_training", "next_training_scenarios", "communication_grade",
    ):
        assert key in ev
