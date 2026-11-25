"""Format converter: v2 ids/navigation must survive a round-trip."""

from __future__ import annotations

from tools.convert_to_freeform import _slugify_id, transform


def _v2_phase(pid: str, title: str, next_id: str = "") -> dict:
    return {
        "id": pid,
        "phase_type": "triage",
        "title": title,
        "situation": "situation",
        "prompt": "What next?",
        "guidance": {"what": "w", "action": "a", "why": "y"},
        "hint": "hint",
        "hints": ["hint"],
        "ideal_concepts": ["a", "b", "c", "d", "e"],
        "reference_answer": "reference",
        "followup_good": "good",
        "followup_weak": "weak",
        "next": next_id,
    }


def test_v2_phase_ids_are_preserved() -> None:
    data = {
        "id": "fixture",
        "name": "Fixture",
        "category": "Network",
        "format_version": 2,
        "incident": {"title": "T", "summary": "S"},
        "phases": [
            _v2_phase("recovery_and_validation", "Recovery & Validation", "post_incident_review"),
            _v2_phase("post_incident_review", "Post-Incident Review & Hardening"),
        ],
    }
    out = transform(data)
    assert [p["id"] for p in out["phases"]] == [
        "recovery_and_validation",
        "post_incident_review",
    ]
    assert out["phases"][0]["next"] == "post_incident_review"
    assert out["phases"][0]["phase_type"] == "triage"


def test_v1_phases_fall_back_to_title_slug() -> None:
    data = {
        "id": "fixture",
        "name": "Fixture",
        "category": "Network",
        "format_version": 1,
        "difficulty": "Easy",
        "incident": {"title": "T", "summary": "First. Second."},
        "phases": [
            {
                "title": "Phase 1 — VPN Authentication Alert",
                "situation": "S",
                "prompt": "What next?",
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1040",
                "choices": [
                    {
                        "text": "Pull the authentication logs",
                        "is_ideal": True,
                        "explanation": "Logs show the source.",
                    },
                    {
                        "text": "Reboot the gateway",
                        "is_ideal": False,
                        "explanation": "Rebooting destroys evidence.",
                    },
                ],
            },
        ],
    }
    out = transform(data)
    assert out["phases"][0]["id"] == _slugify_id("Phase 1 — VPN Authentication Alert")
