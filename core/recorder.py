"""
core/recorder.py
Action recorder for the blue-team incident-response trainer.

Captures every user action (option pick OR free-text) along with the full
situation context, all options, the ideal answer (hidden from user), and the
phase narrative. The entire log is sent to the AI in ONE request at the end.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ActionRecord:
    # Phase context
    phase_number: int
    phase_title: str
    situation: str                       # full scenario narrative shown to user
    mitre_tactic: str
    mitre_technique: str
    prompt: str                          # the question that was asked
    # What the user did
    choice_type: str                     # "option" | "custom"
    user_response: str                   # the actual text the user picked/typed
    # Reference info (NOT shown during the run — used by AI only)
    options_presented: list[str]
    ideal_answer: str                    # reference / ideal action
    reference_explanation: str           # why ideal is ideal
    # Timing
    timestamp: str
    elapsed_sec: float
    # Offline scorer output (format v2; -1 = unscored legacy phase)
    response_score: float = -1.0         # 0-10 offline concept hit-rate
    parts_json: str = ""                 # per-part (what/action/why) scores
    hints_used: int = 0                  # '?' reveals used
    looked_up: bool = False              # '??' reference answer revealed

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionLog:
    started_at: str
    user_name: str = "Anonymous"
    incident_title: str = ""
    incident_category: str = ""
    incident_summary: str = ""           # full story of the attack (blue-team framing)
    compromised_assets: list[str] = field(default_factory=list)
    detected_via: str = ""               # how the SOC first detected the incident
    actions: list[ActionRecord] = field(default_factory=list)
    user_role: str = ""                  # SOC role the player chose (analyst, ciso, etc.)
    industry_filter: str = "all"         # industry context filter (finance, healthcare, etc.)
    executive_brief: str = ""            # CISO-level executive summary for reports
    run_id: int = 0                      # SQLite run_id (populated after save by SessionDB)

    def add(self, record: ActionRecord) -> None:
        self.actions.append(record)

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "user_name": self.user_name,
            "incident_title": self.incident_title,
            "incident_category": self.incident_category,
            "incident_summary": self.incident_summary,
            "compromised_assets": self.compromised_assets,
            "detected_via": self.detected_via,
            "user_role": self.user_role,
            "industry_filter": self.industry_filter,
            "executive_brief": self.executive_brief,
            "run_id": self.run_id,
            "actions": [a.to_dict() for a in self.actions],
        }


class Recorder:
    """Records the IR analyst's actions during a scenario run."""

    def __init__(self) -> None:
        self._start = time.time()
        import datetime as _dt
        self.session = SessionLog(
            started_at=_dt.datetime.now().isoformat(timespec="seconds"),
        )

    def set_context(
        self,
        *,
        user_name: str,
        incident_title: str,
        incident_category: str,
        incident_summary: str,
        compromised_assets: Optional[list[str]] = None,
        detected_via: str = "",
        user_role: str = "analyst",
        industry_filter: str = "all",
        executive_brief: str = "",
    ) -> None:
        s = self.session
        s.user_name = user_name
        s.incident_title = incident_title
        s.incident_category = incident_category
        s.incident_summary = incident_summary
        s.compromised_assets = compromised_assets or []
        s.detected_via = detected_via
        s.user_role = user_role
        s.industry_filter = industry_filter
        s.executive_brief = executive_brief

    def record(
        self,
        *,
        phase_number: int,
        phase_title: str,
        situation: str,
        mitre_tactic: str,
        mitre_technique: str,
        prompt: str,
        choice_type: str,
        user_response: str,
        options_presented: list[str],
        ideal_answer: str,
        reference_explanation: str,
        response_score: float = -1.0,
        parts_json: str = "",
        hints_used: int = 0,
        looked_up: bool = False,
    ) -> None:
        import datetime as _dt
        self.session.add(ActionRecord(
            phase_number=phase_number,
            phase_title=phase_title,
            situation=situation,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            prompt=prompt,
            choice_type=choice_type,
            user_response=user_response,
            options_presented=options_presented,
            ideal_answer=ideal_answer,
            reference_explanation=reference_explanation,
            response_score=response_score,
            parts_json=parts_json,
            hints_used=hints_used,
            looked_up=looked_up,
            timestamp=_dt.datetime.now().strftime("%H:%M:%S"),
            elapsed_sec=round(time.time() - self._start, 1),
        ))

    def elapsed(self) -> float:
        return round(time.time() - self._start, 1)
