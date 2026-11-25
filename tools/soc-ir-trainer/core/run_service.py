"""
core/run_service.py
Headless run state machine shared by the CLI and the web API.

The service owns everything that used to live inside `sim_engine`'s loop:
phase navigation, offline scoring, hint/reveal assists, live-run persistence,
and the final evaluation hand-off. It never writes to a terminal, so FastAPI
can call it from a background task while the CLI wraps it with Rich.

Public state is deliberately sanitized: `reference_answer`, `ideal_concepts`,
`next`, `next_weak`, `followup_good`, and `followup_weak` are never returned by
`start()`/`state()` before the learner submits an answer. Hints and the
reference answer are returned only by the explicit `reveal_hint()` /
`reveal_reference()` calls.
"""

from __future__ import annotations

import json
from dataclasses import fields as dataclass_fields
from datetime import datetime
from typing import Any, Optional

from core import response_scorer
from core.adaptive import recommend_next
from core.ai_evaluator import evaluate
from core.recorder import ActionRecord, SessionLog
from core.session_db import SessionDB
from scenarios.base import Phase, Scenario
from scenarios.loader import SCENARIO_BY_ID

GOOD_THRESHOLD = response_scorer.GOOD_THRESHOLD
MAX_ANSWER_CHARS = 8_000


# --------------------------------------------------------------------------- #
# Errors — the API maps `code` to HTTP status
# --------------------------------------------------------------------------- #
class RunServiceError(Exception):
    """Base class for expected state-transition failures."""

    code = "run_error"
    status_code = 409

    def __init__(self, message: str, *, detail: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class PersistenceUnavailable(RunServiceError):
    code = "persistence_unavailable"
    status_code = 503


class ScenarioNotFound(RunServiceError):
    code = "scenario_not_found"
    status_code = 404


class RunNotFound(RunServiceError):
    code = "run_not_found"
    status_code = 404


class RunStateError(RunServiceError):
    code = "invalid_state"
    status_code = 409


class InvalidAnswer(RunServiceError):
    code = "invalid_answer"
    status_code = 422


# --------------------------------------------------------------------------- #
# Public scenario helpers
# --------------------------------------------------------------------------- #
def resolve_role(scenario_cls: type[Scenario], wanted: str) -> tuple[str, bool]:
    """Return (effective_role, fell_back) for a scenario."""
    supported = list(scenario_cls.meta.roles or ["analyst"])
    if wanted in supported:
        return wanted, False
    fallback = "analyst" if "analyst" in supported else supported[0]
    return fallback, True


def scenario_summary(
    scenario_cls: type[Scenario], role: Optional[str] = None
) -> dict[str, Any]:
    """Sanitized listing/detail payload (no phase internals)."""
    meta = scenario_cls.meta
    effective_role, fell_back = resolve_role(scenario_cls, role or "analyst")
    return {
        "id": getattr(scenario_cls, "_scenario_id", "") or meta.name,
        "name": meta.name,
        "title": meta.incident_title,
        "category": meta.category,
        "difficulty": meta.difficulty,
        "format_version": meta.format_version,
        "opening": meta.opening or meta.incident_summary,
        "detected_via": meta.detected_via,
        "compromised_assets": list(meta.compromised_assets or []),
        "kill_chain": list(meta.kill_chain or []),
        "mitre_tactics": list(meta.mitre_tactics or []),
        "soc_tier": meta.soc_tier,
        "roles": list(meta.roles or ["analyst"]),
        "industries": list(meta.industries or ["all"]),
        "phase_count": len(scenario_cls.phases),
        "executive_brief": meta.executive_brief,
        "role": effective_role,
        "role_fallback": fell_back,
    }


def phase_count(scenario_cls: type[Scenario]) -> int:
    return len(scenario_cls.phases)


def _get_scenario(scenario_id: str) -> type[Scenario]:
    cls = SCENARIO_BY_ID.get(scenario_id)
    if cls is None:
        raise ScenarioNotFound(f"Unknown scenario '{scenario_id}'")
    return cls


def _now() -> datetime:
    return datetime.now()


def _elapsed_seconds(started_at: str) -> float:
    try:
        start = datetime.fromisoformat(started_at)
    except (TypeError, ValueError):
        return 0.0
    return round((_now() - start).total_seconds(), 1)


def _session_log_from_actions(
    run: dict[str, Any], scenario_cls: type[Scenario], actions: list[dict[str, Any]]
) -> SessionLog:
    """Rebuild the evaluator input from persisted live-run actions."""
    meta = scenario_cls.meta
    log = SessionLog(
        started_at=run.get("started_at") or _now().isoformat(timespec="seconds"),
        user_name=run["user_name"],
        incident_title=meta.incident_title,
        incident_category=meta.category,
        incident_summary=meta.incident_summary,
        compromised_assets=list(meta.compromised_assets or []),
        detected_via=meta.detected_via,
        user_role=run.get("role_used") or "analyst",
        executive_brief=meta.executive_brief,
    )
    allowed = {f.name for f in dataclass_fields(ActionRecord)}
    for row in actions:
        payload = row.get("action")
        if not isinstance(payload, dict):
            continue
        clean = {k: v for k, v in payload.items() if k in allowed}
        try:
            log.actions.append(ActionRecord(**clean))
        except TypeError:
            continue
    log.run_id = int(run.get("run_id") or 0)
    return log


# --------------------------------------------------------------------------- #
# RunService
# --------------------------------------------------------------------------- #
class RunService:
    """One process-wide service; pass a fresh `SessionDB` per request."""

    def __init__(self, db: SessionDB) -> None:
        self.db = db

    # ------------------------------------------------------------------ #
    # Start / resume
    # ------------------------------------------------------------------ #
    def start(
        self,
        user_name: str,
        scenario_id: str,
        role: str = "analyst",
        *,
        industry: str = "all",
    ) -> dict[str, Any]:
        """Abandon stale live runs, create a new run, return public state."""
        if not self.db.available:
            raise PersistenceUnavailable("Session database is unavailable")
        scenario_cls = _get_scenario(scenario_id)
        effective_role, fell_back = resolve_role(scenario_cls, role)
        scenario = scenario_cls()
        scenario.set_user_role(effective_role)

        first = scenario.phases[0] if scenario.phases else None
        if first is None:
            raise ScenarioNotFound(f"Scenario '{scenario_id}' has no phases")

        self.db.abandon_live_runs(user_name)
        run_id = self.db.start_run(
            user_name,
            scenario_id,
            effective_role,
            domain=scenario.meta.category,
            format_version=scenario.meta.format_version,
            difficulty=scenario.meta.difficulty,
            yaml_source=getattr(scenario_cls, "_yaml_source", ""),
        )
        if not run_id:
            raise PersistenceUnavailable("Could not create a run row")

        self.db.update_run_state(
            run_id,
            current_phase_id=first.id,
            visited=[],
            draft_answer="",
            assist={"hints": {}, "revealed": []},
        )
        state = self.state(run_id, user_name)
        state["role_fallback"] = fell_back
        state["industry"] = industry
        return state

    def state(self, run_id: int, user_name: Optional[str] = None) -> dict[str, Any]:
        """Resume state for a run. Safe to call after completion."""
        run = self._require_run(run_id, user_name)
        scenario_cls = _get_scenario(run["scenario_id"])
        scenario = scenario_cls()
        scenario.set_user_role(run.get("role_used") or "analyst")

        status = run.get("status") or "in_progress"
        answered = self.db.get_run_actions(run_id)
        current_id = run.get("current_phase_id") or ""
        phase = scenario.phase_by_id(current_id) if current_id else None

        # Legacy live rows (created before current_phase_id existed): derive the
        # cursor from the last answer's recorded navigation target.
        if phase is None and status == "in_progress" and not current_id:
            if answered:
                payload = answered[-1].get("action") or {}
                next_id = str(payload.get("next_phase_id") or "")
                phase = scenario.phase_by_id(next_id) if next_id else None
            elif scenario.phases:
                phase = scenario.phases[0]

        return {
            "run_id": run_id,
            "status": status,
            "scenario": self._scenario_brief(scenario, run),
            "phase": self._public_phase(scenario, phase, run, answered) if phase else None,
            "progress": self._progress(run, answered, current_id),
            "can_finish": status == "in_progress" and phase is None and bool(answered),
            "evaluation_available": status == "completed",
            "started_at": run.get("started_at"),
            "updated_at": run.get("updated_at"),
        }

    def latest_live(self, user_name: str) -> Optional[dict[str, Any]]:
        """The resumable run for a user, if one exists."""
        live = self.db.get_live_run(user_name)
        if not live:
            return None
        return self.state(int(live["run_id"]), user_name)

    # ------------------------------------------------------------------ #
    # Answer / assists
    # ------------------------------------------------------------------ #
    def answer(
        self,
        run_id: int,
        text: str,
        *,
        user_name: Optional[str] = None,
        phase_id: Optional[str] = None,
    ) -> dict[str, Any]:
        run = self._require_live_run(run_id, user_name)
        scenario_cls = _get_scenario(run["scenario_id"])
        scenario = scenario_cls()
        scenario.set_user_role(run.get("role_used") or "analyst")

        current_id = run.get("current_phase_id") or ""
        phase = scenario.phase_by_id(current_id) if current_id else None
        if phase is None:
            raise RunStateError(
                "This run has no open phase — finish it to get the debrief."
            )
        if phase_id and phase_id != phase.id:
            raise RunStateError(
                "Answer was submitted for a stale phase.",
                detail={"expected": phase.id, "received": phase_id},
            )

        answer = (text or "").strip()
        if len(answer) > MAX_ANSWER_CHARS:
            raise InvalidAnswer(
                f"Answers are limited to {MAX_ANSWER_CHARS} characters",
                detail={"length": len(answer), "max": MAX_ANSWER_CHARS},
            )
        if not response_scorer.has_substance(answer):
            raise InvalidAnswer(
                "Describe a concrete action in at least a few words.",
                detail={"reason": "insufficient_substance"},
            )

        scored = response_scorer.score_response(
            answer,
            phase.ideal_concepts,
            reference_answer=phase.reference_answer,
        )
        good = bool(scored["good"])
        followup = phase.followup_good if good else phase.followup_weak

        assist = run.get("assist") or {}
        hints_for_phase = int((assist.get("hints") or {}).get(phase.id, 0) or 0)
        revealed = phase.id in (assist.get("revealed") or [])
        previous_actions = self.db.get_run_actions(run_id)
        next_phase = self._resolve_next(scenario, phase, good, run)

        phase_num = len(previous_actions) + 1
        prompt = scenario._phase_prompt(phase)
        ideal_action, ideal_why = response_scorer.split_reference_answer(
            phase.reference_answer
        )
        record = ActionRecord(
            phase_number=phase_num,
            phase_title=phase.title,
            situation=phase.situation,
            mitre_tactic=phase.mitre_tactic,
            mitre_technique=phase.mitre_technique,
            prompt=prompt,
            choice_type="freeform",
            user_response=answer,
            options_presented=[],
            ideal_answer=ideal_action or phase.reference_answer or "(no reference answer defined)",
            reference_explanation=ideal_why,
            timestamp=_now().strftime("%H:%M:%S"),
            elapsed_sec=_elapsed_seconds(run.get("started_at") or ""),
            response_score=scored["score"],
            parts_json=json.dumps({
                "parts": scored["parts"],
                "coverage": scored.get("coverage", 0.0),
                "phrase_coverage": scored.get("phrase_coverage", 0.0),
                "matched_terms": scored.get("matched_terms", []),
                "missing_terms": scored.get("missing_terms", []),
            }),
            hints_used=hints_for_phase,
            looked_up=revealed,
        )
        action_payload = record.to_dict()
        action_payload.update({
            "phase_id": phase.id,
            "phase_type": phase.phase_type,
            "branch": "good" if good else "weak",
            "next_phase_id": next_phase.id if next_phase else "",
        })

        self.db.add_action(run_id, action_payload)
        visited = list(run.get("visited") or [])
        visited.append(phase.id)
        self.db.update_run_state(
            run_id,
            current_phase_id=next_phase.id if next_phase else "",
            visited=visited,
            draft_answer="",
        )

        updated = self.state(run_id, run.get("user_name"))
        return {
            "run_id": run_id,
            "status": "in_progress",
            "branch": "good" if good else "weak",
            "followup": followup or "",
            "phase": updated["phase"],
            "progress": updated["progress"],
            "can_finish": updated["can_finish"],
        }

    def reveal_hint(
        self, run_id: int, *, user_name: Optional[str] = None
    ) -> dict[str, Any]:
        run = self._require_live_run(run_id, user_name)
        scenario_cls = _get_scenario(run["scenario_id"])
        scenario = scenario_cls()
        scenario.set_user_role(run.get("role_used") or "analyst")
        phase = scenario.phase_by_id(run.get("current_phase_id") or "")
        if phase is None:
            raise RunStateError("There is no open phase to hint.")

        assist = run.get("assist") or {}
        hints = dict(assist.get("hints") or {})
        used = int(hints.get(phase.id, 0) or 0)
        available = list(phase.hints or [])

        if used >= len(available):
            return {
                "run_id": run_id,
                "phase_id": phase.id,
                "hint": None,
                "index": used,
                "total": len(available),
                "remaining": 0,
                "exhausted": True,
            }

        hint = available[used]
        hints[phase.id] = used + 1
        assist["hints"] = hints
        self.db.update_run_state(run_id, assist=assist)
        return {
            "run_id": run_id,
            "phase_id": phase.id,
            "hint": hint,
            "index": used + 1,
            "total": len(available),
            "remaining": max(0, len(available) - (used + 1)),
            "exhausted": used + 1 >= len(available),
        }

    def reveal_reference(
        self, run_id: int, *, user_name: Optional[str] = None
    ) -> dict[str, Any]:
        run = self._require_live_run(run_id, user_name)
        scenario_cls = _get_scenario(run["scenario_id"])
        scenario = scenario_cls()
        scenario.set_user_role(run.get("role_used") or "analyst")
        phase = scenario.phase_by_id(run.get("current_phase_id") or "")
        if phase is None:
            raise RunStateError("There is no open phase to reveal.")

        if not phase.reference_answer:
            raise RunStateError("This phase has no reference answer.")

        assist = run.get("assist") or {}
        revealed = list(assist.get("revealed") or [])
        if phase.id not in revealed:
            revealed.append(phase.id)
        assist["revealed"] = revealed
        self.db.update_run_state(run_id, assist=assist)

        return {
            "run_id": run_id,
            "phase_id": phase.id,
            "reference_answer": phase.reference_answer,
            "looked_up": True,
            "reveals_total": len(revealed),
        }

    def save_draft(
        self, run_id: int, text: str, *, user_name: Optional[str] = None
    ) -> dict[str, Any]:
        run = self._require_live_run(run_id, user_name)
        draft = (text or "")[:MAX_ANSWER_CHARS]
        self.db.update_run_state(run_id, draft_answer=draft)
        return {"run_id": run_id, "draft_answer": draft}

    # ------------------------------------------------------------------ #
    # Finish / abandon
    # ------------------------------------------------------------------ #
    def finish(
        self, run_id: int, *, user_name: Optional[str] = None
    ) -> dict[str, Any]:
        """Evaluate a completed run and persist the debrief payload."""
        run = self._require_live_run(run_id, user_name)
        if run.get("current_phase_id"):
            raise RunStateError(
                "Answer the open phase before finishing the run.",
                detail={"current_phase_id": run.get("current_phase_id")},
            )

        scenario_cls = _get_scenario(run["scenario_id"])
        actions = self.db.get_run_actions(run_id)
        if not actions:
            raise RunStateError("Cannot finish a run with no answers.")

        session = _session_log_from_actions(run, scenario_cls, actions)
        evaluation = evaluate(session)

        final_run_id = self.db.save_run(
            session, evaluation, scenario_cls, run_id=run_id
        )
        session.run_id = final_run_id

        user = self.db.get_user(run["user_name"]) or {}
        domains = list(user.get("domains") or []) or [scenario_cls.meta.category]
        rec = recommend_next(self.db, run["user_name"], domains)
        self.db.set_next_scenario_reason(final_run_id, rec["reason"])
        evaluation["next_scenario_reason"] = rec["reason"]

        return {
            "run_id": final_run_id,
            "status": "completed",
            "evaluation": evaluation,
            "recommendation": self._public_recommendation(rec),
        }

    def abandon(self, run_id: int, *, user_name: Optional[str] = None) -> dict[str, Any]:
        run = self._require_run(run_id, user_name)
        if run.get("status") == "completed":
            raise RunStateError("A completed run cannot be abandoned.")
        self.db.abandon_run(run_id)
        return {"run_id": run_id, "status": "abandoned"}

    # ------------------------------------------------------------------ #
    # Debrief / recommendation
    # ------------------------------------------------------------------ #
    def evaluation(self, run_id: int, user_name: Optional[str] = None) -> dict[str, Any]:
        run = self._require_run(run_id, user_name)
        raw = run.get("evaluation_json")
        payload = None
        if raw:
            try:
                payload = json.loads(raw)
            except (TypeError, ValueError):
                payload = None
        return {
            "run_id": run_id,
            "status": run.get("status"),
            "score": run.get("score"),
            "grade": run.get("grade"),
            "evaluation": payload,
        }

    def session_log(
        self, run_id: int, user_name: Optional[str] = None
    ) -> tuple[SessionLog, dict[str, Any]]:
        """Rebuild the evaluator/report input and the raw run row."""
        run = self._require_run(run_id, user_name)
        scenario_cls = _get_scenario(run["scenario_id"])
        session = _session_log_from_actions(
            run, scenario_cls, self.db.get_run_actions(run_id)
        )
        return session, run

    def recommendation(
        self, user_name: str, domains: Optional[list[str]] = None
    ) -> dict[str, Any]:
        user = self.db.get_user(user_name) or {}
        scopes = list(domains or user.get("domains") or [])
        rec = recommend_next(self.db, user_name, scopes)
        return self._public_recommendation(rec)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _require_run(self, run_id: int, user_name: Optional[str]) -> dict[str, Any]:
        if not self.db.available:
            raise PersistenceUnavailable("Session database is unavailable")
        run = self.db.get_run(run_id, user_name)
        if not run:
            raise RunNotFound(f"Run {run_id} was not found")
        return run

    def _require_live_run(
        self, run_id: int, user_name: Optional[str]
    ) -> dict[str, Any]:
        run = self._require_run(run_id, user_name)
        if run.get("status") != "in_progress":
            raise RunStateError(
                f"Run {run_id} is {run.get('status')}, not in progress.",
                detail={"status": run.get("status")},
            )
        return run

    def _scenario_brief(
        self, scenario: Scenario, run: dict[str, Any]
    ) -> dict[str, Any]:
        meta = scenario.meta
        role = run.get("role_used") or scenario.user_role
        return {
            "id": getattr(scenario, "_scenario_id", "") or meta.name,
            "name": meta.name,
            "title": meta.incident_title,
            "category": meta.category,
            "difficulty": meta.difficulty,
            "opening": meta.opening or meta.incident_summary,
            "compromised_assets": list(meta.compromised_assets or []),
            "detected_via": meta.detected_via,
            "kill_chain": list(meta.kill_chain or []),
            "mitre_tactics": list(meta.mitre_tactics or []),
            "soc_tier": meta.soc_tier,
            "roles": list(meta.roles or ["analyst"]),
            "role": role,
            "role_briefing": meta.role_briefings.get(role, ""),
            "executive_brief": meta.executive_brief,
            "phase_count": len(scenario.phases),
        }

    def _public_phase(
        self,
        scenario: Scenario,
        phase: Phase,
        run: dict[str, Any],
        answered: list[dict[str, Any]],
    ) -> dict[str, Any]:
        assist = run.get("assist") or {}
        hints_used = int((assist.get("hints") or {}).get(phase.id, 0) or 0)
        revealed = phase.id in (assist.get("revealed") or [])
        return {
            "number": len(answered) + 1,
            "id": phase.id,
            "title": phase.title,
            "type": phase.phase_type,
            "situation": phase.situation,
            "prompt": scenario._phase_prompt(phase),
            "guidance": {
                "what": str((phase.guidance or {}).get("what", "")),
                "action": str((phase.guidance or {}).get("action", "")),
                "why": str((phase.guidance or {}).get("why", "")),
            },
            "hint": phase.hint,
            "hints_total": len(phase.hints or []),
            "hints_revealed": hints_used,
            "reference_revealed": revealed,
            "mitre_tactic": phase.mitre_tactic,
            "mitre_technique": phase.mitre_technique,
        }

    def _progress(
        self, run: dict[str, Any], answered: list[dict[str, Any]], current_id: str
    ) -> dict[str, Any]:
        assist = run.get("assist") or {}
        hints_used = sum(
            int(v or 0) for v in (assist.get("hints") or {}).values()
        )
        reveals = len(assist.get("revealed") or [])
        return {
            "answered": len(answered),
            "visited": list(run.get("visited") or []),
            "current_phase_id": current_id or "",
            "hints_used": hints_used,
            "reveals": reveals,
            "draft_answer": run.get("draft_answer") or "",
        }

    @staticmethod
    def _resolve_next(
        scenario: Scenario,
        phase: Phase,
        good: bool,
        run: dict[str, Any],
    ) -> Optional[Phase]:
        """Good/weak branch navigation with sequential fallback and loop guard."""
        next_id = phase.next if good else (phase.next_weak or phase.next)
        visited = set(run.get("visited") or [])
        visited.add(phase.id)

        if next_id and next_id not in visited:
            nxt = scenario.phase_by_id(next_id)
            if nxt is not None:
                return nxt

        for index, candidate in enumerate(scenario.phases):
            if candidate.id == phase.id:
                for fallback in scenario.phases[index + 1:]:
                    if fallback.id not in visited:
                        return fallback
                return None
        return None

    @staticmethod
    def _public_recommendation(rec: dict[str, Any]) -> dict[str, Any]:
        cls = rec.get("scenario_cls")
        return {
            "mode": rec.get("mode"),
            "technique": rec.get("technique"),
            "reason": rec.get("reason", ""),
            "scenario": scenario_summary(cls) if cls is not None else None,
        }


__all__ = [
    "RunService",
    "RunServiceError",
    "PersistenceUnavailable",
    "ScenarioNotFound",
    "RunNotFound",
    "RunStateError",
    "InvalidAnswer",
    "resolve_role",
    "scenario_summary",
    "phase_count",
    "MAX_ANSWER_CHARS",
]
