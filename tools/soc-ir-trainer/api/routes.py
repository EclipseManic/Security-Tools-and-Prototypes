"""HTTP routes for `/api/v1`."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional

import httpx
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import FileResponse

from api import jobs
from api.auth import clear_session_cookie, set_session_cookie
from api.deps import current_user, get_db
from api.errors import ApiError
from api.schemas import (
    AbandonOut,
    AnswerOut,
    AnswerRequest,
    ApiKeyUpdate,
    DataActionOut,
    DraftOut,
    DraftRequest,
    HealthOut,
    HintOut,
    JobOut,
    LiveRunSummary,
    ModelInfo,
    ModelListOut,
    ModelUpdate,
    ProfilePatch,
    ProgressOut,
    RecommendationOut,
    RevealOut,
    RunCreate,
    RunHistoryItem,
    RunHistoryPage,
    RunStateOut,
    ScenarioDetail,
    ScenarioOut,
    ScenarioPage,
    SessionCreate,
    SessionOut,
    SettingsOut,
    UserOut,
)
import config
from config import APP_NAME, APP_VERSION, REPORT_DIR
from core.mitre import same_technique
from core.reporter import render_html, render_json, render_pdf
from core.run_service import (
    MAX_ANSWER_CHARS,
    RunService,
    scenario_summary,
)
from core.session_db import RUN_STATUSES, SessionDB
from scenarios import ALL_CATEGORIES, SCENARIO_BY_ID, TOTAL_SCENARIOS

router = APIRouter()

_DIFFICULTY_ORDER = {"Easy": 0, "Medium": 1, "Hard": 2, "Expert": 3, "Critical": 4}
_DIFFICULTY_LEVELS = ("Easy", "Medium", "Hard", "Expert", "Critical")
_CATEGORY_ORDER = (
    "Endpoint",
    "Identity & Access",
    "Web App",
    "Network",
    "Cloud",
    "Advanced Threats",
    "AI & ML",
)
_CATEGORY_RANK = {name: index for index, name in enumerate(_CATEGORY_ORDER)}
_ROLE_LABELS = {
    "analyst": "SOC Analyst",
    "incident_manager": "Incident Manager",
    "ciso": "CISO",
    "executive": "Executive",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _known_domains(values: Optional[list[str]]) -> list[str]:
    known = set(ALL_CATEGORIES)
    return [value for value in (values or []) if value in known]


def _user_out(user: dict) -> UserOut:
    return UserOut(
        name=user["name"],
        role=user.get("role") or "analyst",
        domains=list(user.get("domains") or []),
        created_at=user.get("created_at"),
    )


def _live_summary(state: Optional[dict]) -> Optional[LiveRunSummary]:
    if not state or not state.get("phase"):
        return None
    scenario = state["scenario"]
    phase = state["phase"]
    return LiveRunSummary(
        run_id=int(state["run_id"]),
        scenario_id=scenario["id"],
        title=scenario["title"],
        category=scenario["category"],
        phase_number=int(phase.get("number") or 0),
        answered=int((state.get("progress") or {}).get("answered") or 0),
        updated_at=state.get("updated_at"),
    )


def _history_item(row: dict) -> RunHistoryItem:
    cls = SCENARIO_BY_ID.get(row.get("scenario_id") or "")
    title = cls.meta.incident_title if cls else (row.get("scenario_id") or "Unknown scenario")
    category = row.get("domain") or (cls.meta.category if cls else "")

    duration = None
    if row.get("started_at") and row.get("completed_at"):
        try:
            start = datetime.fromisoformat(row["started_at"])
            end = datetime.fromisoformat(row["completed_at"])
            duration = round((end - start).total_seconds() / 60, 1)
        except (TypeError, ValueError):
            duration = None

    return RunHistoryItem(
        run_id=int(row["run_id"]),
        scenario_id=row.get("scenario_id") or "",
        title=title,
        category=category,
        role_used=row.get("role_used") or "analyst",
        score=row.get("score"),
        grade=row.get("grade"),
        started_at=row.get("started_at") or "",
        completed_at=row.get("completed_at"),
        status=row.get("status") or "completed",
        duration_minutes=duration,
    )


def _require_user(db: SessionDB, name: str) -> dict:
    user = db.get_user(name)
    if not user:
        raise ApiError(
            401,
            "unknown_profile",
            "This profile no longer exists — create a session again.",
        )
    return user


# --------------------------------------------------------------------------- #
# Session / profile
# --------------------------------------------------------------------------- #
@router.post("/session", response_model=SessionOut, status_code=201)
def create_session(
    payload: SessionCreate, response: Response, db: SessionDB = Depends(get_db)
) -> SessionOut:
    name = payload.name.strip()
    if not name:
        raise ApiError(422, "invalid_name", "A profile name is required.")
    if not db.available:
        raise ApiError(503, "persistence_unavailable", "Session database is unavailable.")

    domains = _known_domains(payload.domains) or list(ALL_CATEGORIES)
    db.create_user(name, payload.role, domains)
    set_session_cookie(response, name)

    user = db.get_user(name) or {"name": name, "role": payload.role, "domains": domains}
    live = None
    try:
        live = _live_summary(RunService(db).latest_live(name))
    except Exception:
        live = None
    return SessionOut(user=_user_out(user), live_run=live, scenarios=TOTAL_SCENARIOS)


@router.get("/me", response_model=SessionOut)
def get_me(db: SessionDB = Depends(get_db), user: str = Depends(current_user)) -> SessionOut:
    profile = _require_user(db, user)
    live = None
    try:
        live = _live_summary(RunService(db).latest_live(user))
    except Exception:
        live = None
    return SessionOut(user=_user_out(profile), live_run=live, scenarios=TOTAL_SCENARIOS)


@router.patch("/me", response_model=SessionOut)
def update_me(
    payload: ProfilePatch,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> SessionOut:
    profile = _require_user(db, user)
    role = payload.role or profile.get("role") or "analyst"
    domains = list(profile.get("domains") or [])
    if payload.domains is not None:
        filtered = _known_domains(payload.domains)
        if not filtered:
            raise ApiError(422, "invalid_domains", "Select at least one known domain.")
        domains = filtered

    db.create_user(user, role, domains)
    updated = db.get_user(user) or profile
    live = None
    try:
        live = _live_summary(RunService(db).latest_live(user))
    except Exception:
        live = None
    return SessionOut(user=_user_out(updated), live_run=live, scenarios=TOTAL_SCENARIOS)


@router.delete("/me", response_model=DataActionOut)
def delete_me(
    response: Response,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> DataActionOut:
    """Delete the current profile and every run/action/mastery row it owns."""
    _require_user(db, user)
    counts = db.delete_user(user)
    clear_session_cookie(response)
    return DataActionOut(user=user, **counts)


@router.post("/settings/clear-history", response_model=DataActionOut)
def clear_history(
    db: SessionDB = Depends(get_db), user: str = Depends(current_user)
) -> DataActionOut:
    """Delete all runs and derived learning data, keeping the profile."""
    _require_user(db, user)
    counts = db.clear_user_history(user)
    return DataActionOut(user=user, **counts)


@router.put("/settings/api-key", response_model=SettingsOut)
def set_api_key(
    payload: ApiKeyUpdate,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> SettingsOut:
    _require_user(db, user)
    key = payload.api_key.strip()
    if key and (len(key) < 10 or any(char.isspace() for char in key)):
        raise ApiError(
            422,
            "invalid_api_key",
            "That does not look like a valid OpenRouter API key.",
        )
    config.save_openrouter_key(key)
    return _settings_out(db)


@router.delete("/settings/api-key", response_model=SettingsOut)
def clear_api_key(
    db: SessionDB = Depends(get_db), user: str = Depends(current_user)
) -> SettingsOut:
    _require_user(db, user)
    config.save_openrouter_key("")
    return _settings_out(db)


@router.put("/settings/model", response_model=SettingsOut)
def set_model(
    payload: ModelUpdate,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> SettingsOut:
    _require_user(db, user)
    model = payload.model.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{2,127}", model):
        raise ApiError(422, "invalid_model", "Use a valid OpenRouter model id.")
    try:
        config.save_openrouter_model(model)
    except (OSError, ValueError) as exc:
        raise ApiError(503, "model_save_failed", str(exc)) from exc
    return _settings_out(db)


_MODEL_CACHE_TTL = 600
_MODEL_FALLBACK = [
    ModelInfo(id="nvidia/nemotron-3.5-lightning:free", name="Nemotron 3.5 Lightning (free)", free=True),
    ModelInfo(id="nvidia/nemotron-3.5-super-vl:free", name="Nemotron 3.5 Super VL (free)", free=True),
    ModelInfo(id="nvidia/nemotron-3-ultra-550b-a55b:free", name="Nemotron 3 Ultra 550B (free)", free=True),
    ModelInfo(id="nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free", name="Nemotron 3 Nano Omni (free)", free=True),
    ModelInfo(id="nvidia/nemotron-3-super-120b-a12b", name="Nemotron 3 Super 120B"),
]
_model_cache: dict[str, Any] = {"at": 0.0, "models": [], "source": "fallback"}


@router.get("/settings/models", response_model=ModelListOut)
def list_models() -> ModelListOut:
    """Live OpenRouter catalog, cached; falls back to known Nemotron ids."""
    now = time.time()
    if _model_cache["models"] and now - float(_model_cache["at"]) < _MODEL_CACHE_TTL:
        return ModelListOut(models=_model_cache["models"], source=_model_cache["source"])

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get("https://openrouter.ai/api/v1/models")
        response.raise_for_status()
        raw = response.json().get("data", [])
        models: list[ModelInfo] = []
        for item in raw:
            model_id = str(item.get("id") or "").strip()
            if not model_id:
                continue
            pricing = item.get("pricing") or {}
            prompt_price = str(pricing.get("prompt") or "")
            models.append(
                ModelInfo(
                    id=model_id,
                    name=str(item.get("name") or model_id),
                    context_length=item.get("context_length"),
                    free=model_id.endswith(":free") or prompt_price in {"0", "0.0"},
                )
            )
        models.sort(key=lambda m: (not m.free, m.name.lower()))
        if models:
            _model_cache.update(at=now, models=models, source="openrouter")
            return ModelListOut(models=models, source="openrouter")
    except Exception:
        pass

    _model_cache.update(at=now, models=_MODEL_FALLBACK, source="fallback")
    return ModelListOut(models=_MODEL_FALLBACK, source="fallback")


@router.post("/logout", status_code=204)
def logout(response: Response) -> Response:
    clear_session_cookie(response)
    response.status_code = 204
    return response


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
@router.get("/scenarios", response_model=ScenarioPage)
def list_scenarios(
    domain: Optional[str] = None,
    difficulty: Optional[str] = None,
    role: Optional[str] = None,
    tier: Optional[str] = None,
    technique: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ScenarioPage:
    query = (q or "").strip().lower()
    technique = (technique or "").strip()
    items: list[ScenarioOut] = []

    for cls in SCENARIO_BY_ID.values():
        meta = cls.meta
        if domain and meta.category != domain:
            continue
        if difficulty and meta.difficulty != difficulty:
            continue
        if role and role not in (meta.roles or ["analyst"]):
            continue
        if tier and tier.lower() not in (meta.soc_tier or "").lower():
            continue
        if technique and not any(
            same_technique(phase.mitre_technique, technique)
            or technique.lower() in (phase.mitre_technique or "").lower()
            for phase in cls.phases
        ):
            continue
        if query:
            haystack = " ".join([
                meta.name,
                meta.incident_title,
                meta.category,
                meta.opening,
                meta.incident_summary,
                " ".join(meta.mitre_tactics or []),
            ]).lower()
            if query not in haystack:
                continue
        items.append(ScenarioOut(**scenario_summary(cls, role)))

    items.sort(
        key=lambda item: (
            _CATEGORY_RANK.get(item.category, len(_CATEGORY_ORDER)),
            _DIFFICULTY_ORDER.get(item.difficulty, 9),
            item.title.lower(),
        )
    )
    total = len(items)
    page = items[offset: offset + limit]

    domain_counts: dict[str, int] = {}
    for name in _CATEGORY_ORDER:
        if name in ALL_CATEGORIES:
            domain_counts[name] = len(ALL_CATEGORIES[name])
    for name, group in ALL_CATEGORIES.items():
        domain_counts.setdefault(name, len(group))

    facets = {
        "domains": domain_counts,
        "difficulties": {
            level: sum(1 for cls in SCENARIO_BY_ID.values() if cls.meta.difficulty == level)
            for level in _DIFFICULTY_LEVELS
        },
        "roles": {
            role_name: sum(
                1
                for cls in SCENARIO_BY_ID.values()
                if role_name in (cls.meta.roles or ["analyst"])
            )
            for role_name in _ROLE_LABELS
        },
    }
    return ScenarioPage(
        items=page, total=total, limit=limit, offset=offset, facets=facets
    )


@router.get("/scenarios/{scenario_id}", response_model=ScenarioDetail)
def get_scenario(
    scenario_id: str, role: Optional[str] = None
) -> ScenarioDetail:
    cls = SCENARIO_BY_ID.get(scenario_id)
    if cls is None:
        raise ApiError(404, "scenario_not_found", f"Unknown scenario '{scenario_id}'.")
    detail = scenario_summary(cls, role)
    detail["briefings"] = dict(cls.meta.role_briefings or {})
    detail["phase_types"] = [phase.phase_type for phase in cls.phases]
    return ScenarioDetail(**detail)


# --------------------------------------------------------------------------- #
# Runs
# --------------------------------------------------------------------------- #
@router.post("/runs", response_model=RunStateOut, status_code=201)
def create_run(
    payload: RunCreate,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> RunStateOut:
    _require_user(db, user)
    state = RunService(db).start(
        user,
        payload.scenario_id,
        payload.role,
        industry=payload.industry,
    )
    return RunStateOut(**state)


@router.get("/runs", response_model=RunHistoryPage)
def list_runs(
    status: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> RunHistoryPage:
    if status and status not in RUN_STATUSES:
        raise ApiError(422, "invalid_status", f"Unknown run status '{status}'.")
    page = db.get_runs(user, status=status, limit=limit, offset=offset)
    return RunHistoryPage(
        items=[_history_item(row) for row in page["items"]],
        total=page["total"],
        limit=page["limit"],
        offset=page["offset"],
    )


@router.get("/runs/{run_id}", response_model=RunStateOut)
def get_run(
    run_id: int,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> RunStateOut:
    return RunStateOut(**RunService(db).state(run_id, user))


@router.post("/runs/{run_id}/answer", response_model=AnswerOut)
def answer_run(
    run_id: int,
    payload: AnswerRequest,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> AnswerOut:
    result = RunService(db).answer(
        run_id, payload.text, user_name=user, phase_id=payload.phase_id
    )
    return AnswerOut(**result)


@router.post("/runs/{run_id}/hint", response_model=HintOut)
def reveal_hint(
    run_id: int,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> HintOut:
    return HintOut(**RunService(db).reveal_hint(run_id, user_name=user))


@router.post("/runs/{run_id}/reveal", response_model=RevealOut)
def reveal_reference(
    run_id: int,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> RevealOut:
    return RevealOut(**RunService(db).reveal_reference(run_id, user_name=user))


@router.patch("/runs/{run_id}/draft", response_model=DraftOut)
def save_draft(
    run_id: int,
    payload: DraftRequest,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> DraftOut:
    return DraftOut(**RunService(db).save_draft(run_id, payload.text, user_name=user))


@router.post("/runs/{run_id}/abandon", response_model=AbandonOut)
def abandon_run(
    run_id: int,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> AbandonOut:
    return AbandonOut(**RunService(db).abandon(run_id, user_name=user))


@router.post("/runs/{run_id}/finish", response_model=JobOut, status_code=202)
def finish_run(
    run_id: int,
    request: Request,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> JobOut:
    state = RunService(db).state(run_id, user)
    if state.get("status") != "in_progress":
        raise ApiError(
            409,
            "invalid_state",
            "This run is already finished.",
            detail={"status": state.get("status")},
        )
    if state.get("phase") is not None:
        raise ApiError(
            409,
            "open_phase",
            "Answer the open phase before finishing.",
            detail={"phase_id": state["phase"].get("id")},
        )
    if not state["progress"].get("answered"):
        raise ApiError(409, "no_answers", "Cannot finish a run with no answers.")

    job = jobs.submit(run_id, request.app.state.db_path, user)
    return JobOut(**job.to_dict())


@router.get("/runs/{run_id}/evaluation", response_model=JobOut)
def get_evaluation(
    run_id: int,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> JobOut:
    run = db.get_run(run_id, user)
    if not run:
        raise ApiError(404, "run_not_found", f"Run {run_id} was not found.")

    job = jobs.get(run_id)
    if job is not None:
        return JobOut(**job.to_dict())

    if run.get("status") == "completed":
        data = RunService(db).evaluation(run_id, user)
        return JobOut(
            run_id=run_id,
            status="done",
            finished_at=run.get("completed_at"),
            result={
                "run_id": run_id,
                "status": "completed",
                "evaluation": data.get("evaluation"),
                "recommendation": RunService(db).recommendation(user),
            },
        )

    return JobOut(run_id=run_id, status="not_started")


@router.get("/runs/{run_id}/report")
def download_report(
    run_id: int,
    format: Literal["html", "pdf", "json"] = "html",
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> FileResponse:
    svc = RunService(db)
    data = svc.evaluation(run_id, user)
    if data.get("status") != "completed" or not data.get("evaluation"):
        raise ApiError(
            409,
            "evaluation_not_ready",
            "The debrief is not ready for this run yet.",
        )

    session, _run = svc.session_log(run_id, user)
    evaluation = data["evaluation"]

    if format == "pdf":
        path = render_pdf(session, evaluation)
        if path is None:
            raise ApiError(503, "pdf_unavailable", "PDF generation is unavailable.")
        media = "application/pdf"
    elif format == "json":
        path = render_json(session, evaluation)
        media = "application/json"
    else:
        path = render_html(session, evaluation)
        media = "text/html; charset=utf-8"

    return FileResponse(str(path), media_type=media, filename=Path(path).name)


# --------------------------------------------------------------------------- #
# Progress / recommendation
# --------------------------------------------------------------------------- #
@router.get("/progress", response_model=ProgressOut)
def get_progress(
    db: SessionDB = Depends(get_db), user: str = Depends(current_user)
) -> ProgressOut:
    profile = _require_user(db, user)
    domains = list(profile.get("domains") or []) or list(ALL_CATEGORIES)

    live = None
    try:
        live = _live_summary(RunService(db).latest_live(user))
    except Exception:
        live = None

    recent = [
        _history_item(row).model_dump()
        for row in db.get_recent_scenarios(user, limit=12)
    ]
    recommendation = RunService(db).recommendation(user, domains)
    return ProgressOut(
        user=_user_out(profile),
        learner_level=db.get_learner_level(user),
        streak=db.get_practice_streak(user),
        run_count=db.get_run_count(user),
        domains=db.get_domain_performance(user),
        mastery=db.get_mastery(user),
        recent=recent,
        recommendation=RecommendationOut(**recommendation),
        live_run=live,
    )


@router.get("/recommendation", response_model=RecommendationOut)
def get_recommendation(
    domains: Optional[str] = None,
    db: SessionDB = Depends(get_db),
    user: str = Depends(current_user),
) -> RecommendationOut:
    scope = _known_domains(domains.split(",")) if domains else None
    profile = _require_user(db, user)
    if scope is None:
        scope = list(profile.get("domains") or []) or list(ALL_CATEGORIES)
    return RecommendationOut(**RunService(db).recommendation(user, scope))


# --------------------------------------------------------------------------- #
# Settings / health
# --------------------------------------------------------------------------- #
def _settings_out(db: SessionDB) -> SettingsOut:
    return SettingsOut(
        app=APP_NAME,
        version=APP_VERSION,
        model=config.OPENROUTER_MODEL,
        api_key_configured=bool(config.OPENROUTER_API_KEY),
        ai_disabled=bool(config.AI_DISABLED),
        db_available=db.available,
        scenarios=TOTAL_SCENARIOS,
        max_answer_chars=MAX_ANSWER_CHARS,
        cookie_secure=(os.getenv("SOC_COOKIE_SECURE", "0") == "1"),
        report_dir=str(REPORT_DIR),
    )


@router.get("/settings", response_model=SettingsOut)
def get_settings(db: SessionDB = Depends(get_db)) -> SettingsOut:
    return _settings_out(db)


@router.get("/health", response_model=HealthOut)
def health(db: SessionDB = Depends(get_db)) -> HealthOut:
    return HealthOut(
        status="ok" if db.available else "degraded",
        version=APP_VERSION,
        db=db.available,
        scenarios=TOTAL_SCENARIOS,
    )
