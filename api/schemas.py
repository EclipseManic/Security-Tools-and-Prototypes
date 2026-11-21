"""Pydantic v2 request/response models."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Role = Literal["analyst", "incident_manager", "ciso", "executive"]


# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #
class SessionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    role: Role = "analyst"
    domains: list[str] = Field(default_factory=list)


class ProfilePatch(BaseModel):
    role: Optional[Role] = None
    domains: Optional[list[str]] = None


class ApiKeyUpdate(BaseModel):
    api_key: str = Field(default="", max_length=512)


class ModelUpdate(BaseModel):
    model: str = Field(min_length=3, max_length=128)


class RunCreate(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=200)
    role: Role = "analyst"
    industry: str = Field(default="all", max_length=32)


class AnswerRequest(BaseModel):
    text: str = Field(min_length=1, max_length=8_000)
    phase_id: Optional[str] = Field(default=None, max_length=200)


class DraftRequest(BaseModel):
    text: str = Field(default="", max_length=8_000)


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #
class UserOut(BaseModel):
    name: str
    role: str
    domains: list[str]
    created_at: Optional[str] = None


class LiveRunSummary(BaseModel):
    run_id: int
    scenario_id: str
    title: str
    category: str
    phase_number: int
    answered: int
    updated_at: Optional[str] = None


class SessionOut(BaseModel):
    user: UserOut
    live_run: Optional[LiveRunSummary] = None
    scenarios: int


class ScenarioOut(BaseModel):
    id: str
    name: str
    title: str
    category: str
    difficulty: str
    format_version: int
    opening: str
    detected_via: str
    compromised_assets: list[str]
    kill_chain: list[str]
    mitre_tactics: list[str]
    soc_tier: str
    roles: list[str]
    industries: list[str]
    phase_count: int
    executive_brief: str
    role: str
    role_fallback: bool


class ScenarioDetail(ScenarioOut):
    briefings: dict[str, str] = Field(default_factory=dict)
    phase_types: list[str] = Field(default_factory=list)


class ScenarioPage(BaseModel):
    items: list[ScenarioOut]
    total: int
    limit: int
    offset: int
    facets: dict[str, Any] = Field(default_factory=dict)


class RunStateOut(BaseModel):
    run_id: int
    status: str
    scenario: dict[str, Any]
    phase: Optional[dict[str, Any]] = None
    progress: dict[str, Any]
    can_finish: bool
    evaluation_available: bool
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    role_fallback: bool = False
    industry: str = "all"


class AnswerOut(BaseModel):
    run_id: int
    status: str
    branch: str
    followup: str
    phase: Optional[dict[str, Any]] = None
    progress: dict[str, Any]
    can_finish: bool


class HintOut(BaseModel):
    run_id: int
    phase_id: str
    hint: Optional[str] = None
    index: int
    total: int
    remaining: int
    exhausted: bool


class RevealOut(BaseModel):
    run_id: int
    phase_id: str
    reference_answer: str
    looked_up: bool
    reveals_total: int


class DraftOut(BaseModel):
    run_id: int
    draft_answer: str


class AbandonOut(BaseModel):
    run_id: int
    status: str


class RunHistoryItem(BaseModel):
    run_id: int
    scenario_id: str
    title: str
    category: str
    role_used: str
    score: Optional[int] = None
    grade: Optional[str] = None
    started_at: str
    completed_at: Optional[str] = None
    status: str
    duration_minutes: Optional[float] = None


class RunHistoryPage(BaseModel):
    items: list[RunHistoryItem]
    total: int
    limit: int
    offset: int


class JobOut(BaseModel):
    run_id: int
    status: str
    queued_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[dict[str, Any]] = None


class RecommendationOut(BaseModel):
    mode: str
    technique: Optional[str] = None
    reason: str
    scenario: Optional[ScenarioOut] = None


class ProgressOut(BaseModel):
    user: UserOut
    learner_level: str
    streak: int
    run_count: int
    domains: list[dict[str, Any]]
    mastery: list[dict[str, Any]]
    recent: list[dict[str, Any]]
    recommendation: RecommendationOut
    live_run: Optional[LiveRunSummary] = None


class ModelInfo(BaseModel):
    id: str
    name: str
    context_length: Optional[int] = None
    free: bool = False


class ModelListOut(BaseModel):
    models: list[ModelInfo]
    source: str = "fallback"


class DataActionOut(BaseModel):
    user: str
    runs_deleted: int = 0
    actions_deleted: int = 0
    profile_deleted: bool = False


class SettingsOut(BaseModel):
    app: str
    version: str
    model: str
    api_key_configured: bool
    ai_disabled: bool = False
    db_available: bool
    scenarios: int
    max_answer_chars: int
    cookie_secure: bool
    report_dir: str


class HealthOut(BaseModel):
    status: str
    version: str
    db: bool
    scenarios: int
