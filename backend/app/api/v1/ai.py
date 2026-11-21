from __future__ import annotations

from pydantic import BaseModel

from app.services.ai.intelligence_service import IntelligenceService
from app.core.logging import get_logger
from fastapi import APIRouter

logger = get_logger(__name__)

router = APIRouter()


class AnalyzeRequest(BaseModel):
    text: str


class AnalyzeResponse(BaseModel):
    summary: str | None = None
    detailed_summary: str | None = None
    category: str | None = None
    subcategory: str | None = None
    confidence: float = 0.0
    explanation: str | None = None
    keywords: list[str] = []
    entities: list[dict] = []
    topics: list[str] = []
    language: str | None = None
    error: str | None = None


@router.post("/ai/analyze", response_model=AnalyzeResponse)
async def analyze_text(body: AnalyzeRequest):
    service = IntelligenceService()
    available = await service.is_available()
    if not available:
        return AnalyzeResponse(error="No AI provider configured or available")

    result = await service.analyze_file_content(extracted_text=body.text)
    return AnalyzeResponse(**result)
