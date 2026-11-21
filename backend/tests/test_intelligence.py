from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.ai.intelligence_service import IntelligenceService


@pytest.mark.asyncio
async def test_intelligence_service_no_provider(monkeypatch):
    # Force provider resolution to "none" regardless of the host environment
    # or the developer's .env file.
    monkeypatch.setattr(settings, "ai_provider", "none")
    for name in (
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "BAZAARLINK_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    service = IntelligenceService()
    available = await service.is_available()
    assert available is False

    result = await service.analyze_file_content(
        extracted_text="Some test content about a software project."
    )
    assert result.get("summary") is None
    assert result.get("error") is not None
    assert result.get("error") == "No AI provider configured"
