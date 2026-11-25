from __future__ import annotations

import json
import os
from typing import Any, Optional

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.services.ai.provider import AIAnalysisResult, AIProvider, ANALYSIS_PROMPT

logger = get_logger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIProvider(AIProvider):
    def __init__(self):
        self.api_key = settings.openai_api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = settings.openai_model or "gpt-4o-mini"

    async def is_available(self) -> bool:
        return bool(self.api_key)

    async def analyze_text(self, text: str, metadata: Optional[dict] = None) -> dict[str, Any]:
        if metadata and metadata.get("batch"):
            return await self._batch_analyze(text)

        result = AIAnalysisResult()

        if not self.api_key:
            result.error = "OpenAI API key not configured"
            return self._to_dict(result)

        if not text or len(text.strip()) < 20:
            result.summary = "File content is empty or too short for AI analysis."
            result.category = "Unknown"
            result.confidence = 0.0
            result.explanation = "Insufficient content for analysis"
            return self._to_dict(result)

        try:
            truncated = text[:15000]
            prompt = ANALYSIS_PROMPT.format(
                text=truncated,
                metadata=json.dumps(metadata or {}, indent=2),
            )

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    OPENAI_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                data = response.json()
                raw = data["choices"][0]["message"]["content"]

            parsed = json.loads(raw)

            result.summary = parsed.get("summary")
            result.detailed_summary = parsed.get("detailed_summary")
            result.category = parsed.get("category", "Other")
            result.subcategory = parsed.get("subcategory")
            result.confidence = float(parsed.get("confidence", 0.0))
            result.explanation = parsed.get("explanation")
            result.keywords = parsed.get("keywords", [])
            result.entities = parsed.get("entities", [])
            result.topics = parsed.get("topics", [])
            result.language = parsed.get("language")

        except Exception as e:
            result.error = str(e)
            logger.warning("OpenAI analysis failed: %s", e)

        return self._to_dict(result)

    async def _batch_analyze(self, text: str) -> dict[str, Any]:
        if not self.api_key:
            return {"raw_response": None, "error": "OpenAI API key not configured"}

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    OPENAI_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": text}],
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                data = response.json()
                raw = data["choices"][0]["message"]["content"]

            return {"raw_response": raw, "error": None}
        except Exception as e:
            logger.warning("OpenAI batch analysis failed: %s", e)
            return {"raw_response": None, "error": str(e)}

    def _to_dict(self, result: AIAnalysisResult) -> dict:
        return {
            "summary": result.summary,
            "detailed_summary": result.detailed_summary,
            "category": result.category,
            "subcategory": result.subcategory,
            "confidence": result.confidence,
            "explanation": result.explanation,
            "keywords": result.keywords,
            "entities": result.entities,
            "topics": result.topics,
            "language": result.language,
            "error": result.error,
        }
