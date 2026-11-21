from __future__ import annotations

import json
import os
from typing import Any, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.services.ai.gemini_provider import GeminiProvider
from app.services.ai.openai_provider import OpenAIProvider
from app.services.ai.openrouter_provider import OpenRouterProvider
from app.services.ai.bazaarlink_provider import BazaarLinkProvider
from app.services.ai.provider import AIProvider

logger = get_logger(__name__)


class IntelligenceService:
    def __init__(self):
        self._provider: Optional[AIProvider] = None

    def _get_provider(self) -> Optional[AIProvider]:
        if self._provider is not None:
            return self._provider

        provider_name = settings.ai_provider

        if provider_name == "gemini":
            self._provider = GeminiProvider()
        elif provider_name == "openrouter":
            self._provider = OpenRouterProvider()
        elif provider_name == "openai":
            self._provider = OpenAIProvider()
        elif provider_name == "bazaarlink":
            self._provider = BazaarLinkProvider()
        elif provider_name == "none" and os.getenv("GEMINI_API_KEY"):
            logger.info("Auto-enabling Gemini from GEMINI_API_KEY env var")
            self._provider = GeminiProvider()
        else:
            logger.info("No AI provider configured (ai_provider=%s)", provider_name)
            return None

        return self._provider

    async def is_available(self) -> bool:
        provider = self._get_provider()
        if provider is None:
            return False
        return await provider.is_available()

    async def analyze_file_content(
        self,
        extracted_text: Optional[str],
        ocr_text: Optional[str] = None,
        metadata: Optional[dict] = None,
        filename: Optional[str] = None,
    ) -> dict[str, Any]:
        provider = self._get_provider()
        if provider is None:
            return {
                "summary": None,
                "detailed_summary": None,
                "category": None,
                "subcategory": None,
                "confidence": 0.0,
                "explanation": None,
                "keywords": [],
                "entities": [],
                "topics": [],
                "language": None,
                "error": "No AI provider configured",
            }

        text = (extracted_text or "") + "\n" + (ocr_text or "")
        if not text.strip():
            return {
                "summary": "No extractable content found for AI analysis.",
                "detailed_summary": None,
                "category": "Unknown",
                "subcategory": None,
                "confidence": 0.0,
                "explanation": "File has no extractable text content",
                "keywords": [],
                "entities": [],
                "topics": [],
                "language": None,
                "error": None,
            }

        combined_metadata = {
            "filename": filename or "unknown",
            **(metadata or {}),
        }

        try:
            result = await provider.analyze_text(text, combined_metadata)
            return result
        except Exception as e:
            logger.error("AI analysis failed: %s", e)
            return {
                "summary": None,
                "detailed_summary": None,
                "category": None,
                "subcategory": None,
                "confidence": 0.0,
                "explanation": None,
                "keywords": [],
                "entities": [],
                "topics": [],
                "language": None,
                "error": str(e),
            }

    async def batch_analyze(self, prompt: str) -> dict[str, Any]:
        provider = self._get_provider()
        if provider is None:
            return {
                "parsed": None,
                "error": "No AI provider configured",
            }

        try:
            result = await provider.analyze_text(prompt, {"batch": True})
            if result.get("error"):
                return {"parsed": None, "error": result["error"]}

            raw = result.get("raw_response", result.get("text", ""))
            if not raw:
                raw_text = result.get("summary", "")
                if raw_text:
                    return {"parsed": None, "error": "No structured response"}
                return {"parsed": None, "error": "Empty response"}

            raw = raw.strip()
            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            brace = raw.find("{")
            if brace > 0:
                raw = raw[brace:]
            end_brace = raw.rfind("}")
            if end_brace > -1 and end_brace < len(raw) - 1:
                raw = raw[:end_brace + 1]

            parsed = json.loads(raw)
            return {"parsed": parsed, "error": None}
        except json.JSONDecodeError as e:
            logger.warning("Batch AI response parse failed: %s", e)
            return {"parsed": None, "error": f"Failed to parse AI response: {e}"}
        except Exception as e:
            logger.warning("Batch AI analysis failed: %s", e)
            return {"parsed": None, "error": str(e)}
