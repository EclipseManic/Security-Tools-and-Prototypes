from __future__ import annotations

import json
import os
from typing import Any, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.services.ai.provider import AIAnalysisResult, AIProvider, ANALYSIS_PROMPT

logger = get_logger(__name__)


class GeminiProvider(AIProvider):
    def __init__(self):
        self.api_key = settings.gemini_api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = settings.gemini_model or "gemini-2.0-flash"
        self._client = None

    async def _get_client(self):
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
            except ImportError:
                logger.error("google-genai package not installed")
                return None
            except Exception as e:
                logger.error("Failed to create Gemini client: %s", e)
                return None
        return self._client

    async def is_available(self) -> bool:
        if not self.api_key:
            return False
        client = await self._get_client()
        return client is not None

    async def analyze_text(self, text: str, metadata: Optional[dict] = None) -> dict[str, Any]:
        if metadata and metadata.get("batch"):
            return await self._batch_analyze(text)

        result = AIAnalysisResult()

        client = await self._get_client()
        if not client:
            result.error = "Gemini client not available"
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

            response = await client.aio.models.generate_content(
                model=self.model,
                contents=prompt,
            )

            try:
                raw = response.text.strip()
            except (ValueError, AttributeError) as e:
                result.error = f"Gemini response had no text: {e}"
                logger.warning("Gemini empty response: finish_reason=%s", response.candidates[0].finish_reason if hasattr(response, "candidates") and response.candidates else "unknown")
                return self._to_dict(result)

            raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

            brace = raw.find("{")
            if brace > 0:
                raw = raw[brace:]
            end_brace = raw.rfind("}")
            if end_brace > -1 and end_brace < len(raw) - 1:
                raw = raw[:end_brace + 1]

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

        except json.JSONDecodeError as e:
            result.error = f"Failed to parse AI response: {e}"
            try:
                logger.warning("Gemini JSON parse error: raw=%r, error=%s", raw[:500], e)
            except NameError:
                logger.warning("Gemini JSON parse error: error=%s", e)
        except Exception as e:
            result.error = str(e)
            logger.warning("Gemini analysis failed: %s", e)

        return self._to_dict(result)

    async def _batch_analyze(self, text: str) -> dict[str, Any]:
        client = await self._get_client()
        if not client:
            return {"raw_response": None, "error": "Gemini client not available"}

        try:
            response = await client.aio.models.generate_content(
                model=self.model,
                contents=text,
            )

            try:
                raw = response.text.strip()
            except (ValueError, AttributeError) as e:
                logger.warning("Gemini batch empty response: finish_reason=%s", response.candidates[0].finish_reason if hasattr(response, "candidates") and response.candidates else "unknown")
                return {"raw_response": None, "error": f"Empty response: {e}"}

            return {"raw_response": raw, "error": None}
        except Exception as e:
            logger.warning("Gemini batch analysis failed: %s", e)
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
