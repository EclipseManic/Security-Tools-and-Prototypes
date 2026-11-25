from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)

TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".rst", ".log", ".csv", ".tsv",
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties",
    ".sql", ".sqlite",
}


class TextAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        result = AnalysisResult()
        try:
            with open(filepath, "rb") as f:
                raw_data = f.read()

            import chardet
            detected = chardet.detect(raw_data)
            encoding = detected.get("encoding", "utf-8") or "utf-8"

            try:
                text = raw_data.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                try:
                    text = raw_data.decode("utf-8", errors="replace")
                except Exception:
                    text = raw_data.decode("latin-1")

            result.extracted_text = text
            result.metadata = {
                "encoding": encoding,
                "confidence": detected.get("confidence", 0),
                "line_count": text.count("\n") + 1,
                "char_count": len(text),
                "word_count": len(text.split()),
            }

        except Exception as e:
            result.error = str(e)
            logger.warning("Text analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "text",
        }
