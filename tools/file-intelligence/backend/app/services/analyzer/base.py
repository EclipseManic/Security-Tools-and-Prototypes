from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        ...

    def extract_text(self, filepath: str) -> Optional[str]:
        return None

    def extract_metadata(self, filepath: str) -> Optional[dict]:
        return None


class AnalysisResult:
    def __init__(self):
        self.extracted_text: Optional[str] = None
        self.ocr_text: Optional[str] = None
        self.metadata: Optional[dict] = None
        self.entities: list[dict] = []
        self.technical_artifacts: list[dict] = []
        self.analysis_details: Optional[dict] = None
        self.error: Optional[str] = None
