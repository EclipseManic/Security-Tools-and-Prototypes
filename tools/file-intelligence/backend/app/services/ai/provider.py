from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class AIProvider(ABC):
    @abstractmethod
    async def analyze_text(self, text: str, metadata: Optional[dict] = None) -> dict[str, Any]:
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        ...


class AIAnalysisResult:
    def __init__(self):
        self.summary: Optional[str] = None
        self.detailed_summary: Optional[str] = None
        self.category: Optional[str] = None
        self.subcategory: Optional[str] = None
        self.confidence: float = 0.0
        self.explanation: Optional[str] = None
        self.keywords: list[str] = []
        self.entities: list[dict[str, str]] = []
        self.topics: list[str] = []
        self.language: Optional[str] = None
        self.error: Optional[str] = None


ANALYSIS_PROMPT = """You are a file intelligence analyst. Analyze the following file content and metadata and provide a structured analysis.

Return ONLY valid JSON with these exact fields:
{{
  "summary": "1-2 sentence summary of what this file is about",
  "detailed_summary": "paragraph with more detail about the file's purpose and content",
  "category": "best category from: Engineering, Finance, HR, Legal, Sales_Marketing, Operations, IT_Security, Cloud_Infrastructure, Database, Documentation, Research, Training_Education, Personal, Communications, Credentials, Backups, Configuration, Logs, Virtual_Machines, Media, Other",
  "subcategory": "more specific subcategory if applicable",
  "confidence": 0.95,
  "explanation": "brief explanation of why this category was chosen based on content",
  "keywords": ["key1", "key2", "key3"],
  "entities": [{{"type": "PERSON|ORG|GPE|PRODUCT|TECHNOLOGY|FRAMEWORK|LANGUAGE|CLOUD", "value": "entity name"}}],
  "topics": ["main topic 1", "main topic 2"],
  "language": "primary language detected"
}}

File metadata: {metadata}

File content:
{text}
"""
