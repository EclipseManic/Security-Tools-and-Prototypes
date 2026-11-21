from __future__ import annotations

import os
import re
from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)

CODE_EXTENSIONS = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript React",
    ".jsx": "JavaScript React", ".java": "Java", ".c": "C", ".cpp": "C++", ".h": "C Header",
    ".hpp": "C++ Header", ".cs": "C#", ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".php": "PHP", ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala",
    ".sh": "Shell", ".bash": "Bash", ".ps1": "PowerShell", ".bat": "Batch",
    ".psm1": "PowerShell Module", ".psd1": "PowerShell Data",
    ".pl": "Perl", ".pm": "Perl Module", ".lua": "Lua", ".r": "R",
    ".m": "MATLAB", ".mm": "Objective-C++",
    ".html": "HTML", ".css": "CSS", ".scss": "SCSS", ".less": "Less", ".sass": "Sass",
    ".sql": "SQL", ".graphql": "GraphQL",
    ".tf": "Terraform", ".yaml": "YAML", ".yml": "YAML",
    ".dockerfile": "Dockerfile", "dockerfile": "Dockerfile",
    ".makefile": "Makefile", "makefile": "Makefile",
}


class CodeAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        result = AnalysisResult()
        ext = os.path.splitext(filepath)[1].lower()
        basename = os.path.basename(filepath).lower()

        language = CODE_EXTENSIONS.get(ext) or CODE_EXTENSIONS.get(basename) or "Unknown"

        try:
            with open(filepath, "rb") as f:
                raw_data = f.read()

            encoding = "utf-8"
            try:
                import chardet
                detected = chardet.detect(raw_data)
                encoding = detected.get("encoding", "utf-8") or "utf-8"
            except Exception:
                pass

            try:
                text = raw_data.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                text = raw_data.decode("utf-8", errors="replace")

            result.extracted_text = text

            imports = self._extract_imports(text, language)
            functions = self._extract_functions(text, language)
            classes = self._extract_classes(text, language)
            urls = re.findall(r'https?://[^\s"\'<>)]+', text)
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

            result.analysis_details = {
                "language": language,
                "line_count": text.count("\n") + 1,
                "import_count": len(imports),
                "function_count": len(functions),
                "class_count": len(classes),
                "imports": imports[:50],
                "functions": functions[:30],
                "classes": classes[:20],
                "urls_found": urls[:20],
                "ips_found": ips[:20],
            }

            result.metadata = {
                "language": language,
                "line_count": text.count("\n") + 1,
            }

        except Exception as e:
            result.error = str(e)
            logger.warning("Code analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "code",
        }

    def _extract_imports(self, text: str, language: str) -> list[str]:
        imports: list[str] = []
        patterns = {
            "Python": [r'^import\s+(\S+)', r'^from\s+(\S+)\s+import'],
            "JavaScript": [r'^import\s+.*?\s+from\s+["\'](.+?)["\']', r'^const\s+.*?=\s+require\(["\'](.+?)["\']\)'],
            "TypeScript": [r'^import\s+.*?\s+from\s+["\'](.+?)["\']'],
            "Java": [r'^import\s+(.+?);'],
            "Go": [r'^import\s+["\'](.+?)["\']', r'^import\s+\(([^)]+)\)'],
            "C": [r'^#include\s*[<"](.+?)[>"]'],
            "C++": [r'^#include\s*[<"](.+?)[>"]'],
            "PHP": [r'^(?:require|include)(?:_once)?\s*\(?["\'](.+?)["\']\)?;'],
            "Rust": [r'^use\s+(\S+);'],
        }

        lang_patterns = patterns.get(language, [])
        for pattern in lang_patterns:
            imports.extend(re.findall(pattern, text, re.MULTILINE))

        return list(set(imports))

    def _extract_functions(self, text: str, language: str) -> list[str]:
        functions: list[str] = []
        patterns = {
            "Python": [r'^def\s+(\w+)\s*\('],
            "JavaScript": [r'(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\()', r'(\w+)\s*:\s*(?:function\s*)?\('],
            "TypeScript": [r'(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\()'],
            "Java": [r'(?:public|private|protected|static|\s)\s+\w+\s+(\w+)\s*\('],
            "C": [r'^\w+\s+\w+\s*\([^)]*\)\s*\{'],
            "Go": [r'^func\s+(\w+)\s*\('],
        }

        lang_patterns = patterns.get(language, [])
        for pattern in lang_patterns:
            functions.extend(re.findall(pattern, text, re.MULTILINE))

        return [f for f in functions if f]

    def _extract_classes(self, text: str, language: str) -> list[str]:
        classes: list[str] = []
        patterns = {
            "Python": [r'^class\s+(\w+)'],
            "JavaScript": [r'^class\s+(\w+)'],
            "TypeScript": [r'^class\s+(\w+)', r'^interface\s+(\w+)'],
            "Java": [r'^class\s+(\w+)', r'^interface\s+(\w+)'],
            "C++": [r'^class\s+(\w+)'],
            "C#": [r'^class\s+(\w+)', r'^interface\s+(\w+)'],
            "PHP": [r'^class\s+(\w+)'],
        }

        lang_patterns = patterns.get(language, [])
        for pattern in lang_patterns:
            classes.extend(re.findall(pattern, text, re.MULTILINE))

        return classes
