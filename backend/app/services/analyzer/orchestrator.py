from __future__ import annotations

import asyncio
import os
from typing import Any, Optional

from app.core.logging import get_logger
from app.services.analyzer.archive_analyzer import ArchiveAnalyzer
from app.services.analyzer.code_analyzer import CodeAnalyzer, CODE_EXTENSIONS
from app.services.analyzer.email_analyzer import EmailAnalyzer
from app.services.analyzer.exe_analyzer import ExecutableAnalyzer, PE_EXTENSIONS
from app.services.analyzer.image_analyzer import ImageAnalyzer
from app.services.analyzer.media_analyzer import MediaAnalyzer, AUDIO_EXTENSIONS, VIDEO_EXTENSIONS
from app.services.analyzer.office_analyzer import OfficeAnalyzer
from app.services.analyzer.pdf_analyzer import PdfAnalyzer
from app.services.analyzer.text_analyzer import TextAnalyzer, TEXT_EXTENSIONS

logger = get_logger(__name__)


class AnalysisOrchestrator:
    def __init__(self):
        self.analyzers: dict[str, Any] = {
            "pdf": PdfAnalyzer(),
            "office": OfficeAnalyzer(),
            "text": TextAnalyzer(),
            "code": CodeAnalyzer(),
            "image": ImageAnalyzer(),
            "media": MediaAnalyzer(),
            "executable": ExecutableAnalyzer(),
            "archive": ArchiveAnalyzer(),
            "email": EmailAnalyzer(),
        }

    def get_analyzer_for_file(self, filepath: str) -> Optional[tuple[str, Any]]:
        ext = os.path.splitext(filepath)[1].lower()
        basename = os.path.basename(filepath).lower()

        if ext == ".pdf":
            return ("pdf", self.analyzers["pdf"])
        elif ext in (".docx", ".docm", ".xlsx", ".xlsm", ".xlsb", ".pptx", ".pptm"):
            return ("office", self.analyzers["office"])
        elif ext in TEXT_EXTENSIONS:
            return ("text", self.analyzers["text"])
        elif ext in CODE_EXTENSIONS or basename in CODE_EXTENSIONS:
            return ("code", self.analyzers["code"])
        elif ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".svg", ".ico"):
            return ("image", self.analyzers["image"])
        elif ext in AUDIO_EXTENSIONS or ext in VIDEO_EXTENSIONS:
            return ("media", self.analyzers["media"])
        elif ext in PE_EXTENSIONS:
            return ("executable", self.analyzers["executable"])
        elif ext in (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"):
            return ("archive", self.analyzers["archive"])
        elif ext in (".msg", ".eml"):
            return ("email", self.analyzers["email"])
        else:
            return None

    async def analyze_file(self, filepath: str, mime_type: Optional[str] = None) -> dict[str, Any]:
        analyzer_info = self.get_analyzer_for_file(filepath)

        if analyzer_info is None:
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": "No analyzer available for this file type",
                "analyzer_type": "none",
            }

        analyzer_type, analyzer = analyzer_info
        file_metadata = {"path": filepath, "mime_type": mime_type}

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, analyzer.analyze, filepath, file_metadata)
            result["analyzer_type"] = analyzer_type
            return result
        except Exception as e:
            logger.error("Analysis failed for %s with %s analyzer: %s", filepath, analyzer_type, e)
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": str(e),
                "analyzer_type": analyzer_type,
            }
