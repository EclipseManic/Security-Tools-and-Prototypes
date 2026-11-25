from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)


class PdfAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        result = AnalysisResult()
        try:
            import fitz

            doc = fitz.open(filepath)
            try:
                result.metadata = {
                    "title": doc.metadata.get("title", ""),
                    "author": doc.metadata.get("author", ""),
                    "subject": doc.metadata.get("subject", ""),
                    "producer": doc.metadata.get("producer", ""),
                    "creator": doc.metadata.get("creator", ""),
                    "page_count": doc.page_count,
                    "encrypted": doc.needs_pass,
                    "format": getattr(doc, "format", "") or "",
                }

                text_parts: list[str] = []
                urls: list[str] = []
                embedded_images: list[dict] = []

                for page_num in range(doc.page_count):
                    page = doc[page_num]
                    text_parts.append(page.get_text())

                    for link in page.get_links():
                        if link.get("uri"):
                            urls.append(link["uri"])

                result.extracted_text = "\n".join(text_parts)

                result.analysis_details = {
                    "page_count": doc.page_count,
                    "urls_found": len(urls),
                    "image_count": len(embedded_images),
                    "urls": urls[:100],
                }

                try:
                    embfile_count = doc.embfile_count()
                    if embfile_count > 0:
                        attachments = []
                        for i in range(embfile_count):
                            emb = doc.embfile_get(i)
                            attachments.append(
                                {
                                    "name": emb.get("name", f"attachment_{i}"),
                                    "size": doc.embfile_size(i),
                                }
                            )
                        result.analysis_details["attachments"] = attachments
                except Exception:
                    pass

                try:
                    if hasattr(doc, "get_javascript"):
                        javascript = doc.get_javascript()
                        if javascript:
                            result.analysis_details["javascript_found"] = True
                            result.analysis_details["javascript"] = javascript[:5000]
                except Exception:
                    pass

            finally:
                doc.close()

        except ImportError:
            result.error = "PyMuPDF not installed"
        except Exception as e:
            result.error = str(e)
            logger.warning("PDF analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "pdf",
        }
