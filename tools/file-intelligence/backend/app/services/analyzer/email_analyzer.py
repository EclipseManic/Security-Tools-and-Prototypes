from __future__ import annotations

import os
from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)


class EmailAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        ext = os.path.splitext(filepath)[1].lower()
        result = AnalysisResult()

        if ext == ".msg":
            return self._analyze_msg(filepath, result)
        elif ext == ".eml":
            return self._analyze_eml(filepath, result)
        else:
            result.error = f"Unsupported email format: {ext}"
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": result.error,
                "analyzer_type": "email",
            }

    def _analyze_msg(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            from extract_msg import Message

            msg = Message(filepath)
            result.metadata = {
                "sender": msg.sender or "",
                "to": msg.to or "",
                "cc": msg.cc or "",
                "bcc": msg.bcc or "",
                "subject": msg.subject or "",
                "date": str(msg.date or ""),
            }

            body = msg.body or ""
            result.extracted_text = body

            attachments = []
            try:
                for attachment in msg.attachments:
                    attachments.append(
                        {
                            "name": attachment.longFilename or attachment.shortFilename or "unknown",
                            "size": attachment.dataSize if hasattr(attachment, "dataSize") else 0,
                        }
                    )
            except Exception:
                pass

            result.analysis_details = {
                "has_attachments": len(attachments) > 0,
                "attachment_count": len(attachments),
                "attachments": attachments[:50],
                "body_length": len(body),
            }

            msg.close()

        except ImportError:
            result.error = "extract_msg not installed"
        except Exception as e:
            result.error = str(e)
            logger.warning("MSG analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "email",
        }

    def _analyze_eml(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            from email import policy
            from email.parser import BytesParser

            with open(filepath, "rb") as f:
                msg = BytesParser(policy=policy.default).parse(f)

            result.metadata = {
                "sender": str(msg.get("From", "")),
                "to": str(msg.get("To", "")),
                "cc": str(msg.get("Cc", "")),
                "subject": str(msg.get("Subject", "")),
                "date": str(msg.get("Date", "")),
                "message_id": str(msg.get("Message-ID", "")),
            }

            body_parts: list[str] = []
            attachments: list[dict] = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        try:
                            body_parts.append(part.get_content())
                        except Exception:
                            pass
                    elif content_type == "text/html":
                        try:
                            body_parts.append(part.get_content())
                        except Exception:
                            pass
                    elif part.get_filename():
                        attachments.append(
                            {
                                "name": part.get_filename(),
                                "content_type": content_type,
                            }
                        )
            else:
                body_parts.append(str(msg.get_content() or ""))

            result.extracted_text = "\n".join(body_parts)
            result.analysis_details = {
                "has_attachments": len(attachments) > 0,
                "attachment_count": len(attachments),
                "attachments": attachments[:50],
                "body_length": len(result.extracted_text or ""),
            }

        except Exception as e:
            result.error = str(e)
            logger.warning("EML analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "email",
        }
