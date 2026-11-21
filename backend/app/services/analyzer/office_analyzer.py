from __future__ import annotations

import os
from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)


class OfficeAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        ext = os.path.splitext(filepath)[1].lower()
        result = AnalysisResult()

        if ext in (".docx", ".docm"):
            return self._analyze_word(filepath, result)
        elif ext in (".xlsx", ".xlsm", ".xlsb"):
            return self._analyze_excel(filepath, result)
        elif ext in (".pptx", ".pptm"):
            return self._analyze_powerpoint(filepath, result)
        else:
            result.error = f"Unsupported office format: {ext}"
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": result.error,
                "analyzer_type": "office",
            }

    def _analyze_word(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            import docx

            doc = docx.Document(filepath)

            text_parts: list[str] = []
            for para in doc.paragraphs:
                if para.text.strip():
                    text_parts.append(para.text)

            tables_text: list[str] = []
            for table in doc.tables:
                for row in table.rows:
                    cells = [cell.text.strip() for cell in row.cells]
                    tables_text.append(" | ".join(cells))

            result.extracted_text = "\n".join(text_parts + tables_text)

            core_props = doc.core_properties
            result.metadata = {
                "author": core_props.author or "",
                "title": core_props.title or "",
                "subject": core_props.subject or "",
                "company": getattr(core_props, "company", "") or "",
                "category": core_props.category or "",
                "created": str(core_props.created or ""),
                "modified": str(core_props.modified or ""),
                "revision": core_props.revision or 0,
                "page_count": len(doc.sections),
                "paragraph_count": len(doc.paragraphs),
                "table_count": len(doc.tables),
            }

            comments = []
            try:
                for comment in doc.comments:
                    comments.append(
                        {
                            "author": comment.author,
                            "text": comment.text.strip(),
                        }
                    )
                if comments:
                    result.analysis_details = {"comments": comments}
            except Exception:
                pass

        except Exception as e:
            result.error = str(e)
            logger.warning("Word analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "word",
        }

    def _analyze_excel(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            import openpyxl

            wb = openpyxl.load_workbook(filepath, data_only=True, read_only=True)

            all_text: list[str] = []
            sheet_info: list[dict] = []

            for sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                sheet_data: list[str] = []
                row_count = 0
                for row in ws.iter_rows(values_only=True):
                    row_text = [
                        str(cell).strip()
                        for cell in row
                        if cell is not None and str(cell).strip()
                    ]
                    if row_text:
                        sheet_data.append(" | ".join(row_text))
                    row_count += 1

                all_text.extend(sheet_data)
                sheet_info.append(
                    {
                        "name": sheet_name,
                        "rows": row_count,
                        "columns": ws.max_column or 0,
                    }
                )

            result.extracted_text = "\n".join(all_text)
            result.metadata = {
                "sheet_count": len(wb.sheetnames),
                "sheets": sheet_info,
            }

        except Exception as e:
            result.error = str(e)
            logger.warning("Excel analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "excel",
        }

    def _analyze_powerpoint(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            import pptx

            prs = pptx.Presentation(filepath)

            text_parts: list[str] = []
            slide_info: list[dict] = []

            for i, slide in enumerate(prs.slides):
                slide_text: list[str] = []
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        for para in shape.text_frame.paragraphs:
                            if para.text.strip():
                                slide_text.append(para.text.strip())

                    if shape.has_table:
                        table = shape.table
                        for row in table.rows:
                            cells = [cell.text.strip() for cell in row.cells]
                            slide_text.append(" | ".join(cells))

                text_parts.extend(slide_text)
                slide_info.append(
                    {
                        "slide_number": i + 1,
                        "text_length": sum(len(t) for t in slide_text),
                    }
                )

            result.extracted_text = "\n".join(text_parts)
            result.metadata = {
                "slide_count": len(prs.slides),
                "slides": slide_info,
            }

        except Exception as e:
            result.error = str(e)
            logger.warning("PowerPoint analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "powerpoint",
        }
