from __future__ import annotations

import os
from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)


class ArchiveAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        ext = os.path.splitext(filepath)[1].lower()
        result = AnalysisResult()

        if ext == ".zip":
            return self._analyze_zip(filepath, result)
        elif ext == ".rar":
            return self._analyze_rar(filepath, result)
        elif ext == ".7z":
            return self._analyze_7z(filepath, result)
        elif ext in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
            return self._analyze_tar(filepath, result, ext)
        else:
            result.error = f"Unsupported archive format: {ext}"
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": result.error,
                "analyzer_type": "archive",
            }

    def _analyze_zip(self, filepath: str, result: AnalysisResult) -> dict:
        import zipfile

        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                entries: list[dict] = []
                total_compressed = 0
                total_uncompressed = 0

                for info in zf.infolist():
                    entries.append(
                        {
                            "filename": info.filename,
                            "size": info.file_size,
                            "compressed_size": info.compress_size,
                            "compress_ratio": round(
                                info.compress_size / info.file_size, 4
                            )
                            if info.file_size > 0
                            else 0,
                        }
                    )
                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size

                result.metadata = {
                    "format": "ZIP",
                    "entry_count": len(entries),
                    "total_compressed_size": total_compressed,
                    "total_uncompressed_size": total_uncompressed,
                    "entries": entries[:500],
                    "encrypted": any(info.flag_bits & 0x1 for info in zf.infolist()),
                }
        except Exception as e:
            result.error = str(e)
            logger.warning("ZIP analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "archive",
        }

    def _analyze_rar(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            import rarfile

            with rarfile.RarFile(filepath) as rf:
                entries: list[dict] = []
                total_compressed = 0
                total_uncompressed = 0

                for info in rf.infolist():
                    entries.append(
                        {
                            "filename": info.filename,
                            "size": info.file_size,
                            "compressed_size": info.compress_size,
                            "compress_ratio": round(
                                info.compress_size / info.file_size, 4
                            )
                            if info.file_size > 0
                            else 0,
                        }
                    )
                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size

                result.metadata = {
                    "format": "RAR",
                    "entry_count": len(entries),
                    "total_compressed_size": total_compressed,
                    "total_uncompressed_size": total_uncompressed,
                    "entries": entries[:500],
                }
        except Exception as e:
            result.error = str(e)
            logger.warning("RAR analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "archive",
        }

    def _analyze_7z(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            import py7zr

            with py7zr.SevenZipFile(filepath, "r") as szf:
                entries: list[dict] = []
                total_compressed = 0
                total_uncompressed = 0

                for info in szf.list():
                    entries.append(
                        {
                            "filename": info.filename,
                            "size": info.uncompressed or 0,
                            "compressed_size": info.compressed or 0,
                            "compress_ratio": round(
                                (info.compressed or 0) / (info.uncompressed or 1), 4
                            )
                            if (info.uncompressed or 0) > 0
                            else 0,
                        }
                    )
                    total_compressed += info.compressed or 0
                    total_uncompressed += info.uncompressed or 0

                result.metadata = {
                    "format": "7Z",
                    "entry_count": len(entries),
                    "total_compressed_size": total_compressed,
                    "total_uncompressed_size": total_uncompressed,
                    "entries": entries[:500],
                }
        except Exception as e:
            result.error = str(e)
            logger.warning("7Z analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "archive",
        }

    def _analyze_tar(self, filepath: str, result: AnalysisResult, ext: str) -> dict:
        import tarfile

        try:
            mode = "r"
            if ext == ".gz" or ext == ".tgz":
                mode = "r:gz"
            elif ext == ".bz2":
                mode = "r:bz2"
            elif ext == ".xz":
                mode = "r:xz"

            with tarfile.open(filepath, mode) as tf:
                entries: list[dict] = []
                total_size = 0

                for info in tf.getmembers():
                    entries.append(
                        {
                            "filename": info.name,
                            "size": info.size,
                            "type": "file" if info.isfile() else "directory",
                        }
                    )
                    total_size += info.size

                result.metadata = {
                    "format": f"TAR ({ext})",
                    "entry_count": len(entries),
                    "total_size": total_size,
                    "entries": entries[:500],
                }
        except Exception as e:
            result.error = str(e)
            logger.warning("TAR analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "archive",
        }
