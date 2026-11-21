from __future__ import annotations

import os
from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)

PE_EXTENSIONS = {".exe", ".dll", ".scr", ".cpl", ".ocx", ".sys"}


class ExecutableAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        ext = os.path.splitext(filepath)[1].lower()
        result = AnalysisResult()

        if ext in PE_EXTENSIONS:
            return self._analyze_pe(filepath, result)
        else:
            result.error = f"Unsupported executable format: {ext}"
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": result.error,
                "analyzer_type": "executable",
            }

    def _analyze_pe(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            import pefile

            pe = pefile.PE(filepath)
            try:
                result.metadata = {
                    "image_base": hex(pe.OPTIONAL_HEADER.ImageBase) if hasattr(pe, "OPTIONAL_HEADER") else "",
                    "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, "OPTIONAL_HEADER") else "",
                    "subsystem": pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, "OPTIONAL_HEADER") else 0,
                    "compile_time": str(pe.FILE_HEADER.TimeDateStamp) if hasattr(pe, "FILE_HEADER") else "",
                }

                has_signature = False
                digital_signer = None
                try:
                    if hasattr(pe, "DIRECTORY_ENTTRY_SECURITY"):
                        has_signature = True
                except Exception:
                    pass

                result.metadata["has_signature"] = has_signature
                result.metadata["digital_signer"] = digital_signer

                imports: list[dict] = []
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_imports = []
                        if hasattr(entry, "imports"):
                            for imp in entry.imports:
                                if imp.name:
                                    dll_imports.append(imp.name.decode("utf-8", errors="replace"))
                        imports.append(
                            {
                                "dll": entry.dll.decode("utf-8", errors="replace") if entry.dll else "",
                                "functions": dll_imports[:50],
                            }
                        )
                result.metadata["imports"] = imports

                sections: list[dict] = []
                for section in pe.sections:
                    sections.append(
                        {
                            "name": section.Name.decode("utf-8", errors="replace").strip("\x00"),
                            "size": section.SizeOfRawData,
                            "entropy": section.get_entropy(),
                            "characteristics": hex(section.Characteristics),
                        }
                    )
                result.metadata["sections"] = sections

                version_info = {}
                if hasattr(pe, "VS_VERSIONINFO"):
                    try:
                        for info in pe.VS_VERSIONINFO:
                            if hasattr(info, "StringFileInfo"):
                                for st in info.StringFileInfo:
                                    for entry in st.entries:
                                        for k, v in entry.items():
                                            key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                                            val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                                            version_info[key] = val
                    except Exception:
                        pass

                result.metadata["version_info"] = version_info

            finally:
                pe.close()

        except ImportError:
            result.error = "pefile not installed"
        except Exception as e:
            result.error = str(e)
            logger.warning("PE analysis failed for %s: %s", filepath, e)

        metadata = result.metadata or {}
        details = {
            "image_base": metadata.get("image_base"),
            "entry_point": metadata.get("entry_point"),
            "subsystem": metadata.get("subsystem"),
            "compile_time": metadata.get("compile_time"),
            "has_signature": metadata.get("has_signature", False),
            "digital_signer": metadata.get("digital_signer"),
            "section_count": len(metadata.get("sections", [])),
            "sections": [
                {"name": s.get("name"), "size": s.get("size"), "entropy": round(s.get("entropy", 0), 2)}
                for s in metadata.get("sections", [])
            ],
            "import_count": sum(len(i.get("functions", [])) for i in metadata.get("imports", [])),
            "imports": [
                {"dll": i.get("dll"), "function_count": len(i.get("functions", []))}
                for i in metadata.get("imports", [])
            ],
            "version_info": metadata.get("version_info", {}),
        }

        return {
            "extracted_text": result.extracted_text,
            "metadata": metadata,
            "analysis_details": details,
            "error": result.error,
            "analyzer_type": "executable",
        }
