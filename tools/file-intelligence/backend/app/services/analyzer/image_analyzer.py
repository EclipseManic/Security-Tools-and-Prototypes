from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)


class ImageAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        result = AnalysisResult()
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            img = Image.open(filepath)
            result.metadata = {
                "format": img.format or "",
                "mode": img.mode,
                "width": img.width,
                "height": img.height,
                "dpi": img.info.get("dpi", (0, 0)),
            }

            if hasattr(img, "n_frames"):
                result.metadata["frames"] = img.n_frames

            exif_data = None
            if hasattr(img, "_getexif"):
                try:
                    exif_data = img._getexif()
                except Exception:
                    pass

            if exif_data:
                exif_dict = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="replace")
                        except Exception:
                            value = str(value)
                    exif_dict[tag_name] = value

                result.metadata["exif"] = exif_dict

                gps_info = exif_data.get(34853)
                if gps_info:
                    result.metadata["has_gps"] = True

            result.analysis_details = {
                "has_exif": exif_data is not None,
                "has_icc_profile": "icc_profile" in img.info,
            }

            img.close()

        except ImportError:
            result.error = "Pillow not installed"
        except Exception as e:
            result.error = str(e)
            logger.warning("Image analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "ocr_text": result.ocr_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "image",
        }
