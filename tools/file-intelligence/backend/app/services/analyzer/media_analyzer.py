from __future__ import annotations

import os
from typing import Any

from app.core.logging import get_logger
from app.services.analyzer.base import AnalysisResult, BaseAnalyzer

logger = get_logger(__name__)

AUDIO_EXTENSIONS = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".wma", ".aac"}
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm"}


class MediaAnalyzer(BaseAnalyzer):
    def analyze(self, filepath: str, file_metadata: dict) -> dict[str, Any]:
        ext = os.path.splitext(filepath)[1].lower()
        result = AnalysisResult()

        if ext in AUDIO_EXTENSIONS:
            return self._analyze_audio(filepath, result)
        elif ext in VIDEO_EXTENSIONS:
            return self._analyze_video(filepath, result)
        else:
            result.error = f"Unsupported media format: {ext}"
            return {
                "extracted_text": None,
                "metadata": None,
                "analysis_details": None,
                "error": result.error,
                "analyzer_type": "media",
            }

    def _analyze_audio(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            from mutagen import File as MutagenFile

            audio = MutagenFile(filepath)
            if audio is None:
                raise ValueError("Could not parse audio file")

            result.metadata = {
                "format": str(type(audio).__name__),
                "length_seconds": audio.info.length if hasattr(audio.info, "length") else 0,
                "bitrate": audio.info.bitrate if hasattr(audio.info, "bitrate") else 0,
                "sample_rate": audio.info.sample_rate if hasattr(audio.info, "sample_rate") else 0,
                "channels": audio.info.channels if hasattr(audio.info, "channels") else 0,
            }

            tags = {}
            if hasattr(audio, "tags") and audio.tags:
                for key, value in audio.tags.items():
                    tags[key] = str(value)
            result.metadata["tags"] = tags

        except ImportError:
            result.error = "mutagen not installed"
        except Exception as e:
            result.error = str(e)
            logger.warning("Audio analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "audio",
        }

    def _analyze_video(self, filepath: str, result: AnalysisResult) -> dict:
        try:
            from mutagen import File as MutagenFile
            from mutagen.mp4 import MP4

            try:
                video = MP4(filepath)
                result.metadata = {
                    "format": "MP4",
                    "length_seconds": video.info.length if hasattr(video.info, "length") else 0,
                    "bitrate": video.info.bitrate if hasattr(video.info, "bitrate") else 0,
                    "sample_rate": video.info.sample_rate if hasattr(video.info, "sample_rate") else 0,
                    "channels": video.info.channels if hasattr(video.info, "channels") else 0,
                }
                tags = {}
                for key, value in video.tags.items() if hasattr(video, "tags") and video.tags else []:
                    tags[key] = str(value)
                result.metadata["tags"] = tags
            except Exception:
                video = MutagenFile(filepath)
                if video:
                    result.metadata = {
                        "format": str(type(video).__name__),
                        "length_seconds": video.info.length if hasattr(video.info, "length") else 0,
                        "bitrate": video.info.bitrate if hasattr(video.info, "bitrate") else 0,
                    }

        except ImportError:
            result.error = "mutagen not installed"
        except Exception as e:
            result.error = str(e)
            logger.warning("Video analysis failed for %s: %s", filepath, e)

        return {
            "extracted_text": result.extracted_text,
            "metadata": result.metadata,
            "analysis_details": result.analysis_details,
            "error": result.error,
            "analyzer_type": "video",
        }
