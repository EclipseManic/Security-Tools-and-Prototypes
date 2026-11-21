from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ScanCancelledError
from app.core.logging import get_logger
from app.models.file import (
    FileCategory, FileContent, FileAnalysis, FileRecord, ScanJob,
    FileSensitivity, EntityExtraction, SensitiveFinding, FileTimeline,
)

from app.services.analyzer.orchestrator import AnalysisOrchestrator
from app.services.ai.intelligence_service import IntelligenceService
from app.services.scanner.base import ScanState
from app.services.scanner.directory_scanner import DirectoryScanner

logger = get_logger(__name__)


def _sanitize_json(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, tuple):
        return [_sanitize_json(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _sanitize_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_json(v) for v in obj]
    if isinstance(obj, set):
        return list(obj)
    return obj


EXTENSION_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    ".py": ("Source Code", "Python"),
    ".js": ("Source Code", "JavaScript"),
    ".jsx": ("Source Code", "React JSX"),
    ".ts": ("Source Code", "TypeScript"),
    ".tsx": ("Source Code", "React TSX"),
    ".java": ("Source Code", "Java"),
    ".c": ("Source Code", "C"),
    ".cpp": ("Source Code", "C++"),
    ".h": ("Source Code", "C/C++ Header"),
    ".hpp": ("Source Code", "C++ Header"),
    ".cs": ("Source Code", "C#"),
    ".go": ("Source Code", "Go"),
    ".rs": ("Source Code", "Rust"),
    ".rb": ("Source Code", "Ruby"),
    ".php": ("Source Code", "PHP"),
    ".swift": ("Source Code", "Swift"),
    ".kt": ("Source Code", "Kotlin"),
    ".scala": ("Source Code", "Scala"),
    ".r": ("Source Code", "R"),
    ".m": ("Source Code", "Objective-C"),
    ".mm": ("Source Code", "Objective-C++"),
    ".pl": ("Source Code", "Perl"),
    ".sh": ("Source Code", "Shell"),
    ".bash": ("Source Code", "Bash"),
    ".zsh": ("Source Code", "Zsh"),
    ".ps1": ("Source Code", "PowerShell"),
    ".sql": ("Source Code", "SQL"),
    ".html": ("Source Code", "HTML"),
    ".htm": ("Source Code", "HTML"),
    ".css": ("Source Code", "CSS"),
    ".scss": ("Source Code", "SCSS"),
    ".less": ("Source Code", "Less"),
    ".vue": ("Source Code", "Vue"),
    ".svelte": ("Source Code", "Svelte"),
    ".astro": ("Source Code", "Astro"),
    ".tf": ("Source Code", "Terraform"),
    ".yaml": ("Configuration", "YAML"),
    ".yml": ("Configuration", "YAML"),
    ".toml": ("Configuration", "TOML"),
    ".ini": ("Configuration", "INI"),
    ".cfg": ("Configuration", "Config"),
    ".conf": ("Configuration", "Config"),
    ".json": ("Configuration", "JSON"),
    ".xml": ("Configuration", "XML"),
    ".env": ("Configuration", "Environment"),
    ".dockerfile": ("Configuration", "Dockerfile"),
    ".pdf": ("Document", "PDF"),
    ".docx": ("Document", "Word"),
    ".docm": ("Document", "Word Macro-Enabled"),
    ".xlsx": ("Document", "Excel"),
    ".xlsm": ("Document", "Excel Macro-Enabled"),
    ".xlsb": ("Document", "Excel Binary"),
    ".pptx": ("Document", "PowerPoint"),
    ".pptm": ("Document", "PowerPoint Macro-Enabled"),
    ".doc": ("Document", "Word Legacy"),
    ".xls": ("Document", "Excel Legacy"),
    ".ppt": ("Document", "PowerPoint Legacy"),
    ".odt": ("Document", "OpenDocument Text"),
    ".ods": ("Document", "OpenDocument Spreadsheet"),
    ".odp": ("Document", "OpenDocument Presentation"),
    ".rtf": ("Document", "Rich Text"),
    ".txt": ("Document", "Plain Text"),
    ".md": ("Document", "Markdown"),
    ".csv": ("Document", "CSV"),
    ".epub": ("Document", "eBook"),
    ".jpg": ("Image", "JPEG"),
    ".jpeg": ("Image", "JPEG"),
    ".png": ("Image", "PNG"),
    ".gif": ("Image", "GIF"),
    ".bmp": ("Image", "Bitmap"),
    ".tiff": ("Image", "TIFF"),
    ".tif": ("Image", "TIFF"),
    ".webp": ("Image", "WebP"),
    ".svg": ("Image", "SVG"),
    ".ico": ("Image", "Icon"),
    ".heic": ("Image", "HEIC"),
    ".heif": ("Image", "HEIF"),
    ".raw": ("Image", "Raw"),
    ".psd": ("Image", "Photoshop"),
    ".ai": ("Image", "Adobe Illustrator"),
    ".mp4": ("Video", "MP4"),
    ".mkv": ("Video", "MKV"),
    ".avi": ("Video", "AVI"),
    ".mov": ("Video", "QuickTime"),
    ".wmv": ("Video", "WMV"),
    ".flv": ("Video", "Flash Video"),
    ".webm": ("Video", "WebM"),
    ".m4v": ("Video", "M4V"),
    ".mpg": ("Video", "MPEG"),
    ".mpeg": ("Video", "MPEG"),
    ".mp3": ("Audio", "MP3"),
    ".wav": ("Audio", "WAV"),
    ".flac": ("Audio", "FLAC"),
    ".aac": ("Audio", "AAC"),
    ".ogg": ("Audio", "OGG"),
    ".wma": ("Audio", "WMA"),
    ".m4a": ("Audio", "M4A"),
    ".opus": ("Audio", "Opus"),
    ".exe": ("Executable", "Windows PE"),
    ".dll": ("Executable", "Windows DLL"),
    ".msi": ("Executable", "Windows Installer"),
    ".bin": ("Executable", "Binary"),
    ".elf": ("Executable", "ELF"),
    ".app": ("Executable", "macOS App"),
    ".dmg": ("Executable", "macOS Disk Image"),
    ".deb": ("Executable", "Debian Package"),
    ".rpm": ("Executable", "RPM Package"),
    ".apk": ("Executable", "Android APK"),
    ".ipa": ("Executable", "iOS IPA"),
    ".zip": ("Archive", "ZIP"),
    ".rar": ("Archive", "RAR"),
    ".7z": ("Archive", "7-Zip"),
    ".tar": ("Archive", "TAR"),
    ".gz": ("Archive", "GZip"),
    ".tgz": ("Archive", "TGZ"),
    ".bz2": ("Archive", "BZip2"),
    ".xz": ("Archive", "XZ"),
    ".zst": ("Archive", "Zstandard"),
    ".iso": ("Archive", "ISO Image"),
    ".cab": ("Archive", "Cabinet"),
    ".eml": ("Email", "Email Message"),
    ".msg": ("Email", "Outlook Message"),
    ".pst": ("Email", "Outlook PST"),
    ".ost": ("Email", "Outlook OST"),
    ".log": ("Logs", "Log File"),
    ".syslog": ("Logs", "Syslog"),
    ".db": ("Database", "Database"),
    ".sqlite": ("Database", "SQLite"),
    ".sqlite3": ("Database", "SQLite"),
    ".mdb": ("Database", "Access"),
    ".bak": ("Backups", "Backup"),
    ".backup": ("Backups", "Backup"),
    ".old": ("Backups", "Legacy Backup"),
    ".tmp": ("Other", "Temporary"),
    ".temp": ("Other", "Temporary"),
    ".lnk": ("Other", "Shortcut"),
    ".desktop": ("Other", "Desktop Entry"),
    ".part": ("Other", "Partial Download"),
    ".crdownload": ("Other", "Chrome Download"),
}


def _categorize_by_extension(filepath: str) -> tuple[str, str]:
    ext = os.path.splitext(filepath)[1].lower()
    basename = os.path.basename(filepath).lower()
    if ext in EXTENSION_CATEGORY_MAP:
        return EXTENSION_CATEGORY_MAP[ext]
    if basename in ("makefile", "cmakelists.txt", "gemfile", "rakefile"):
        return ("Source Code", basename.title())
    if basename == "dockerfile":
        return ("Configuration", "Dockerfile")
    return ("Other", ext.upper().lstrip(".") if ext else "Unknown")


class ScanService:
    _active_scans: dict[int, DirectoryScanner] = {}

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_scan_job(self, path: str, scan_type: str = "full") -> ScanJob:
        job = ScanJob(
            scan_type=scan_type,
            path=path,
            status="pending",
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def start_scan(self, scan_job_id: int) -> None:
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            raise ValueError(f"Scan job {scan_job_id} not found")

        path = job.path
        if not os.path.exists(path):
            job.status = "failed"
            await self.db.commit()
            raise ValueError(f"Scan path does not exist: {path}")

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await self.db.commit()

        scanner = DirectoryScanner(
            path=path,
            thread_count=settings.scan_default_threads,
            batch_size=settings.scan_batch_size,
            exclude_dirs=settings.scan_exclude_dirs,
        )
        ScanService._active_scans[scan_job_id] = scanner

        try:
            scanned_files = await scanner.scan()

            # Snapshot previous records BEFORE persist overwrites them (Option 2)
            previous_records: dict[str, FileRecord] = {}
            paths = [f["path"] for f in scanned_files if f.get("path")]
            for i in range(0, len(paths), 500):
                batch = paths[i:i + 500]
                result = await self.db.execute(
                    select(FileRecord).where(FileRecord.path.in_(batch))
                )
                for rec in result.scalars().all():
                    previous_records[rec.path] = rec

            await self._persist_files(scanned_files, scan_job_id)

            await self._analyze_files(scanned_files, job, previous_records)

            job.status = "completed"
            job.total_files = scanner.progress.total_files
            job.scanned_files = len(scanned_files)
            job.progress = 100.0
            job.error_count = scanner.progress.error_count
            job.completed_at = datetime.now(timezone.utc)
            await self.db.commit()

            logger.info(
                "Scan job %d completed: %d files indexed",
                scan_job_id,
                len(scanned_files),
            )

        except ScanCancelledError:
            job.status = "cancelled"
            await self.db.commit()
            logger.info("Scan job %d cancelled", scan_job_id)

        except Exception as e:
            job.status = "failed"
            job.error_count = scanner.progress.error_count
            await self.db.commit()
            logger.error("Scan job %d failed: %s", scan_job_id, e)

        finally:
            ScanService._active_scans.pop(scan_job_id, None)

    async def _persist_files(
        self, scanned_files: list[dict], scan_job_id: int
    ) -> None:
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        BATCH_SIZE = 500
        now = datetime.now(timezone.utc)

        for i in range(0, len(scanned_files), BATCH_SIZE):
            batch = scanned_files[i:i + BATCH_SIZE]
            stmt = sqlite_insert(FileRecord)
            stmt = stmt.on_conflict_do_update(
                index_elements=["path"],
                set_={
                    "name": stmt.excluded.name,
                    "extension": stmt.excluded.extension,
                    "size": stmt.excluded.size,
                    "mime_type": stmt.excluded.mime_type,
                    "magic_bytes": stmt.excluded.magic_bytes,
                    "created_at": stmt.excluded.created_at,
                    "modified_at": stmt.excluded.modified_at,
                    "accessed_at": stmt.excluded.accessed_at,
                    "owner": stmt.excluded.owner,
                    "permissions": stmt.excluded.permissions,
                    "is_hidden": stmt.excluded.is_hidden,
                    "is_system": stmt.excluded.is_system,
                    "is_readonly": stmt.excluded.is_readonly,
                    "is_symlink": stmt.excluded.is_symlink,
                    "volume": stmt.excluded.volume,
                    "sha256": stmt.excluded.sha256,
                    "md5": stmt.excluded.md5,
                    "entropy": stmt.excluded.entropy,
                    "last_scanned_at": now,
                    "scan_id": scan_job_id,
                },
            )
            values = [
                {
                    "path": f.get("path", ""),
                    "name": f.get("name", ""),
                    "extension": f.get("extension"),
                    "size": f.get("size", 0),
                    "mime_type": f.get("mime_type"),
                    "magic_bytes": f.get("magic_bytes"),
                    "created_at": f.get("created_at"),
                    "modified_at": f.get("modified_at"),
                    "accessed_at": f.get("accessed_at"),
                    "owner": f.get("owner"),
                    "permissions": f.get("permissions"),
                    "is_hidden": f.get("is_hidden", False),
                    "is_system": f.get("is_system", False),
                    "is_readonly": f.get("is_readonly", False),
                    "is_symlink": f.get("is_symlink", False),
                    "volume": f.get("volume"),
                    "sha256": f.get("sha256"),
                    "md5": f.get("md5"),
                    "entropy": f.get("entropy"),
                    "scan_id": scan_job_id,
                    "first_scanned_at": f.get("first_scanned_at", now),
                    "last_scanned_at": now,
                }
                for f in batch
            ]
            await self.db.execute(stmt, values)

        await self.db.commit()

    async def _analyze_files(self, scanned_files: list[dict], job: ScanJob,
                              previous_records: dict[str, FileRecord] | None = None) -> None:
        from app.services.detector.sensitive_data_detector import SensitiveDataDetector
        from app.services.ai.anonymized_batch_analyzer import AnonymizedBatchAnalyzer, _size_to_range
        from app.services.analyzer.exe_analyzer import PE_EXTENSIONS
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        orchestrator = AnalysisOrchestrator()
        intelligence = IntelligenceService()
        detector = SensitiveDataDetector()
        ai_available = await intelligence.is_available()

        max_exe_skip_size = 50 * 1024 * 1024
        per_file_timeout = 50.0
        io_concurrency = 8
        total = len(scanned_files)

        if previous_records is None:
            previous_records = {}

        # ── Phase A: Concurrent I/O (no DB access) ─────────────────────────
        sem = asyncio.Semaphore(io_concurrency)
        io_results: list[dict | None] = [None] * total
        cancelled = False
        io_done = 0
        loop = asyncio.get_running_loop()

        async def _io_worker(file_data: dict, idx: int) -> None:
            nonlocal cancelled, io_done
            if cancelled:
                return

            filepath = file_data.get("path", "")
            file_size = file_data.get("size", 0)
            if not filepath or not os.path.isfile(filepath):
                return
            if file_size == 0:
                return

            # Cancel/pause
            scanner = ScanService._active_scans.get(job.id)
            if scanner and scanner._cancelled:
                cancelled = True
                return
            if scanner and scanner._state == ScanState.paused:
                while scanner._state == ScanState.paused and not scanner._cancelled:
                    await asyncio.sleep(0.5)

            async with sem:
                ext_lower = os.path.splitext(filepath)[1].lower()

                # Option 2: skip if file unchanged since last scan
                prev = previous_records.get(filepath)
                if prev and prev.sha256:
                    curr_mod = file_data.get("modified_at")
                    prev_mod = prev.modified_at
                    if curr_mod and prev_mod:
                        if isinstance(curr_mod, (int, float)):
                            curr_mod_dt = datetime.fromtimestamp(curr_mod, tz=timezone.utc)
                        else:
                            curr_mod_dt = curr_mod.replace(tzinfo=timezone.utc) if curr_mod.tzinfo is None else curr_mod
                        if prev_mod.tzinfo is None:
                            prev_mod = prev_mod.replace(tzinfo=timezone.utc)
                        if prev_mod == curr_mod_dt:
                            io_results[idx] = {"_tag": "skip_unchanged", "path": filepath,
                                               "file_size": file_size, "prev": prev,
                                               "mime_type": file_data.get("mime_type"),
                                               "name": file_data.get("name", os.path.basename(filepath))}
                            io_done += 1
                            return

                # Option 4: skip analyzer for large executables (>50MB)
                if file_size > max_exe_skip_size and ext_lower in PE_EXTENSIONS:
                    io_results[idx] = {"_tag": "skip_large_exe", "path": filepath,
                                       "file_size": file_size, "prev": prev,
                                       "mime_type": file_data.get("mime_type"),
                                       "name": file_data.get("name", os.path.basename(filepath))}
                    io_done += 1
                    return

                # Option 5: run analyzer with timeout
                try:
                    result = await asyncio.wait_for(
                        orchestrator.analyze_file(filepath, file_data.get("mime_type")),
                        timeout=per_file_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning("Analysis timed out for %s", filepath)
                    io_results[idx] = {"_tag": "timeout", "path": filepath,
                                       "file_size": file_size, "prev": prev,
                                       "mime_type": file_data.get("mime_type"),
                                       "name": file_data.get("name", os.path.basename(filepath))}
                    io_done += 1
                    return
                except Exception as e:
                    logger.warning("Analyzer failed for %s: %s", filepath, e)
                    io_results[idx] = {"_tag": "error", "path": filepath,
                                       "file_size": file_size, "prev": prev,
                                       "mime_type": file_data.get("mime_type"),
                                       "name": file_data.get("name", os.path.basename(filepath))}
                    io_done += 1
                    return

                extracted_text = result.get("extracted_text") or ""

                # Run detector in thread pool — doesn't block event loop
                detection_result = None
                if extracted_text:
                    detection_result = await loop.run_in_executor(
                        None, detector.analyze, extracted_text, file_data.get("name", "")
                    )

                io_results[idx] = {"_tag": "done", "path": filepath,
                                   "result": result, "extracted_text": extracted_text,
                                   "detection_result": detection_result,
                                   "file_size": file_size, "prev": prev,
                                   "mime_type": file_data.get("mime_type"),
                                   "name": file_data.get("name", os.path.basename(filepath))}
                io_done += 1
                if io_done % 5 == 0:
                    job.progress = 50.0 + (io_done / max(total, 1)) * 35.0
                    await self.db.commit()

        await asyncio.gather(
            *[_io_worker(fd, i) for i, fd in enumerate(scanned_files)],
            return_exceptions=True,
        )

        if cancelled:
            raise ScanCancelledError("Scan cancelled during analysis")

        # ── Phase B: Sequential DB writes + build summaries ─────────────────
        collected_summaries: list[dict] = []
        db_written = 0

        for idx, file_data in enumerate(scanned_files):
            io_res = io_results[idx]
            if io_res is None:
                continue

            filepath = io_res["path"]
            file_size = io_res["file_size"]
            tag = io_res.get("_tag", "done")

            # ── skipped / timed-out / errored (no analyzer output) ─────
            if tag in ("skip_unchanged", "skip_large_exe", "timeout", "error"):
                prev: FileRecord | None = io_res.get("prev")
                rec = prev
                if not rec:
                    r = await self.db.execute(select(FileRecord).where(FileRecord.path == filepath))
                    rec = r.scalar_one_or_none()
                if rec and rec.sha256:
                    ext_out = os.path.splitext(filepath)[1].lower()
                    cat_out, _ = _categorize_by_extension(filepath)
                    collected_summaries.append({
                        "dummy_id": f"f_{len(collected_summaries):04d}",
                        "path": filepath,
                        "name": io_res.get("name", os.path.basename(filepath)),
                        "ext": ext_out, "size_range": _size_to_range(file_size),
                        "category": cat_out, "sha256": rec.sha256,
                        "analyzer_type": tag, "findings_types": [],
                        "has_text": False,
                        "mime_group": (io_res.get("mime_type") or "unknown").split("/")[0],
                    })
                continue

            # ── successfully analyzed ──────────────────────────────────
            result = io_res.get("result")
            if not result:
                continue
            if not (result.get("extracted_text") or result.get("metadata") or result.get("analysis_details")):
                continue

            # Fetch the FileRecord (from snapshot or fresh query)
            file_record: FileRecord | None = io_res.get("prev")
            if not file_record:
                r = await self.db.execute(select(FileRecord).where(FileRecord.path == filepath))
                file_record = r.scalar_one_or_none()
            if not file_record:
                continue

            metadata = result.get("metadata")
            analysis_details = result.get("analysis_details")
            extracted_text = io_res.get("extracted_text", "")
            detection_result = io_res.get("detection_result")

            # FileContent
            stmt = sqlite_insert(FileContent).values(
                file_id=file_record.id,
                extracted_text=extracted_text or None,
                raw_metadata=_sanitize_json(metadata),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["file_id"],
                set_={
                    "extracted_text": stmt.excluded.extracted_text,
                    "raw_metadata": stmt.excluded.raw_metadata,
                },
            )
            await self.db.execute(stmt)

            # FileAnalysis
            analysis_record = FileAnalysis(
                file_id=file_record.id,
                analyzer_type=result.get("analyzer_type", "unknown"),
                status="completed" if result.get("error") is None else "failed",
                result=analysis_details,
                error_message=result.get("error"),
            )
            self.db.add(analysis_record)

            if metadata and metadata.get("mime_type"):
                file_record.mime_type = metadata["mime_type"]

            # FileCategory
            category, subcategory = _categorize_by_extension(filepath)
            cat_stmt = sqlite_insert(FileCategory).values(
                file_id=file_record.id,
                category=category, subcategory=subcategory,
                confidence=1.0, explanation="Categorized by file extension",
            )
            cat_stmt = cat_stmt.on_conflict_do_update(
                index_elements=["file_id"],
                set_={
                    "category": cat_stmt.excluded.category,
                    "subcategory": cat_stmt.excluded.subcategory,
                    "confidence": cat_stmt.excluded.confidence,
                    "explanation": cat_stmt.excluded.explanation,
                },
            )
            await self.db.execute(cat_stmt)

            # Sensitive findings
            if detection_result:
                if detection_result.get("findings"):
                    for finding in detection_result["findings"]:
                        sf = SensitiveFinding(
                            file_id=file_record.id,
                            finding_type=finding["finding_type"],
                            value=finding.get("value", ""),
                            context=finding.get("context", ""),
                            count=finding.get("count", 1),
                            severity=finding.get("severity", "medium"),
                        )
                        self.db.add(sf)

                if detection_result.get("risk_score", 0) > 0:
                    fs_stmt = sqlite_insert(FileSensitivity).values(
                        file_id=file_record.id,
                        sensitivity_level=detection_result.get("sensitivity_level", "Public"),
                        risk_score=detection_result.get("risk_score", 0),
                        explanation=detection_result.get("explanation", ""),
                    )
                    fs_stmt = fs_stmt.on_conflict_do_update(
                        index_elements=["file_id"],
                        set_={
                            "sensitivity_level": fs_stmt.excluded.sensitivity_level,
                            "risk_score": fs_stmt.excluded.risk_score,
                            "explanation": fs_stmt.excluded.explanation,
                        },
                    )
                    await self.db.execute(fs_stmt)

            ext_out = os.path.splitext(filepath)[1].lower()
            mime_group = (metadata or {}).get("mime_type", "unknown").split("/")[0] if (metadata or {}).get("mime_type") else "unknown"
            findings_types = [f["finding_type"] for f in (detection_result or {}).get("findings", [])]

            collected_summaries.append({
                "dummy_id": f"f_{len(collected_summaries):04d}",
                "path": filepath,
                "name": file_data.get("name", os.path.basename(filepath)),
                "ext": ext_out, "size_range": _size_to_range(file_size),
                "category": category, "sha256": file_record.sha256,
                "analyzer_type": result.get("analyzer_type", "unknown"),
                "findings_types": findings_types,
                "has_text": bool(extracted_text),
                "mime_group": mime_group,
            })

            db_written += 1
            if db_written % 10 == 0:
                await self.db.commit()
            if db_written % 5 == 0:
                job.progress = 85.0 + (db_written / max(total, 1)) * 10.0
                await self.db.commit()

        await self.db.commit()
        job.progress = 95.0
        await self.db.commit()

        # Every indexed file must have a category, even when no analyzer
        # produced content (for example, an image format the analyzer cannot
        # decode). This also repairs files from older scans.
        uncategorized = (
            await self.db.execute(
                select(FileRecord)
                .outerjoin(FileCategory, FileCategory.file_id == FileRecord.id)
                .where(FileCategory.file_id.is_(None))
            )
        ).scalars().all()
        if uncategorized:
            for record in uncategorized:
                category_name, subcategory_name = _categorize_by_extension(record.path)
                await self.db.execute(
                    sqlite_insert(FileCategory)
                    .values(
                        file_id=record.id,
                        category=category_name,
                        subcategory=subcategory_name,
                        confidence=1.0,
                        explanation="Categorized by file extension",
                    )
                    .on_conflict_do_nothing(index_elements=["file_id"])
                )
            await self.db.commit()

        # ── Batch AI analysis ─────────────────────────────────────────────
        if collected_summaries and ai_available:
            try:
                backup_intel = None
                if os.getenv("GEMINI_API_KEY"):
                    from app.services.ai.gemini_provider import GeminiProvider
                    backup_svc = IntelligenceService()
                    backup_svc._provider = GeminiProvider()
                    backup_intel = backup_svc
                batch_analyzer = AnonymizedBatchAnalyzer(self.db, intelligence, backup_intel)
                batch_results = await batch_analyzer.analyze(collected_summaries, job.id)
                if batch_results:
                    await self.db.commit()
                    logger.info("Batch AI analysis completed for scan %d", job.id)
            except Exception as e:
                logger.warning("Batch AI analysis failed for scan %d: %s", job.id, e)
                await self.db.rollback()

    async def pause_scan(self, scan_job_id: int) -> bool:
        scanner = ScanService._active_scans.get(scan_job_id)
        if scanner:
            scanner.pause()
            for attempt in range(5):
                try:
                    result = await self.db.execute(
                        select(ScanJob).where(ScanJob.id == scan_job_id)
                    )
                    job = result.scalar_one_or_none()
                    if job:
                        job.status = "paused"
                        await self.db.commit()
                    return True
                except Exception:
                    if attempt < 4:
                        await asyncio.sleep(0.2)
                    else:
                        logger.warning("Could not persist pause status for scan %d (DB busy)", scan_job_id)
            return True
        return False

    async def resume_scan(self, scan_job_id: int) -> bool:
        scanner = ScanService._active_scans.get(scan_job_id)
        if scanner:
            scanner.resume()
            try:
                result = await self.db.execute(
                    select(ScanJob).where(ScanJob.id == scan_job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.status = "running"
                    await self.db.commit()
            except Exception:
                logger.warning("Could not persist resume status for scan %d (DB busy)", scan_job_id)
            return True
        return False

    async def cancel_scan(self, scan_job_id: int) -> bool:
        scanner = ScanService._active_scans.get(scan_job_id)
        if scanner:
            scanner.cancel()
            for attempt in range(5):
                try:
                    result = await self.db.execute(
                        select(ScanJob).where(ScanJob.id == scan_job_id)
                    )
                    job = result.scalar_one_or_none()
                    if job:
                        job.status = "cancelled"
                        await self.db.commit()
                    return True
                except Exception:
                    if attempt < 4:
                        await asyncio.sleep(0.2)
                    else:
                        logger.warning("Could not persist cancel status for scan %d (DB busy)", scan_job_id)
            return True
        return False

    async def get_scan_progress(self, scan_job_id: int) -> Optional[dict]:
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            return None

        scanner = ScanService._active_scans.get(scan_job_id)
        progress_data = {
            "id": job.id,
            "path": job.path,
            "scan_type": job.scan_type,
            "status": job.status,
            "total_files": job.total_files,
            "scanned_files": job.scanned_files,
            "error_count": job.error_count,
            "progress": job.progress,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
        }

        if scanner:
            progress_data["progress"] = scanner.progress.percentage
            progress_data["total_files"] = scanner.progress.total_files
            progress_data["scanned_files"] = scanner.progress.scanned_files
            progress_data["error_count"] = scanner.progress.error_count
            progress_data["eta_seconds"] = scanner.progress.eta_seconds

        return progress_data

    async def list_scan_jobs(self) -> list[ScanJob]:
        result = await self.db.execute(
            select(ScanJob).order_by(ScanJob.created_at.desc())
        )
        jobs = list(result.scalars().all())
        for job in jobs:
            scanner = ScanService._active_scans.get(job.id)
            if scanner and job.status == "running":
                job.total_files = scanner.progress.total_files
                job.scanned_files = scanner.progress.scanned_files
                job.error_count = scanner.progress.error_count
                if scanner.progress.percentage < 100:
                    job.progress = scanner.progress.percentage / 2
        return jobs

    async def delete_scan_job(self, scan_job_id: int) -> bool:
        await self.cancel_scan(scan_job_id)
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            return False

        file_ids_q = select(FileRecord.id).where(FileRecord.scan_id == scan_job_id)
        file_ids_result = await self.db.execute(file_ids_q)
        file_ids = [row[0] for row in file_ids_result.all()]

        if file_ids:
            for model in [FileContent, FileCategory, FileSensitivity,
                          SensitiveFinding, EntityExtraction,
                          FileAnalysis, FileTimeline]:
                await self.db.execute(
                    delete(model).where(model.file_id.in_(file_ids))
                )

        await self.db.execute(
            delete(FileRecord).where(FileRecord.scan_id == scan_job_id)
        )
        await self.db.delete(job)
        await self.db.commit()
        return True

    async def get_existing_paths(self) -> set[str]:
        result = await self.db.execute(select(FileRecord.path))
        return {row[0] for row in result.all()}

    async def run_incremental_scan(self, scan_job_id: int) -> None:
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            raise ValueError(f"Scan job {scan_job_id} not found")

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await self.db.commit()

        existing_paths = await self.get_existing_paths()

        scanner = DirectoryScanner(
            path=job.path,
            thread_count=settings.scan_default_threads,
            batch_size=settings.scan_batch_size,
            exclude_dirs=settings.scan_exclude_dirs,
        )
        ScanService._active_scans[scan_job_id] = scanner

        try:
            new_files, deleted_paths, modified_paths = await scanner.scan_incremental(
                existing_paths
            )

            await self._persist_files(new_files, scan_job_id)

            if deleted_paths:
                del_file_ids_q = select(FileRecord.id).where(FileRecord.path.in_(deleted_paths))
                del_result = await self.db.execute(del_file_ids_q)
                del_file_ids = [row[0] for row in del_result.all()]
                if del_file_ids:
                    for model in [FileContent, FileCategory, FileSensitivity,
                                   SensitiveFinding, EntityExtraction,
                                   FileAnalysis, FileTimeline]:
                        await self.db.execute(
                            delete(model).where(model.file_id.in_(del_file_ids))
                        )
                await self.db.execute(
                    delete(FileRecord).where(FileRecord.path.in_(deleted_paths))
                )

            if new_files:
                await self._analyze_files(new_files, job)

            job.status = "completed"
            job.total_files = scanner.progress.total_files
            job.scanned_files = len(new_files)
            job.progress = 100.0
            job.error_count = scanner.progress.error_count
            job.completed_at = datetime.now(timezone.utc)
            await self.db.commit()

        except ScanCancelledError:
            job.status = "cancelled"
            await self.db.commit()

        except Exception as e:
            job.status = "failed"
            await self.db.commit()
            logger.error("Incremental scan job %d failed: %s", scan_job_id, e)
            raise

        finally:
            ScanService._active_scans.pop(scan_job_id, None)
