from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from app.core.exceptions import ScanCancelledError
from app.core.logging import get_logger
from app.services.scanner.base import BaseScanner, ScanProgress, ScanState

logger = get_logger(__name__)

MAGIC_MAP = {
    "25504446": "application/pdf",
    "d0cf11e0a1b11ae1": "application/vnd.ms-office",
    "504b0304": "application/zip",
    "504b0506": "application/zip",
    "504b0708": "application/zip",
    "52617221": "application/x-rar-compressed",
    "377abcaf271c": "application/x-7z-compressed",
    "89504e47": "image/png",
    "ffd8ffe0": "image/jpeg",
    "ffd8ffe1": "image/jpeg",
    "ffd8ffe2": "image/jpeg",
    "49492a00": "image/tiff",
    "4d4d002a": "image/tiff",
    "47494638": "image/gif",
    "424d": "image/bmp",
    "1f8b": "application/gzip",
}


class DirectoryScanner(BaseScanner):
    def __init__(
        self,
        path: str,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
        thread_count: int = 4,
        batch_size: int = 100,
        exclude_dirs: Optional[list[str]] = None,
        max_depth: int = 100,
        exclude_files: Optional[list[str]] = None,
    ):
        super().__init__(path, progress_callback, thread_count, batch_size, exclude_dirs)
        self.max_depth = max_depth
        self._start_time: float = 0.0
        if exclude_files:
            self.exclude_files = set(exclude_files)

    def _walk_directory(self, root_path: str) -> list[str]:
        file_paths: list[str] = []
        try:
            root_path = os.path.abspath(root_path)
            for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not self._should_exclude(d)
                ]

                depth = dirpath[len(root_path) :].count(os.sep)
                if depth > self.max_depth:
                    dirnames.clear()
                    continue

                for filename in filenames:
                    if not self._should_exclude_file(filename):
                        file_paths.append(os.path.join(dirpath, filename))
        except (OSError, PermissionError) as e:
            logger.error("Failed to walk directory %s: %s", root_path, e)

        return file_paths

    def _process_file(self, filepath: str) -> Optional[dict]:
        try:
            self._check_paused_or_cancelled()

            if not os.path.isfile(filepath):
                return None

            metadata = self._get_file_metadata(filepath)
            if not metadata.get("name"):
                return None

            metadata["magic_bytes"] = self._read_magic_bytes(filepath)

            file_size = metadata.get("size", 0)
            if file_size > 0:
                sha256, md5, entropy, _ = self._compute_file_metrics(filepath)
                metadata["sha256"] = sha256
                metadata["md5"] = md5
                metadata["entropy"] = entropy or 0.0
            else:
                metadata["sha256"] = None
                metadata["md5"] = None
                metadata["entropy"] = 0.0

            mime_type = self._detect_mime_type(filepath, metadata["magic_bytes"])
            metadata["mime_type"] = mime_type

            metadata["first_scanned_at"] = datetime.now(timezone.utc)
            metadata["last_scanned_at"] = datetime.now(timezone.utc)

            return metadata

        except ScanCancelledError:
            raise
        except Exception as e:
            logger.warning("Failed to process file %s: %s", filepath, e)
            return None

    def _read_magic_bytes(self, filepath: str, length: int = 16) -> Optional[str]:
        try:
            with open(filepath, "rb") as f:
                magic = f.read(length)
            return magic.hex()
        except (OSError, PermissionError):
            return None

    def _detect_mime_type(self, filepath: str, magic_hex: Optional[str] = None) -> Optional[str]:
        if not hasattr(DirectoryScanner, '_magic_instance'):
            try:
                import magic
                DirectoryScanner._magic_instance = magic.Magic(mime=True)
            except Exception:
                DirectoryScanner._magic_instance = None
        if DirectoryScanner._magic_instance is not None:
            try:
                return DirectoryScanner._magic_instance.from_file(filepath)
            except Exception:
                pass
        if magic_hex:
            for sig, mime in MAGIC_MAP.items():
                if magic_hex.startswith(sig):
                    return mime
        return None

    async def scan(self) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_scan)

    def _sync_scan(self) -> list[dict]:
        self._state = ScanState.running
        self._start_time = time.time()
        self._paused = False
        self._cancelled = False

        logger.info("Starting scan of %s", self.path)

        all_files = self._walk_directory(self.path)
        self.progress.total_files = len(all_files)
        logger.info("Discovered %d files in %s", len(all_files), self.path)

        scanned_files: list[dict] = []
        batch: list[str] = []

        for filepath in all_files:
            if self._cancelled:
                raise ScanCancelledError("Scan cancelled")

            self._check_paused_or_cancelled()
            batch.append(filepath)

            if len(batch) >= self.batch_size:
                result = self._process_batch(batch)
                scanned_files.extend(result)
                self._update_progress(batch)
                batch = []

        if batch:
            result = self._process_batch(batch)
            scanned_files.extend(result)
            self._update_progress(batch)

        self._state = ScanState.completed
        elapsed = time.time() - self._start_time
        logger.info(
            "Scan completed in %.2fs: %d files scanned, %d errors",
            elapsed,
            len(scanned_files),
            self.progress.error_count,
        )

        return scanned_files

    def _process_batch(self, batch: list[str]) -> list[dict]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            futures = {
                executor.submit(self._process_file, fp): fp for fp in batch
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except ScanCancelledError:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
                except Exception as e:
                    logger.warning("Batch processing error: %s", e)
                    self.progress.error_count += 1
        return results

    def _update_progress(self, batch: list[str]) -> None:
        self.progress.add_scanned(len(batch))
        elapsed = time.time() - self._start_time
        self.progress.elapsed_seconds = elapsed

        scanned = self.progress.scanned_files
        if scanned > 0 and elapsed > 0:
            rate = scanned / elapsed
            remaining = self.progress.total_files - scanned
            if rate > 0:
                self.progress.estimated_remaining = remaining / rate

        if self.progress_callback:
            self.progress_callback(self.progress)

    async def scan_incremental(
        self, existing_paths: set[str]
    ) -> tuple[list[dict], list[str], list[str]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sync_scan_incremental, existing_paths)

    def _sync_scan_incremental(
        self, existing_paths: set[str]
    ) -> tuple[list[dict], list[str], list[str]]:
        self._state = ScanState.running
        self._start_time = time.time()
        self._paused = False
        self._cancelled = False

        logger.info("Starting incremental scan of %s", self.path)

        current_paths = set(self._walk_directory(self.path))

        new_files = current_paths - existing_paths
        deleted_files = existing_paths - current_paths

        modified_files: list[str] = []

        self.progress.total_files = len(new_files)

        scanned_new: list[dict] = []

        batch: list[str] = []
        for filepath in new_files:
            if self._cancelled:
                raise ScanCancelledError("Scan cancelled")
            self._check_paused_or_cancelled()
            batch.append(filepath)
            if len(batch) >= self.batch_size:
                result = self._process_batch(batch)
                scanned_new.extend(result)
                self._update_progress(batch)
                batch = []

        if batch:
            result = self._process_batch(batch)
            scanned_new.extend(result)
            self._update_progress(batch)

        self._state = ScanState.completed
        elapsed = time.time() - self._start_time
        logger.info(
            "Incremental scan completed in %.2fs: %d new, %d modified, %d deleted",
            elapsed,
            len(scanned_new),
            len(modified_files),
            len(deleted_files),
        )

        return scanned_new, deleted_files, modified_files
