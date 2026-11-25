from __future__ import annotations

import hashlib
import math
import os
import stat as stat_module
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Callable, Optional

from app.core.exceptions import ScanCancelledError
from app.core.logging import get_logger

logger = get_logger(__name__)


class ScanState:
    idle = "idle"
    running = "running"
    paused = "paused"
    cancelled = "cancelled"
    completed = "completed"
    failed = "failed"


class ScanProgress:
    def __init__(self):
        self.total_files: int = 0
        self.scanned_files: int = 0
        self.error_count: int = 0
        self.current_path: str = ""
        self.elapsed_seconds: float = 0.0
        self.estimated_remaining: float = 0.0
        self._lock = threading.Lock()

    @property
    def percentage(self) -> float:
        if self.total_files == 0:
            return 0.0
        return min(100.0, (self.scanned_files / self.total_files) * 100.0)

    @property
    def eta_seconds(self) -> float:
        return self.estimated_remaining

    def add_scanned(self, count: int) -> None:
        with self._lock:
            self.scanned_files += count


class BaseScanner(ABC):
    def __init__(
        self,
        path: str,
        progress_callback: Optional[Callable[[ScanProgress], None]] = None,
        thread_count: int = 4,
        batch_size: int = 100,
        exclude_dirs: Optional[list[str]] = None,
    ):
        self.path = path
        self.progress_callback = progress_callback
        self.thread_count = thread_count
        self.batch_size = batch_size
        self.exclude_dirs = set(exclude_dirs or [])
        self.exclude_files: set[str] = set()
        self.progress = ScanProgress()
        self._state = ScanState.idle
        self._paused_event = threading.Event()
        self._cancelled = False
        self._paused_event.set()

    @property
    def state(self) -> str:
        return self._state

    def pause(self) -> None:
        if self._state == ScanState.running:
            self._state = ScanState.paused
            self._paused_event.clear()
            logger.info("Scanner paused")

    def resume(self) -> None:
        if self._state == ScanState.paused:
            self._state = ScanState.running
            self._paused_event.set()
            logger.info("Scanner resumed")

    def cancel(self) -> None:
        if self._state in (ScanState.running, ScanState.paused):
            self._state = ScanState.cancelled
            self._cancelled = True
            self._paused_event.set()
            logger.info("Scanner cancelled")

    def _check_paused_or_cancelled(self) -> None:
        self._paused_event.wait()
        if self._cancelled:
            raise ScanCancelledError("Scan cancelled")

    def _should_exclude(self, dir_name: str) -> bool:
        return dir_name in self.exclude_dirs or dir_name in self.exclude_files

    def _should_exclude_file(self, filename: str) -> bool:
        return filename in self.exclude_files

    def _get_file_metadata(self, filepath: str) -> dict:
        metadata: dict = {}
        try:
            stat_info = os.stat(filepath)
            metadata["size"] = stat_info.st_size
            metadata["created_at"] = datetime.fromtimestamp(
                stat_info.st_ctime, tz=timezone.utc
            )
            metadata["modified_at"] = datetime.fromtimestamp(
                stat_info.st_mtime, tz=timezone.utc
            )
            metadata["accessed_at"] = datetime.fromtimestamp(
                stat_info.st_atime, tz=timezone.utc
            )

            mode = stat_info.st_mode
            metadata["permissions"] = stat_module.filemode(mode)
            metadata["is_hidden"] = False
            metadata["is_readonly"] = not bool(mode & stat_module.S_IWUSR)
            metadata["is_system"] = False

            metadata["owner"] = None
            if os.name == "nt":
                try:
                    import ctypes
                    from ctypes import wintypes

                    attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                    if attrs != -1:
                        metadata["is_hidden"] = bool(attrs & 2)
                        metadata["is_system"] = bool(attrs & 4)
                        metadata["is_readonly"] = bool(attrs & 1)

                    OWNER_SECURITY_INFORMATION = 1
                    sd_buf = ctypes.create_string_buffer(512)
                    needed = wintypes.DWORD(0)
                    ret = ctypes.windll.advapi32.GetFileSecurityW(
                        filepath,
                        OWNER_SECURITY_INFORMATION,
                        ctypes.byref(sd_buf),
                        ctypes.sizeof(sd_buf),
                        ctypes.byref(needed),
                    )
                    if ret:
                        owner_sid = ctypes.c_void_p()
                        owner_defaulted = wintypes.BOOL()
                        if ctypes.windll.advapi32.GetSecurityDescriptorOwner(
                            ctypes.byref(sd_buf),
                            ctypes.byref(owner_sid),
                            ctypes.byref(owner_defaulted),
                        ):
                            if owner_sid.value:
                                name_buf = ctypes.create_unicode_buffer(256)
                                domain_buf = ctypes.create_unicode_buffer(256)
                                name_len = wintypes.DWORD(256)
                                domain_len = wintypes.DWORD(256)
                                sid_name_use = wintypes.DWORD()
                                if ctypes.windll.advapi32.LookupAccountSidW(
                                    None,
                                    owner_sid,
                                    name_buf,
                                    ctypes.byref(name_len),
                                    domain_buf,
                                    ctypes.byref(domain_len),
                                    ctypes.byref(sid_name_use),
                                ):
                                    domain = domain_buf.value or ""
                                    name = name_buf.value or ""
                                    metadata["owner"] = f"{domain}\\{name}" if domain else name
                except Exception:
                    pass

            metadata["is_symlink"] = os.path.islink(filepath)
            metadata["volume"] = os.path.splitdrive(filepath)[0]
            metadata["extension"] = os.path.splitext(filepath)[1].lower()
            metadata["name"] = os.path.basename(filepath)
            metadata["path"] = filepath

        except (OSError, PermissionError) as e:
            logger.warning("Failed to read metadata for %s: %s", filepath, e)

        return metadata

    def _compute_file_metrics(
        self, filepath: str, max_read: int = 100 * 1024 * 1024
    ) -> tuple[Optional[str], Optional[str], Optional[float], Optional[str]]:
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        freq = [0] * 256
        total_read = 0
        entropy_sample = 1048576
        magic_bytes: Optional[str] = None
        try:
            with open(filepath, "rb") as f:
                header = f.read(16)
                if header:
                    magic_bytes = header.hex()
                    sha256_hash.update(header)
                    md5_hash.update(header)
                    for byte in header:
                        freq[byte] += 1
                    total_read += len(header)

                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    remaining = entropy_sample - total_read
                    if remaining > 0:
                        for byte in chunk[:remaining]:
                            freq[byte] += 1
                    total_read += len(chunk)
                    if total_read >= max_read:
                        break

            sample_used = min(total_read, entropy_sample)
            entropy = 0.0
            if sample_used > 0:
                for count in freq:
                    if count > 0:
                        p_x = count / sample_used
                        entropy -= p_x * math.log2(p_x)

            return sha256_hash.hexdigest(), md5_hash.hexdigest(), entropy, magic_bytes
        except (OSError, PermissionError) as e:
            logger.warning("Failed to read %s: %s", filepath, e)
            return None, None, None, magic_bytes

    def _compute_entropy(
        self, filepath: str, sample_size: int = 1048576
    ) -> Optional[float]:
        try:
            with open(filepath, "rb") as f:
                data = f.read(sample_size)
            if not data:
                return 0.0
            length = len(data)
            freq = [0] * 256
            for byte in data:
                freq[byte] += 1
            entropy = 0.0
            for count in freq:
                if count > 0:
                    p_x = count / length
                    entropy -= p_x * math.log2(p_x)
            return entropy
        except (OSError, PermissionError) as e:
            logger.warning("Failed to compute entropy for %s: %s", filepath, e)
            return None

    @abstractmethod
    async def scan(self) -> list[dict]:
        ...

    @abstractmethod
    async def scan_incremental(
        self, existing_paths: set[str]
    ) -> tuple[list[dict], list[str], list[str]]:
        ...
