"""Configuration, version and evidence storage layout for ServiceSentinel Web."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

APP_NAME = "ServiceSentinel"
VERSION = "3.0.0"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PS_SCRIPT = Path(__file__).resolve().parent / "ps" / "collect.ps1"

IS_WINDOWS = os.name == "nt"

# Evidence lives beside the project when possible, otherwise in LOCALAPPDATA.
# This mirrors the original tool so existing evidence stays in one place.
_DATA_ROOT: Path | None = None


def _is_writable(directory: Path) -> bool:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".sentinel-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def data_root() -> Path:
    global _DATA_ROOT
    if _DATA_ROOT is not None:
        return _DATA_ROOT

    override = os.environ.get("SENTINEL_DATA_DIR")
    if override:
        candidate = Path(override).expanduser()
        candidate.mkdir(parents=True, exist_ok=True)
        _DATA_ROOT = candidate
        return _DATA_ROOT

    preferred = PROJECT_ROOT / "ServiceSentinelData"
    if _is_writable(preferred):
        _DATA_ROOT = preferred
        return _DATA_ROOT

    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    fallback = Path(base) / APP_NAME
    fallback.mkdir(parents=True, exist_ok=True)
    _DATA_ROOT = fallback
    return _DATA_ROOT


def set_data_root(path: str | Path) -> Path:
    """Point the application at a different evidence directory (used by tests)."""
    global _DATA_ROOT
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    _DATA_ROOT = target
    return _DATA_ROOT


def cache_dir() -> Path:
    directory = data_root() / "cache"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def log_file() -> Path:
    from datetime import datetime

    return data_root() / f"ServiceSentinel_{datetime.now():%Y%m%d}.log"


def baseline_file() -> Path:
    return data_root() / "baseline-latest.json"


def triage_file() -> Path:
    return data_root() / "triage_decisions.jsonl"


def containment_dir() -> Path:
    directory = data_root() / "containment_backups"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def evidence_cache_file() -> Path:
    return cache_dir() / "file-evidence.json"


def state_words_file() -> Path:
    return cache_dir() / "state-words.json"


def export_dir() -> Path:
    return data_root()


# --------------------------------------------------------------------------- #
# Operational settings (environment driven, safe defaults)
# --------------------------------------------------------------------------- #
def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


_RUNTIME_PASSWORD: str | None = None


def set_auth_password(value: str | None) -> None:
    """Set the console password without exposing it in the process environment."""
    global _RUNTIME_PASSWORD
    cleaned = (value or "").strip()
    _RUNTIME_PASSWORD = cleaned or None


def auth_password() -> str | None:
    """Optional console password. When unset, access is controlled by the OS account."""
    if _RUNTIME_PASSWORD:
        return _RUNTIME_PASSWORD
    value = os.environ.get("SENTINEL_PASSWORD", "").strip()
    return value or None


def allow_remote() -> bool:
    return os.environ.get("SENTINEL_ALLOW_REMOTE", "").strip().lower() in {"1", "true", "yes"}


def session_secret() -> str:
    """Signing key for the login cookie, persisted so restarts keep sessions valid."""
    override = os.environ.get("SENTINEL_SECRET")
    if override:
        return override
    path = data_root() / ".session-secret"
    try:
        if path.exists():
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                return stored
    except OSError:
        pass
    import secrets

    generated = secrets.token_urlsafe(48)
    try:
        path.write_text(generated, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass
    return generated


def retention_days() -> int:
    """How long reports, logs and baseline history are kept."""
    return _env_int("SENTINEL_RETENTION_DAYS", 90)


def max_export_files() -> int:
    return _env_int("SENTINEL_MAX_EXPORTS", 200)


def max_evidence_cache_entries() -> int:
    return _env_int("SENTINEL_MAX_EVIDENCE_CACHE", 5000)
