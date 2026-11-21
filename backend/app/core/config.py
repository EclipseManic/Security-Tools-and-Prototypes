from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ directory. Relative SQLite paths and the .env file resolve here so
# the app behaves the same whether it is started from the repository root,
# from backend/, or inside the container.
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "File Intelligence Platform"
    app_version: str = "1.0.1"
    debug: bool = False

    database_url: str = "sqlite+aiosqlite:///./data/fip.db"
    database_echo: bool = False
    database_pool_size: int = 2
    database_max_overflow: int = 4

    # Loopback only by default. This tool can read any path the process can
    # access, so exposing it to a network is an explicit, documented choice.
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    log_level: str = "INFO"
    log_format: str = "json"

    scan_default_threads: int = 4
    scan_batch_size: int = 100
    scan_max_depth: int = 100
    scan_exclude_dirs: list[str] = [
        "$Recycle.Bin",
        "System Volume Information",
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
    ]
    scan_exclude_files: list[str] = [
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
    ]

    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash"

    openrouter_api_key: str = ""
    openrouter_model: str = ""

    openai_api_key: str = ""
    openai_model: str = ""

    bazaarlink_api_key: str = ""
    bazaarlink_model: str = ""

    ai_provider: Literal["gemini", "openrouter", "openai", "bazaarlink", "none"] = "none"

    watch_enabled: bool = False
    watch_interval: float = 0.5


settings = Settings()
