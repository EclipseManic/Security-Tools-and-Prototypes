"""INI configuration-file support for LogTriage.

The optional ``tool.config`` file supplies defaults for every runtime option.
Explicit command-line flags always take precedence. The loader is strict:
unknown sections/keys and invalid values produce an error instead of being
silently ignored, so a typo cannot quietly weaken detection.
"""
from __future__ import annotations

import configparser
from datetime import datetime
from pathlib import Path
from typing import Any

from triage_types import DEFAULT_MAX_BYTES, Config

CONFIG_FILENAME = "tool.config"

# section -> key -> type
SCHEMA: dict[str, dict[str, str]] = {
    "detection": {
        "window_seconds": "int",
        "brute_threshold": "int",
        "scan_threshold": "int",
        "port_scan_threshold": "int",
        "success_window_seconds": "int",
    },
    "limits": {
        "assume_year": "int",
        "max_bytes": "int",
    },
    "output": {
        "out_dir": "str",
        "output_prefix": "str",
        "format": "str",
    },
    "run": {
        "input": "str",
        "watchlist": "str",
        "no_watchlist": "bool",
        "fail_on": "str",
        "quiet": "bool",
        "no_color": "bool",
    },
}

FORMATS = ("both", "json", "md")
FAIL_ON_LEVELS = ("low", "medium", "high", "critical")


def default_settings() -> dict[str, Any]:
    """Built-in defaults, kept in sync with the Config dataclass."""
    base = Config()
    return {
        "input": None,
        "out_dir": "sample_output",
        "output_prefix": "triage",
        "format": "both",
        "watchlist": None,
        "no_watchlist": False,
        "window_seconds": base.window_seconds,
        "brute_threshold": base.brute_threshold,
        "scan_threshold": base.scan_threshold,
        "port_scan_threshold": base.port_scan_threshold,
        "success_window_seconds": base.success_window_seconds,
        "assume_year": datetime.now().year,
        "max_bytes": DEFAULT_MAX_BYTES,
        "fail_on": None,
        "quiet": False,
        "no_color": False,
    }


def default_config_path() -> Path | None:
    """Return tool.config next to the script when it exists."""
    candidate = Path(__file__).resolve().with_name(CONFIG_FILENAME)
    return candidate if candidate.is_file() else None


def load_config_file(path: Path) -> dict[str, Any]:
    """Load and validate one INI file, returning only configured values."""
    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    if not path.is_file():
        raise ValueError(f"config path is not a file: {path}")

    parser = configparser.ConfigParser(
        interpolation=None,
        inline_comment_prefixes=("#", ";"),
    )
    try:
        parser.read_string(path.read_text(encoding="utf-8-sig"), source=str(path))
    except UnicodeDecodeError as exc:
        raise ValueError(f"config file is not valid UTF-8: {path}") from exc
    except configparser.Error as exc:
        raise ValueError(f"invalid config file {path}: {exc}") from exc

    unknown_sections = set(parser.sections()) - set(SCHEMA)
    if unknown_sections:
        raise ValueError(
            f"unknown config section(s) in {path}: "
            f"{', '.join(sorted(unknown_sections))}"
        )
    if parser.defaults():
        raise ValueError(f"[DEFAULT] section is not supported in {path}")

    values: dict[str, Any] = {}
    for section, keys in SCHEMA.items():
        if not parser.has_section(section):
            continue
        for key in parser[section]:
            if key not in keys:
                raise ValueError(
                    f"unknown key '{key}' in [{section}] of {path}"
                )
            kind = keys[key]
            try:
                if kind == "int":
                    value = parser.getint(section, key)
                elif kind == "bool":
                    value = parser.getboolean(section, key)
                else:
                    value = parser.get(section, key).strip()
            except ValueError as exc:
                raise ValueError(
                    f"invalid {kind} value for [{section}] {key} "
                    f"in {path}: {exc}"
                ) from exc
            if kind == "str" and value == "":
                continue
            values[key] = value

    if "format" in values and values["format"] not in FORMATS:
        raise ValueError(
            f"invalid format '{values['format']}' in {path}; "
            f"choose from {', '.join(FORMATS)}"
        )
    if "fail_on" in values and values["fail_on"] not in FAIL_ON_LEVELS:
        raise ValueError(
            f"invalid fail_on '{values['fail_on']}' in {path}; "
            f"choose from {', '.join(FAIL_ON_LEVELS)}"
        )
    return values


def resolve_settings(
    overrides: dict[str, Any], config_path: Path | None
) -> tuple[dict[str, Any], Path | None]:
    """Merge built-in defaults, the config file, and non-None CLI overrides."""
    path = config_path
    if path is None:
        path = default_config_path()
    elif not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")

    settings = default_settings()
    if path is not None:
        settings.update(load_config_file(path))
    for key in settings:
        value = overrides.get(key)
        if value is not None:
            settings[key] = value
    return settings, path
