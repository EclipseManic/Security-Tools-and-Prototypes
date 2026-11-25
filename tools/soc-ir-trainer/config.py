"""
config.py
Global configuration for the AI-Powered Attack Simulation Trainer.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    # Optional: load .env if python-dotenv is installed
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except Exception:
    pass

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
ENV_FILE = BASE_DIR / ".env"


def _clean_env(value: str | None) -> str:
    """Trim whitespace and the quotes `setx` users often paste around a key."""
    return (value or "").strip().strip('"').strip("'").strip()


def _windows_system_env(name: str) -> str:
    """Read a persisted Windows environment variable.

    System/user variables set with `setx` are only inherited by processes
    started *after* the change. Falling back to the registry means an editor
    or terminal opened earlier still picks up OPENROUTER_API_KEY.
    """
    if os.name != "nt":
        return ""
    try:
        import winreg
    except Exception:
        return ""

    locations = (
        (winreg.HKEY_CURRENT_USER, "Environment"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    )
    for root, path in locations:
        try:
            with winreg.OpenKey(root, path) as key:
                value, _kind = winreg.QueryValueEx(key, name)
        except OSError:
            continue
        cleaned = _clean_env(str(value) if value is not None else "")
        if cleaned:
            return cleaned
    return ""


def env_value(name: str, default: str = "") -> str:
    """Process env first, then (on Windows) the persisted system value."""
    value = _clean_env(os.getenv(name))
    if not value:
        value = _windows_system_env(name)
    return value or default


def _set_env_file(name: str, value: str) -> None:
    """Persist one key in .env without disturbing the other entries."""
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    except OSError:
        lines = []

    prefix = f"{name}="
    replaced = False
    output: list[str] = []
    for line in lines:
        if line.strip().startswith(prefix):
            output.append(f"{prefix}{value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{prefix}{value}")

    ENV_FILE.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# OpenRouter API configuration
# Key is read from OPENROUTER_API_KEY (process env, .env, or Windows system env).
# SOC_AI_DISABLED=1 lets Settings explicitly turn AI off even when a system-level
# key exists.
# --------------------------------------------------------------------------- #
AI_DISABLED = env_value("SOC_AI_DISABLED").lower() in {"1", "true", "yes", "on"}

OPENROUTER_API_KEY = "" if AI_DISABLED else env_value("OPENROUTER_API_KEY")
if OPENROUTER_API_KEY:
    # Make it available to any child process/library that reads os.environ.
    os.environ["OPENROUTER_API_KEY"] = OPENROUTER_API_KEY
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = env_value(
    "OPENROUTER_MODEL",
    "nvidia/nemotron-3.5-lightning:free",
)


def save_openrouter_model(model: str) -> None:
    """Set the evaluator model at runtime and persist it in .env."""
    global OPENROUTER_MODEL

    cleaned = _clean_env(model)
    if not cleaned:
        raise ValueError("A model id is required")
    _set_env_file("OPENROUTER_MODEL", cleaned)
    os.environ["OPENROUTER_MODEL"] = cleaned
    OPENROUTER_MODEL = cleaned


def save_openrouter_key(api_key: str) -> None:
    """Set (or clear) the OpenRouter key at runtime and persist it in .env.

    Passing an empty string disables AI explicitly, so a system-level
    OPENROUTER_API_KEY does not silently turn it back on after a restart.
    """
    global OPENROUTER_API_KEY, AI_DISABLED

    cleaned = _clean_env(api_key)
    disabled = not cleaned
    _set_env_file("OPENROUTER_API_KEY", cleaned)
    _set_env_file("SOC_AI_DISABLED", "1" if disabled else "0")

    os.environ["OPENROUTER_API_KEY"] = cleaned
    os.environ["SOC_AI_DISABLED"] = "1" if disabled else "0"
    OPENROUTER_API_KEY = cleaned
    AI_DISABLED = disabled


def _env_float(name: str, default: float, low: float, high: float) -> float:
    """Read a float env var, falling back safely on bad/out-of-range input."""
    raw = env_value(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value < low or value > high:
        return default
    return value


# AI request tuning is env-overridable so slow free tiers / local models can be
# adjusted without editing code.
OPENROUTER_TIMEOUT = _env_float("OPENROUTER_TIMEOUT", 180.0, 5.0, 900.0)
OPENROUTER_TEMPERATURE = _env_float("OPENROUTER_TEMPERATURE", 0.3, 0.0, 2.0)

# Scenario generation is slower and more creative than evaluation.
GENERATOR_TIMEOUT = _env_float("GENERATOR_TIMEOUT", 180.0, 10.0, 900.0)
GENERATOR_TEMPERATURE = _env_float("GENERATOR_TEMPERATURE", 0.7, 0.0, 2.0)

# --------------------------------------------------------------------------- #
# Branding
# --------------------------------------------------------------------------- #
APP_NAME = "AI Evolution Attack Simulation Trainer"
APP_VERSION = "3.0.0"
APP_TAGLINE = "Interactive cyber-range trainer with AI-powered debrief"

# Disclaimer shown at startup
DISCLAIMER = (
    "[bold yellow]DISCLAIMER[/bold yellow]: This is a SIMULATION ONLY training tool.\n"
    "No real exploits are executed. All 'attacks' are decision-tree walkthroughs\n"
    "for educational blue-team / red-team learning purposes."
)
