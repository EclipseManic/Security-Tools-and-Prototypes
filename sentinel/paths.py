"""Service path analysis.

This module is pure Python with no Windows dependency so the logic can be unit
tested anywhere. It fixes three defects in the original PowerShell tool:

* ``\\??\\C:\\...`` native paths were never normalised.
* User-writable detection only matched ``C:\\Users\\...`` and ``Temp``, so a
  binary dropped in ``E:\\Downloads\\...`` scored nothing.
* Unknown paths were silently treated as "outside protected roots".
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_EXE_PATTERN = re.compile(
    r"^(?P<path>.*?\.(?:exe|com|sys|dll|bat|cmd|ps1))(?=\s|$)", re.IGNORECASE
)

# Directory names that are writable by non-administrators in a default Windows
# install, no matter which drive or how deeply nested they are.
USER_WRITABLE_SEGMENTS = frozenset(
    {
        "users",
        "downloads",
        "download",
        "desktop",
        "appdata",
        "temp",
        "tmp",
        "systemtemp",
        "temporary",
    }
)

_ENV_VARS = {
    "%systemroot%": lambda: os.environ.get("SystemRoot", r"C:\Windows"),
    "%windir%": lambda: os.environ.get("SystemRoot", r"C:\Windows"),
    "%programfiles%": lambda: os.environ.get("ProgramFiles", r"C:\Program Files"),
    "%programfiles(x86)%": lambda: os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    "%programdata%": lambda: os.environ.get("ProgramData", r"C:\ProgramData"),
}


def expand_env(text: str) -> str:
    """Expand the handful of Windows variables a service path can legally contain."""
    if not text:
        return ""
    expanded = text
    for name, resolver in _ENV_VARS.items():
        if name in expanded.lower():
            pattern = re.compile(re.escape(name), re.IGNORECASE)
            expanded = pattern.sub(lambda _match, r=resolver: r(), expanded)
    return os.path.expandvars(expanded)


def normalize_service_path(command_line: str | None) -> str | None:
    """Extract the executable path from a service command line.

    Returns ``None`` when the command line is empty, which callers must treat as
    *unknown* rather than as evidence of a missing binary.
    """
    if not command_line or not str(command_line).strip():
        return None

    text = expand_env(str(command_line).strip())

    # Native object-manager prefixes such as \??\C:\Windows\... are not real paths.
    while text.startswith(("\\??\\", "\\\\.\\", "\\\\?\\")):
        text = text[4:]

    # Registry-style roots that appear verbatim in some service PathNames.
    if re.match(r"^\\SystemRoot\\", text, re.IGNORECASE):
        text = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), text[12:])
    elif re.match(r"^System32\\", text, re.IGNORECASE):
        text = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), text)

    path = ""
    if text.startswith('"'):
        closing = text.find('"', 1)
        if closing > 1:
            path = text[1:closing]
    if not path:
        match = _EXE_PATTERN.match(text)
        path = match.group("path") if match else text

    path = path.strip().strip('"').strip()
    return path or None


def is_unquoted_path(command_line: str | None) -> bool:
    """True when the executable path contains spaces but is not quoted.

    Only ``.exe`` images are considered: the classic unquoted-service-path
    weakness applies to executable images, not to drivers or DLL hosts.
    """
    if not command_line or not str(command_line).strip():
        return False
    text = expand_env(str(command_line).strip())
    if text.startswith('"'):
        return False
    match = _EXE_PATTERN.match(text)
    if not match:
        return False
    candidate = match.group("path")
    return bool(" " in candidate and candidate.lower().endswith(".exe"))


def segments(path: str) -> list[str]:
    if not path:
        return []
    cleaned = path.replace("/", "\\")
    return [part.strip().lower() for part in cleaned.split("\\") if part.strip()]


def _is_writable_segment(part: str) -> bool:
    if part in USER_WRITABLE_SEGMENTS:
        return True
    # Real-world folders are often named Downloads1, Downloads (2), tempfiles, ...
    return part.startswith("download") or part.startswith("temp folder")


def is_user_writable(path: str | None) -> bool:
    """Flag binaries stored under a profile, Downloads, Desktop, AppData or Temp.

    Segment-based so it works on any drive and any depth, which the original
    ``\\Users\\<name>\\...`` regex did not: ``E:\\...\\Downloads1\\...`` is now
    treated exactly like ``C:\\Users\\me\\Downloads``.
    """
    if not path:
        return False
    parts = segments(expand_env(path))
    if not parts:
        return False
    # Ignore the drive/volume label itself.
    for part in parts[1:] if len(parts) > 1 else parts:
        if _is_writable_segment(part):
            return True
    return False


def protected_roots() -> list[str]:
    roots = []
    for variable, fallback in (
        ("SystemRoot", r"C:\Windows"),
        ("ProgramFiles", r"C:\Program Files"),
        ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ):
        value = os.environ.get(variable) or fallback
        if value:
            roots.append(value)
    return roots


def _absolute(path: str) -> str | None:
    try:
        return os.path.normcase(os.path.abspath(expand_env(path)))
    except (OSError, ValueError):
        return None


def is_under_roots(path: str | None, roots: list[str] | None = None) -> bool:
    """True when *path* sits inside one of the trusted install roots."""
    if not path:
        return False
    candidate = _absolute(path)
    if not candidate:
        return False
    for root in roots if roots is not None else protected_roots():
        base = _absolute(root)
        if not base:
            continue
        base = base.rstrip("\\")
        if candidate == base or candidate.startswith(base + "\\"):
            return True
    return False


def is_outside_protected_roots(path: str | None) -> bool:
    """Known path that lives outside Windows and Program Files.

    Returns ``False`` for an unknown path: absence of data is not evidence.
    """
    if not path:
        return False
    return not is_under_roots(path)


def exists(path: str | None) -> bool:
    if not path:
        return False
    try:
        return Path(path).is_file()
    except OSError:
        return False


def display_name(path: str | None) -> str:
    return os.path.basename(path) if path else ""
