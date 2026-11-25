"""
core/mitre.py
MITRE ATT&CK technique canonicalization + domain map access.

Why this module exists
----------------------
The corpus stored technique names as free-text strings ("T1110.004 Credential
Stuffing", "T1110.004 — Credential Stuffing", "Credential Stuffing"). The
database keyed mastery on that raw string, so 132 real techniques produced 168
distinct buckets and the adaptive engine could not see a learner's progress.

Everything now goes through one canonical key:

    canonical_technique("T1110.004 — Credential Stuffing") -> "T1110.004"
    canonical_technique("Credential Stuffing")              -> "name:credential stuffing"
    display_technique("T1110.004")                          -> "T1110.004"

The MITRE domain map (domain -> valid technique ids) lives in
`data/mitre_domain_map.json` so the runtime no longer depends on the
`.opencode/` tooling folder.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from config import BASE_DIR


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
MITRE_MAP_PATH = BASE_DIR / "data" / "mitre_domain_map.json"
LEGACY_MITRE_MAP_PATH = BASE_DIR / ".opencode" / "planning" / "mitre_domain_map.json"


# --------------------------------------------------------------------------- #
# Technique parsing
# --------------------------------------------------------------------------- #
# T1234 / T1234.001 — the sub-technique form is the canonical one.
_ID_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b", re.IGNORECASE)
_SEPARATORS = " \t-—–_:|,"


def _clean_name(text: str) -> str:
    """Collapse whitespace and trim separator noise from a technique name."""
    cleaned = re.sub(r"\s+", " ", (text or "")).strip(_SEPARATORS).strip()
    return cleaned


def parse_technique(value: str | None) -> tuple[str, str]:
    """Split a technique string into (id, name).

    >>> parse_technique("T1110.004 — Credential Stuffing")
    ('T1110.004', 'Credential Stuffing')
    >>> parse_technique("Credential Stuffing")
    ('', 'Credential Stuffing')
    """
    text = (value or "").strip()
    if not text:
        return "", ""

    match = _ID_RE.search(text)
    if not match:
        return "", _clean_name(text)

    tech_id = f"T{match.group(1)}"
    if match.group(2):
        tech_id += f".{match.group(2)}"

    before = _clean_name(text[: match.start()])
    after = _clean_name(text[match.end():])
    name = after or before
    return tech_id, _clean_name(name)


def canonical_technique(value: str | None) -> str:
    """Stable key for a technique.

    Technique ids win; otherwise a normalized name key is used so that
    name-only techniques still group together instead of fragmenting.
    """
    tech_id, name = parse_technique(value)
    if tech_id:
        return tech_id
    slug = re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()
    return f"name:{slug}" if slug else ""


def display_technique(value: str | None, name: str | None = None) -> str:
    """Human-readable label: 'T1110.004 — Credential Stuffing'."""
    tech_id, parsed_name = parse_technique(value)
    label = _clean_name(name) if name else parsed_name
    if tech_id and label:
        return f"{tech_id} — {label}"
    return tech_id or label or (value or "").strip()


def technique_id(value: str | None) -> str:
    """The MITRE id only ('T1110.004'), or '' when the string carries none."""
    return parse_technique(value)[0]


def technique_name(value: str | None) -> str:
    """The technique name only ('Credential Stuffing')."""
    return parse_technique(value)[1]


def base_technique(tech_id: str | None) -> str:
    """Parent technique of a sub-technique ('T1110.004' -> 'T1110')."""
    parsed = technique_id(tech_id) or (tech_id or "").strip().upper()
    if not parsed:
        return ""
    return parsed.split(".")[0]


def same_technique(a: str | None, b: str | None) -> bool:
    """True when two technique strings refer to the same technique.

    Sub-techniques match only their own parent (T1110.004 != T1110.002), but
    a parent id matches any of its sub-techniques.
    """
    id_a, id_b = technique_id(a) or "", technique_id(b) or ""
    if not id_a or not id_b:
        return False
    if id_a == id_b:
        return True
    if "." not in id_a:
        return id_b.startswith(id_a + ".")
    if "." not in id_b:
        return id_a.startswith(id_b + ".")
    return False


# --------------------------------------------------------------------------- #
# Domain map
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def load_domain_map() -> dict[str, list[str]]:
    """Load the domain -> technique-id map.

    Prefers `data/mitre_domain_map.json` (shipped with the app) and falls back
    to the legacy `.opencode/planning/` copy when the new file is missing.
    """
    for path in (MITRE_MAP_PATH, LEGACY_MITRE_MAP_PATH):
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data:
            return {str(k): [str(t) for t in v] for k, v in data.items()}
    return {}


def techniques_for_domain(domain: str) -> list[str]:
    """Valid technique ids for a domain display name (empty list if unknown)."""
    return list(load_domain_map().get(domain, []))


def technique_in_domain(tech_value: str | None, domain: str) -> bool:
    """True when a technique belongs to a domain's taxonomy.

    A parent id matches any of its sub-techniques, and a sub-technique matches
    when its parent is listed.
    """
    valid = techniques_for_domain(domain)
    if not valid:
        return True  # unknown domain — do not block
    tech_id = technique_id(tech_value)
    if not tech_id:
        return False
    valid_set = {v.upper() for v in valid}
    if tech_id.upper() in valid_set:
        return True
    parent = base_technique(tech_id)
    for candidate in valid_set:
        if candidate.startswith(parent + "."):
            return True
        if parent.startswith(candidate + "."):
            return True
    return False


def unknown_techniques_for_domain(domain: str, technique_values: list[str]) -> list[str]:
    """Technique strings from a scenario that are not part of the domain map."""
    return [t for t in technique_values if not technique_in_domain(t, domain)]


__all__ = [
    "MITRE_MAP_PATH",
    "LEGACY_MITRE_MAP_PATH",
    "parse_technique",
    "canonical_technique",
    "display_technique",
    "technique_id",
    "technique_name",
    "base_technique",
    "same_technique",
    "load_domain_map",
    "techniques_for_domain",
    "technique_in_domain",
    "unknown_techniques_for_domain",
]
