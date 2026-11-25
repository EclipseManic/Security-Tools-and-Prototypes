"""
scenarios/loader.py
Dynamic scenario loader — discovers and parses YAML scenario files
from scenarios/data/ and builds Scenario subclass instances.

YAML is the ONLY source of scenarios (legacy Python classes were removed
in P2). All files are format v2 (free-text); v2 schema is validated at load.
"""

from __future__ import annotations

import logging
import yaml
from pathlib import Path

from scenarios.base import Scenario, ScenarioMeta, Phase

DATA_DIR = Path(__file__).resolve().parent / "data"

PHASE_TYPES = {"triage", "analysis", "containment", "eradication", "recovery", "lessons"}

_log = logging.getLogger("scenarios.loader")


def _build_phase(data: dict) -> Phase:
    """Build a Phase from a YAML phase dict (v2 keys)."""
    return Phase(
        title=data.get("title", ""),
        situation=data.get("situation", ""),
        prompt=data.get("prompt", "What is your next action?"),
        id=data.get("id", ""),
        phase_type=data.get("phase_type", ""),
        guidance=data.get("guidance", {}) or {},
        hint=data.get("hint", ""),
        hints=data.get("hints", []) or [],
        ideal_concepts=data.get("ideal_concepts", []) or [],
        reference_answer=data.get("reference_answer", ""),
        followup_good=data.get("followup_good", ""),
        followup_weak=data.get("followup_weak", ""),
        next=data.get("next", ""),
        next_weak=data.get("next_weak", ""),
        mitre_tactic=data.get("mitre_tactic", ""),
        mitre_technique=data.get("mitre_technique", ""),
        role_prompts=data.get("role_prompts", {}) or {},
    )


def _resolve_navigation(sid: str, phases: list[Phase]) -> None:
    """Validate next/next_weak ids; fall back to sequential/empty when broken."""
    ids = {p.id for p in phases if p.id}
    for i, p in enumerate(phases):
        if p.next and p.next not in ids:
            _log.warning("%s: phase '%s' next='%s' not found — falling back to sequential", sid, p.id, p.next)
            p.next = ""
        if not p.next_weak:
            p.next_weak = p.next
        # A v2 phase without navigation continues to the next phase in order
        if not p.next and i < len(phases) - 1 and phases[i + 1].id:
            p.next = phases[i + 1].id


def _validate_mitre(sid: str, category: str, phases: list[Phase]) -> None:
    """Warn when a phase technique is absent from the scenario's domain map."""
    if not category or not phases:
        return
    try:
        from core.mitre import technique_id, technique_in_domain

        for p in phases:
            raw = (p.mitre_technique or "").strip()
            if not raw:
                continue
            if not technique_id(raw):
                _log.warning(
                    "%s: phase '%s' technique '%s' has no MITRE id",
                    sid, p.id or p.title, raw,
                )
                continue
            if not technique_in_domain(raw, category):
                _log.warning(
                    "%s: phase '%s' technique '%s' is not in the '%s' domain map",
                    sid, p.id or p.title, raw, category,
                )
    except Exception as exc:  # map missing / malformed — never fail loading
        _log.debug("MITRE validation unavailable for %s: %s", sid, exc)


def _validate_structure(sid: str, data: dict, phases: list[Phase]) -> list[str]:
    """Structural errors that make a scenario unreliable to play."""
    errors: list[str] = []
    if not phases:
        errors.append("no phases")
        return errors

    ids = [p.id for p in phases if p.id]
    if len(ids) != len(set(ids)):
        errors.append("duplicate phase ids")
    for p in phases:
        if not p.id:
            errors.append(f"phase '{p.title or '?'}' has no id")
        if p.phase_type and p.phase_type not in PHASE_TYPES:
            errors.append(f"phase '{p.id or p.title}': unknown phase_type '{p.phase_type}'")

    if int(data.get("format_version", 1)) >= 2:
        for p in phases:
            if not p.reference_answer and not p.ideal_concepts:
                errors.append(f"phase '{p.id or p.title}': no scoring target")
    return errors


def _validate_v2(sid: str, data: dict, phases: list[Phase]) -> None:
    """Log warnings for v2 files that miss required free-text content."""
    if int(data.get("format_version", 1)) < 2:
        return
    if not phases:
        _log.warning("%s: v2 file has no phases", sid)
        return
    for p in phases:
        if not p.ideal_concepts:
            _log.warning("%s: phase '%s' missing ideal_concepts", sid, p.id or p.title)
        if not p.reference_answer:
            _log.warning("%s: phase '%s' missing reference_answer", sid, p.id or p.title)
        if not p.followup_good or not p.followup_weak:
            _log.warning("%s: phase '%s' missing followup_good/followup_weak", sid, p.id or p.title)
        if p.phase_type and p.phase_type not in PHASE_TYPES:
            _log.warning("%s: phase '%s' unknown phase_type '%s'", sid, p.id or p.title, p.phase_type)


def _build_scenario_class(data: dict, source_file: str) -> type[Scenario]:
    """Construct a Scenario subclass dynamically from a parsed YAML dict."""
    incident = data.get("incident", {}) or {}
    meta = ScenarioMeta(
        name=data.get("name", ""),
        category=data.get("category", ""),
        difficulty=data.get("difficulty", "Medium"),
        format_version=int(data.get("format_version", 1)),
        incident_title=incident.get("title", data.get("name", "")),
        incident_summary=incident.get("summary", incident.get("opening", "")),
        opening=incident.get("opening", ""),
        compromised_assets=incident.get("compromised_assets", []),
        detected_via=incident.get("detected_via", ""),
        kill_chain=incident.get("kill_chain", []),
        mitre_tactics=incident.get("mitre_tactics", incident.get("kill_chain", [])),
        soc_tier=data.get("soc_tier", "L1"),
        roles=data.get("roles", ["analyst"]),
        executive_brief=data.get("executive_brief", ""),
        role_briefings=data.get("briefings", {}) or {},
        industries=data.get("industries", ["all"]),
    )

    phases = [_build_phase(p) for p in data.get("phases", [])]
    sid = data.get("id", "")
    _resolve_navigation(sid, phases)
    _validate_v2(sid, data, phases)
    _validate_mitre(sid, data.get("category", ""), phases)
    errors = _validate_structure(sid, data, phases)
    if errors:
        # Keep loading: the scenario may still be playable, but make the
        # problem visible in logs and in `python -m scenarios.loader`.
        _log.warning("%s: %s", sid, "; ".join(errors))

    cls_name = "".join(c if c.isalnum() else "" for c in f"YAML_{sid}") or "YAMLScenario"

    return type(cls_name, (Scenario,), {
        "meta": meta,
        "phases": phases,
        "_yaml_source": source_file,
        "_scenario_id": sid,
    })


def _load_yaml_scenarios() -> tuple[dict[str, list[type[Scenario]]], dict[str, type[Scenario]]]:
    """Scan scenarios/data/ for YAML files and build Scenario classes."""
    by_category: dict[str, list[type[Scenario]]] = {}
    by_id: dict[str, type[Scenario]] = {}
    sources: dict[str, str] = {}

    if not DATA_DIR.exists():
        return by_category, by_id

    for yfile in sorted(DATA_DIR.rglob("*.yaml")):
        try:
            with open(yfile, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                continue
            sid = data.get("id", "")
            cat = data.get("category", "")
            if not sid or not cat:
                continue
            if not isinstance(data.get("phases", []), list) or not data["phases"]:
                _log.warning("Skipping %s: no phases", yfile.name)
                continue
            if sid in by_id:
                _log.warning(
                    "Duplicate scenario id '%s' in %s — replacing %s",
                    sid, yfile, sources.get(sid, "?"),
                )
                old = by_id[sid]
                old_cat = getattr(old.meta, "category", "")
                if old in by_category.get(old_cat, []):
                    by_category[old_cat].remove(old)
            cls = _build_scenario_class(data, str(yfile))
            by_id[sid] = cls
            sources[sid] = str(yfile)
            by_category.setdefault(cat, []).append(cls)
        except Exception as e:
            _log.warning("YAML load error in %s: %s", yfile, e)
            continue

    return by_category, by_id


def load_all() -> dict[str, list[type[Scenario]]]:
    """
    Load all scenarios from YAML files.
    Returns an ALL_CATEGORIES-compatible dict: category -> list of Scenario classes.
    """
    by_category, _by_id = _load_yaml_scenarios()
    return by_category


def reload() -> tuple[dict[str, list[type[Scenario]]], dict[str, type[Scenario]]]:
    """Re-scan scenarios/data/ and refresh the shared module-level registries.

    The dicts are mutated in place so every module that imported
    `ALL_CATEGORIES` or `SCENARIO_BY_ID` sees the new content.
    """
    global TOTAL_SCENARIOS

    by_category, by_id_new = _load_yaml_scenarios()
    ALL_CATEGORIES.clear()
    ALL_CATEGORIES.update(by_category)
    SCENARIO_BY_ID.clear()
    SCENARIO_BY_ID.update(by_id_new)
    TOTAL_SCENARIOS = sum(len(v) for v in ALL_CATEGORIES.values())
    return ALL_CATEGORIES, SCENARIO_BY_ID


# --------------------------------------------------------------------------- #
# Computed at import time — mirrors the old scenarios/__init__.py interface
# --------------------------------------------------------------------------- #
by_cat, by_id = _load_yaml_scenarios()
ALL_CATEGORIES: dict[str, list[type[Scenario]]] = by_cat
SCENARIO_BY_ID: dict[str, type[Scenario]] = by_id
TOTAL_SCENARIOS: int = sum(len(v) for v in ALL_CATEGORIES.values())

__all__ = [
    "DATA_DIR",
    "PHASE_TYPES",
    "ALL_CATEGORIES",
    "SCENARIO_BY_ID",
    "TOTAL_SCENARIOS",
    "load_all",
    "reload",
]
