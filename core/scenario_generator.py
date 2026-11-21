"""
core/scenario_generator.py
AI-powered scenario generation via OpenRouter.

Generates a complete YAML scenario in a single one-shot call, validates it
against the schema + MITRE domain map, sanitizes HTML, and saves to
scenarios/data/generated/. Falls back to domain-filtered prebuilt scenarios
if generation fails validation after 2 retries.
"""

from __future__ import annotations

import json
import re
import yaml
import httpx
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from config import (
    GENERATOR_TEMPERATURE,
    GENERATOR_TIMEOUT,
    OPENROUTER_API_KEY,
    OPENROUTER_API_URL,
    OPENROUTER_MODEL,
)
from core import ui
from scenarios import ALL_CATEGORIES
from scenarios.base import ScenarioMeta, Phase

# Load the shipped MITRE domain map (falls back to the legacy tooling copy)
try:
    from core.mitre import load_domain_map

    _DOMAIN_MITRE_MAP: dict[str, list[str]] = load_domain_map()
except Exception:
    try:
        _MITRE_MAP_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_domain_map.json"
        with open(_MITRE_MAP_PATH, encoding="utf-8") as _f:
            _DOMAIN_MITRE_MAP = json.load(_f)
    except Exception:
        _DOMAIN_MITRE_MAP = {}


# Temperature for generation (higher than eval's 0.3 for creative variety)
_GEN_TEMPERATURE = GENERATOR_TEMPERATURE
_MAX_RETRIES = 2
_RETRY_DELAY = 5
_GEN_TIMEOUT = GENERATOR_TIMEOUT


# --------------------------------------------------------------------------- #
# Schema validation (format v2)
# --------------------------------------------------------------------------- #
_REQUIRED_TOP_KEYS = {"id", "name", "category", "format_version", "incident", "phases"}
_REQUIRED_PHASE_KEYS = {
    "id", "phase_type", "title", "situation", "guidance", "hint",
    "ideal_concepts", "reference_answer", "followup_good", "followup_weak", "next",
}
_INCIDENT_KEYS = {"title", "opening", "summary"}
_PHASE_TYPES = {"triage", "analysis", "containment", "eradication", "recovery", "lessons"}
_MIN_PHASES = 4
_MAX_PHASES = 6
_MIN_IDEAL_CONCEPTS = 5
_MAX_IDEAL_CONCEPTS = 8


def _strip_html(text: str) -> str:
    """Remove script tags and any HTML tags from generated text."""
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def _sanitize_scenario(data: dict[str, Any]) -> None:
    """Strip HTML from every string field (top-level, incident, phases)."""
    def _clean_str(v: Any) -> Any:
        if isinstance(v, str):
            return _strip_html(v)
        if isinstance(v, list):
            return [_clean_str(i) for i in v]
        if isinstance(v, dict):
            return {k: _clean_str(x) for k, x in v.items()}
        return v

    for key in ("id", "name"):
        if isinstance(data.get(key), str):
            data[key] = _strip_html(data[key])
    incident = data.get("incident")
    if isinstance(incident, dict):
        for k in incident:
            incident[k] = _clean_str(incident[k])
    for ph in data.get("phases", []):
        if isinstance(ph, dict):
            for k in ph:
                ph[k] = _clean_str(ph[k])


def _validate_scenario(data: dict[str, Any], domain: str = "") -> list[str]:
    """Validate a parsed v2 YAML scenario. Returns list of error strings (empty = valid).

    P6 fixes: category is validated against the taxonomy map directly (the old
    validator accepted any category via `| {cat}` — a tautology); phases must be
    free-form v2 (guidance/hints/ideal_concepts/reference_answer/followups/next);
    `next` ids must resolve; 4-6 phases; HTML stripped."""
    errors: list[str] = []

    # Top-level keys
    missing = _REQUIRED_TOP_KEYS - set(data.keys())
    if missing:
        errors.append(f"Missing required top-level keys: {missing}")

    if not isinstance(data.get("id"), str) or not data["id"]:
        errors.append("'id' must be a non-empty string")

    if not isinstance(data.get("name"), str) or not data["name"]:
        errors.append("'name' must be a non-empty string")

    if data.get("format_version") != 2:
        errors.append("'format_version' must be 2")

    cat = data.get("category", "")
    if cat not in _DOMAIN_MITRE_MAP:
        errors.append(f"'category' must be one of: {', '.join(sorted(_DOMAIN_MITRE_MAP.keys()))}")

    # Incident block
    incident = data.get("incident", {})
    if not isinstance(incident, dict):
        errors.append("'incident' must be a dict")
    else:
        inc_missing = _INCIDENT_KEYS - set(incident.keys())
        if inc_missing:
            errors.append(f"Missing incident keys: {inc_missing}")

    # Phases
    phases = data.get("phases", [])
    if not isinstance(phases, list):
        errors.append("'phases' must be a list")
        return errors
    if len(phases) < _MIN_PHASES:
        errors.append(f"Need at least {_MIN_PHASES} phases (got {len(phases)})")
    elif len(phases) > _MAX_PHASES:
        errors.append(f"Need at most {_MAX_PHASES} phases (got {len(phases)})")

    phase_ids = {p.get("id") for p in phases if isinstance(p, dict)}
    for i, ph in enumerate(phases):
        if not isinstance(ph, dict):
            errors.append(f"Phase {i+1} is not a dict")
            continue
        ph_missing = _REQUIRED_PHASE_KEYS - set(ph.keys())
        if ph_missing:
            errors.append(f"Phase {i+1} missing keys: {ph_missing}")

        ptype = ph.get("phase_type", "")
        if ptype not in _PHASE_TYPES:
            errors.append(f"Phase {i+1} phase_type '{ptype}' must be one of: {sorted(_PHASE_TYPES)}")

        guidance = ph.get("guidance", {})
        if not isinstance(guidance, dict) or not {"what", "action", "why"} <= set(guidance.keys()):
            errors.append(f"Phase {i+1} 'guidance' must be a dict with what/action/why")

        if not str(ph.get("hint", "")).strip():
            errors.append(f"Phase {i+1} 'hint' must be non-empty")

        concepts = ph.get("ideal_concepts", [])
        if not isinstance(concepts, list) or not (
            _MIN_IDEAL_CONCEPTS <= len(concepts) <= _MAX_IDEAL_CONCEPTS
        ):
            errors.append(
                f"Phase {i+1} 'ideal_concepts' must be a list of "
                f"{_MIN_IDEAL_CONCEPTS}-{_MAX_IDEAL_CONCEPTS} items (got "
                f"{len(concepts) if isinstance(concepts, list) else 'non-list'})"
            )

        if not str(ph.get("reference_answer", "")).strip():
            errors.append(f"Phase {i+1} 'reference_answer' must be non-empty")
        if not str(ph.get("followup_good", "")).strip():
            errors.append(f"Phase {i+1} 'followup_good' must be non-empty")
        if not str(ph.get("followup_weak", "")).strip():
            errors.append(f"Phase {i+1} 'followup_weak' must be non-empty")

        nxt = ph.get("next", "")
        if nxt and nxt not in phase_ids:
            errors.append(f"Phase {i+1} 'next' points to unknown phase id '{nxt}'")

        # MITRE technique must belong to the category's taxonomy map
        mitre_tech = ph.get("mitre_technique", "")
        if mitre_tech:
            domain_techs = _DOMAIN_MITRE_MAP.get(cat, [])
            tech_id = mitre_tech.strip().upper().replace(" ", "")
            tech_match = re.match(r"(T\d+(?:\.\d+)?)", tech_id)
            tech_id = tech_match.group(1) if tech_match else tech_id
            _tech_ok = tech_id in domain_techs
            if not _tech_ok:
                for dt in domain_techs:
                    if dt.startswith(tech_id.split(".")[0]) and not dt.startswith(tech_id + "."):
                        _tech_ok = True
                        break
            if domain_techs and not _tech_ok:
                errors.append(
                    f"Phase {i+1} MITRE technique '{mitre_tech}' not in domain '{cat}' "
                    f"(valid: {domain_techs[:5]}...)"
                )

    _sanitize_scenario(data)
    return errors


# --------------------------------------------------------------------------- #
# Schema reference (compact — sent in system prompt for one-shot generation)
# --------------------------------------------------------------------------- #
_SCHEMA_REF = """
YAML Schema Reference (generate EXACTLY this structure, format v2 free-text):

format_version: 2
id: string  # unique slug, e.g. "generated_mitre_phishing_20260806"
name: string  # short scenario name
category: string  # MUST be exactly one of the taxonomy domains: Endpoint, Web App, Cloud, Identity & Access, Network, AI & ML, Advanced Threats
difficulty: string  # Easy | Medium | Hard (match the requested learner level)
soc_tier: string  # L1 | L2 | L3 | L1-L2 | L1-L3 | L2-L3
roles: [string, ...]  # e.g. ["analyst"]
industries: [string, ...]  # e.g. ["all"]
briefings:
  analyst: string  # 2-3 sentences, role-aware briefing

incident:
  title: string  # attacker-facing title
  opening: string  # ONE short scene-setting sentence shown to the user
  summary: string  # full narrative, 3-5 paragraphs, blue-team framing (attack already happened)
  compromised_assets: [string, ...]
  detected_via: string
  kill_chain: [string, ...]  # MITRE kill-chain stages
  mitre_tactics: [string, ...]

phases:  # 4-6 phases, following the IR lifecycle (triage -> analysis -> containment -> eradication -> recovery -> lessons)
  - id: string  # unique slug within this scenario (navigation target)
    phase_type: string  # triage | analysis | containment | eradication | recovery | lessons
    title: string  # e.g. "Phase 1 — Initial Alert Triage"
    situation: string  # what the analyst sees at this phase
    prompt: string  # what the analyst is asked to do
    guidance:
      what: string  # what to look at / identify
      action: string  # what action to take (short)
      why: string  # why this matters
    hint: string  # always-visible first hint
    hints: [string, ...]  # 1-2 progressive hints (revealed by '?')
    ideal_concepts: [string, ...]  # 5-8 short offline-scoring keywords
    reference_answer: string  # full ideal response (revealed by '??')
    followup_good: string  # what happens after a strong answer (non-empty)
    followup_weak: string  # what happens after a weak answer (non-empty)
    next: string  # id of the next phase ("" for the final phase)
    mitre_tactic: string  # e.g. "Initial Access"
    mitre_technique: string  # MUST be one of the VALID techniques listed for the category

executive_brief: string  # 2-3 sentence CISO-level summary
"""


# --------------------------------------------------------------------------- #
# Generation with retry + fallback
# --------------------------------------------------------------------------- #
class ScenarioGenerator:
    """Generates custom YAML scenarios via OpenRouter, validated + sanitized."""

    def __init__(self) -> None:
        self.api_key = OPENROUTER_API_KEY
        self.model = OPENROUTER_MODEL

    def generate(
        self,
        domain: str,
        weaknesses: list[str],
        role: str,
        user_name: str,
        learner_level: Optional[str] = None,
        custom_prompt: Optional[str] = None,
    ) -> Optional[str]:
        """
        Generate a format-v2 scenario YAML for the given domain, targeting the
        user's weak MITRE techniques and adjusted to their learner level.

        Returns path to saved YAML file, or None if all attempts fail
        (the caller then falls back to a prebuilt targeting the same technique).
        """
        if not self.api_key:
            ui.write_warn("OPENROUTER_API_KEY not set — skipping AI generation.")
            return None

        # Validate domain has known techniques
        valid_techs = _DOMAIN_MITRE_MAP.get(domain, [])
        if not valid_techs:
            ui.write_warn(f"No MITRE map for domain '{domain}' — skipping AI generation.")
            return None

        # Difficulty progression: learner level -> scenario difficulty
        try:
            from core.adaptive import difficulty_for_level
        except ImportError:  # pragma: no cover
            difficulty_for_level = lambda lvl: "Medium"
        difficulty = difficulty_for_level(learner_level) if learner_level else "balanced"

        # Build weakness context
        weak_str = "No specific weaknesses detected — generate a balanced scenario."
        if weaknesses:
            weak_str = f"Target these weak techniques: {', '.join(weaknesses)}"

        system_prompt = (
            f"You are a cybersecurity scenario generator for a blue-team IR trainer.\n"
            f"Generate a COMPLETE, VALID format-v2 (free-text) YAML scenario for the "
            f"domain: '{domain}'.\n"
            f"Role context: {role}\n"
            f"Weakness context: {weak_str}\n"
            f"Learner level: {learner_level or 'unknown'} — use difficulty '{difficulty}'.\n"
            f"User: {user_name}\n"
            f"\n"
            f"VALID MITRE techniques for '{domain}': {', '.join(valid_techs)}\n"
            f"Use ONLY these techniques in phase mitre_technique fields.\n"
            f"\n"
            f"{_SCHEMA_REF}\n"
            f"\n"
            f"Generate valid YAML matching the schema EXACTLY. "
            f"Include 4-6 phases following the IR lifecycle (triage through lessons). "
            f"Every phase MUST have: guidance (what/action/why), a hint, 5-8 "
            f"ideal_concepts, a non-empty reference_answer, non-empty followup_good "
            f"and followup_weak, and a 'next' id pointing to a phase that exists "
            f"('' for the final phase).\n"
            f"Do NOT include markdown fences. Start with 'format_version: 2' directly.\n"
            f"Keep text realistic, professional, no placeholder content."
        )

        user_prompt = custom_prompt or (
            f"Generate a blue-team incident response training scenario in the "
            f"'{domain}' domain, difficulty '{difficulty}', for a learner at "
            f"'{learner_level or 'unknown'}' level. The player is a {role}. "
            f"{weak_str}. "
            f"4-6 free-text phases (no choices), each with guidance, hints, "
            f"ideal_concepts, reference_answer, followups and next links. "
            f"Use only MITRE techniques from the {domain} domain list. "
            f"Output strict YAML matching the schema above. No markdown, no commentary."
        )

        for attempt in range(1, _MAX_RETRIES + 1):
            if attempt > 1:
                ui.write_warn(f"Generation retry {attempt}/{_MAX_RETRIES}...")
                time.sleep(_RETRY_DELAY)

            ui.write_info(f"Generating custom scenario (attempt {attempt}/{_MAX_RETRIES})...")
            raw_yaml = self._call_openrouter(system_prompt, user_prompt)

            if not raw_yaml:
                continue

            parsed = self._try_parse_yaml(raw_yaml)
            if parsed is None:
                continue

            errors = _validate_scenario(parsed, domain)
            if errors:
                ui.write_warn(f"Validation errors: {errors[:3]}")
                continue

            # Sanitize + fix ID for uniqueness
            parsed["id"] = self._unique_id(parsed.get("id", "generated"), domain)
            if not _validate_scenario(parsed, domain):
                # Re-validate after ID fix
                saved_path = self._save(parsed, domain)
                if saved_path:
                    ui.write_success(f"Scenario saved: {saved_path}")
                    return saved_path

        ui.write_error("All generation attempts failed validation.")
        return None

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _call_openrouter(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Single OpenRouter API call. Returns raw text response."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "temperature": _GEN_TEMPERATURE,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            with httpx.Client(timeout=_GEN_TIMEOUT) as client:
                resp = client.post(OPENROUTER_API_URL, headers=headers, json=payload)
            if resp.status_code == 429:
                ui.write_warn("Rate limited (429). Will retry.")
                return None
            resp.raise_for_status()
            data = resp.json()
            if not data.get("choices"):
                ui.write_warn("No choices in OpenRouter response.")
                return None
            msg = data["choices"][0].get("message", {})
            return msg.get("content", "")
        except Exception as e:
            ui.write_warn(f"OpenRouter call failed: {type(e).__name__}: {e}")
            return None

    def _try_parse_yaml(self, raw: str) -> Optional[dict[str, Any]]:
        """Strip fences and parse YAML."""
        cleaned = re.sub(r"```(?:yaml)?\s*\n?", "", raw).strip()
        cleaned = re.sub(r"\n?```\s*$", "", cleaned).strip()
        try:
            result = yaml.safe_load(cleaned)
            if isinstance(result, dict):
                return result
            ui.write_warn("Parsed content is not a YAML dict.")
            return None
        except yaml.YAMLError as e:
            ui.write_warn(f"YAML parse error: {e}")
            return None

    def _unique_id(self, base_id: str, domain: str) -> str:
        """Ensure unique scenario ID."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = re.sub(r"[^a-z0-9]", "_", domain.lower())
        safe_base = re.sub(r"[^a-z0-9_]", "_", base_id.lower())
        return f"{safe_base}_{safe_domain}_{ts}"

    def _save(self, data: dict[str, Any], domain: str) -> Optional[str]:
        """Save the validated YAML to scenarios/data/generated/."""
        out_dir = Path(__file__).resolve().parent.parent / "scenarios" / "data" / "generated"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = re.sub(r"[^a-z0-9]", "_", domain.lower())
        filename = f"generated_{safe_domain}_{ts}.yaml"
        out_path = out_dir / filename

        # Ensure id is unique in filename
        data["id"] = f"gen_{safe_domain}_{ts}"

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            return str(out_path)
        except Exception as e:
            ui.write_warn(f"Failed to save YAML: {e}")
            return None


__all__ = ["ScenarioGenerator", "_DOMAIN_MITRE_MAP", "_validate_scenario"]
