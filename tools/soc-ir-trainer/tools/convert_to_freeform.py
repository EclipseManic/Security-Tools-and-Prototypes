"""
tools/convert_to_freeform.py
Convert format v1 (multiple-choice) YAML scenarios to format v2 (free-text).

Transformation per file:
- format_version: 2
- incident.opening derived from the full summary (first ~2 sentences)
- every phase gains: id, phase_type (NIST 800-61 progression by position),
  guidance (what/action/why), hint + progressive hints (derived from the
  non-ideal choice explanations), ideal_concepts (auto-extracted from the
  ideal choice), reference_answer (ideal choice + explanation),
  followup_good/weak (next phase's situation, with a nudge on the weak path),
  next (sequential phase ids)
- `choices` and `source_file` are removed

Round-trip safe: when a phase is already v2 (no `choices`), its curated
reference_answer / hint / hints / ideal_concepts / followups / guidance /
phase_type / next / next_weak are preserved unchanged.

Usage:
    python tools/convert_to_freeform.py --dry-run          # plan only (default)
    python tools/convert_to_freeform.py --apply --yes      # convert in place
    python tools/convert_to_freeform.py --apply --yes --backup  # backup originals first
"""

from __future__ import annotations

import re
import sys
import shutil
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml

DATA_DIR = ROOT / "scenarios" / "data"
SKIP_DIRS = {"generated"}
ARCHIVE_DIR = ROOT / "scenarios_archive" / "v2_convert"

# --------------------------------------------------------------------------- #
# Phase-type templates
# --------------------------------------------------------------------------- #
_GUIDANCE_TEMPLATES = {
    "triage": {
        "what": "Identify the alert: what fired, which assets/accounts are involved, and its severity.",
        "action": "Take your next concrete action (query, tool, or decision).",
        "why": "Rapid scoping decides everything downstream — triage is where containment starts.",
    },
    "analysis": {
        "what": "State what the evidence tells you about scope, access, and privilege.",
        "action": "Pick the next analysis step that confirms or rules out compromise.",
        "why": "Evidence drives decisions — confirm the attacker's reach before acting.",
    },
    "containment": {
        "what": "Identify what must be isolated or disabled to stop the spread.",
        "action": "Execute the containment step (accounts, hosts, egress, or services).",
        "why": "Containment limits the blast radius while evidence is preserved.",
    },
    "eradication": {
        "what": "Identify the root cause and all persistence artifacts left behind.",
        "action": "Remove the threat and remediate the systems (clean, rotate, reimage).",
        "why": "The incident is not over until the attacker's footholds are gone.",
    },
    "recovery": {
        "what": "Identify what must be restored and how you will validate it.",
        "action": "Restore operations safely and verify integrity before normal use.",
        "why": "Recovery must be verified — restoring a compromised system just re-breaks it.",
    },
    "lessons": {
        "what": "Summarize what happened, what was missed, and what worked.",
        "action": "Define concrete improvements (detection, playbooks, training, controls).",
        "why": "The post-incident review is what turns an incident into a defense.",
    },
}

_HINT_DEFAULTS = {
    "triage": [
        "Start by defining what you need to know to scope this.",
        "Consider pulling the relevant logs for the affected window.",
        "Think about which accounts or assets could be affected.",
    ],
    "analysis": [
        "Look for the evidence trail: logs, connections, and process activity.",
        "Cross-reference findings with identity and privilege context.",
    ],
    "containment": [
        "Think about what the attacker still has access to.",
        "Consider the affected accounts and their privilege level.",
        "Preserve evidence before disrupting anything.",
    ],
    "eradication": [
        "Find and remove every persistence artifact, not just the visible one.",
        "Rotate or reset any credentials the attacker may have touched.",
    ],
    "recovery": [
        "Restore from known-good state, then validate before reopening access.",
        "Watch for signs of re-compromise during recovery.",
    ],
    "lessons": [
        "Focus on concrete improvements, not blame.",
        "Update detection rules, playbooks, and training from this incident.",
    ],
}

_CONCEPT_DEFAULTS = {
    "triage": ["alert triage", "affected assets", "severity", "evidence", "scope"],
    "analysis": ["log analysis", "evidence", "scope", "privilege", "indicators"],
    "containment": ["containment", "isolate", "preserve evidence", "stop spread", "affected accounts"],
    "eradication": ["remove persistence", "remediate", "rotate credentials", "verify integrity", "root cause"],
    "recovery": ["restore services", "validation", "monitoring", "backup restore", "verify integrity"],
    "lessons": ["lessons learned", "documentation", "detection improvement", "stakeholder update", "remediation"],
}

# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #
_STOPWORDS = {
    "the", "and", "for", "with", "from", "your", "all", "that", "this", "are", "was",
    "were", "has", "had", "have", "not", "but", "their", "them", "they", "then", "than",
    "you", "its", "any", "will", "would", "should", "can", "could", "which", "who",
    "whom", "when", "where", "what", "how", "into", "onto", "over", "under", "upon",
    "before", "after", "during", "within", "without", "between", "each", "every",
    "both", "few", "more", "most", "other", "some", "such", "only", "own", "same",
    "so", "too", "very", "also", "just", "being", "been", "does", "did", "do", "is",
    "am", "of", "to", "in", "on", "at", "by", "as", "or", "if", "it", "be", "via",
    "using", "used", "use", "may", "might", "must", "need", "needs", "new", "now",
}

_TRIVIAL_VERBS = {
    "use", "uses", "make", "makes", "take", "takes", "get", "gets", "set", "sets",
    "check", "checks", "look", "looks", "want", "wants", "ensure", "run", "runs",
    "call", "calls", "ask", "asks", "keep", "keeps", "start", "starts", "stop",
    "stops", "add", "adds", "send", "sends", "put", "puts", "see", "sees", "show",
    "shows", "find", "finds", "give", "gives", "try", "tries", "turn", "open",
    "close", "enable", "disable", "force", "block", "pull", "push", "go", "move",
    "work", "create", "delete", "remove", "reset", "rotate", "restart", "reboot",
    "kill", "escalate", "notify", "inform", "alert", "continue",
}

_NOISE_TOKENS = {"utc", "ips", "ip", "o'clock", "e.g", "etc", "i.e"}


def _split_sentences(text: str) -> list[str]:
    """Split into sentences on [.!?] followed by whitespace, keeping them intact."""
    text = (text or "").strip()
    if not text:
        return []
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


def _first_sentence(text: str) -> str:
    sents = _split_sentences(text)
    return sents[0] if sents else (text or "").strip()


def _phase_type_for(i: int, n: int) -> str:
    """NIST 800-61 lifecycle progression by phase position."""
    if n <= 1:
        return "lessons"
    pct = i / (n - 1)
    if pct < 0.15:
        return "triage"
    if pct < 0.35:
        return "analysis"
    if pct < 0.60:
        return "containment"
    if pct < 0.80:
        return "eradication"
    if pct < 0.95:
        return "recovery"
    return "lessons"


def _slugify_id(title: str) -> str:
    """'Phase 1 — VPN Authentication Anomaly Alert' -> 'vpn_authentication_anomaly_alert'."""
    slug = re.sub(r"[^a-z0-9]+", "_", (title or "").lower()).strip("_")
    slug = re.sub(r"^phase_\d+_*", "", slug)
    if not slug:
        slug = "phase"
    return slug


def _derive_opening(summary: str) -> str:
    sents = _split_sentences(summary)
    opening = " ".join(sents[:2])
    if len(opening) > 420:
        opening = opening[:420].rsplit(" ", 1)[0].rstrip(",. ;:") + "\u2026"
    return opening or "An incident has occurred."


# --------------------------------------------------------------------------- #
# Per-phase derivation
# --------------------------------------------------------------------------- #
def _extract_concepts(ideal_text: str, phase_type: str, cap: int = 8, minimum: int = 5) -> list[str]:
    """Extract 5-8 short concept phrases from the ideal answer text."""
    tokens = re.findall(r"[a-z][a-z0-9\-]{2,}", (ideal_text or "").lower())
    meaningful = [t for t in tokens if t not in _STOPWORDS and t not in _NOISE_TOKENS]

    bigrams: list[str] = []
    for i in range(len(meaningful) - 1):
        a, b = meaningful[i], meaningful[i + 1]
        if a in _TRIVIAL_VERBS or b in _NOISE_TOKENS or len(a) < 3 or len(b) < 3:
            continue
        pair = f"{a} {b}"
        if pair not in bigrams:
            bigrams.append(pair)

    concepts = bigrams[:cap]
    for d in _CONCEPT_DEFAULTS.get(phase_type, _CONCEPT_DEFAULTS["triage"]):
        if len(concepts) >= minimum:
            break
        if d not in concepts:
            concepts.append(d)
    return concepts[:cap]


def _derive_hints(phase: dict, phase_type: str) -> tuple[str, list[str]]:
    """hint = first sentence of the ideal explanation; hints = 'watch out' clauses."""
    choices = phase.get("choices", [])
    ideal = next((c for c in choices if isinstance(c, dict) and c.get("is_ideal")), None)

    hint = _first_sentence((ideal or {}).get("explanation", ""))
    if not hint or len(hint) < 25:
        hint = _HINT_DEFAULTS[phase_type][0]

    hints: list[str] = []
    warn_re = re.compile(r"\b(but|however|without|premature|does not|misses|overreaction|negligent|not yet|still)\b", re.IGNORECASE)
    for ch in choices:
        if not isinstance(ch, dict) or ch.get("is_ideal"):
            continue
        for sent in _split_sentences(ch.get("explanation", "")):
            if warn_re.search(sent) and len(sent) > 40:
                hints.append(sent[:220].rstrip())
                break
    for d in _HINT_DEFAULTS[phase_type][1:]:
        if len(hints) >= 2:
            break
        if d not in hints:
            hints.append(d)
    return hint, hints[:3]


def _build_guidance(phase: dict, phase_type: str) -> dict[str, str]:
    tpl = _GUIDANCE_TEMPLATES[phase_type]
    return {
        "what": tpl["what"],
        "action": phase.get("prompt", "").strip() or tpl["action"],
        "why": tpl["why"],
    }


def _build_followups(ideal_expl: str, next_situation: str, executive_brief: str) -> tuple[str, str]:
    if next_situation:
        nudge = _first_sentence(ideal_expl)
        weak = f"{nudge}\n\n{next_situation}" if nudge else next_situation
        return next_situation, weak
    wrap = (executive_brief or "The incident is contained. Document lessons learned and update detection playbooks.").strip()
    return f"The scenario ends here.\n\n{wrap}", f"The scenario ends here.\n\n{wrap}"


# --------------------------------------------------------------------------- #
# File transformation
# --------------------------------------------------------------------------- #
def transform(data: dict) -> dict:
    incident = data.get("incident", {}) or {}
    summary = incident.get("summary", incident.get("opening", ""))
    phases_in = data.get("phases", [])
    n = len(phases_in)

    # Pass 1: stable, unique phase ids. Curated v2 files already carry ids and
    # navigation targets, so those must win; v1 phases fall back to a title slug.
    ids: list[str] = []
    seen: set[str] = set()
    for ph in phases_in:
        pid = str(ph.get("id") or "").strip() or _slugify_id(ph.get("title", ""))
        base = pid
        suffix = 2
        while pid in seen:
            pid = f"{base}_{suffix}"
            suffix += 1
        seen.add(pid)
        ids.append(pid)

    phases_out: list[dict] = []
    for i, ph in enumerate(phases_in):
        phase_type = ph.get("phase_type") or _phase_type_for(i, n)
        ideal = next((c for c in ph.get("choices", []) if isinstance(c, dict) and c.get("is_ideal")), None)
        ideal_text = (ideal or {}).get("text", "")
        ideal_expl = (ideal or {}).get("explanation", "")
        ref_parts = [p.strip() for p in (ideal_text, f"Why: {ideal_expl}" if ideal_expl else "") if p]
        reference_answer = "\n\n".join(ref_parts) or ph.get("reference_answer", "")
        next_situation = phases_in[i + 1].get("situation", "") if i + 1 < n else ""

        if ideal is not None:
            # v1 input: derive hints, followups, concepts and guidance from the choices
            hint, hints = _derive_hints(ph, phase_type)
            fg, fw = _build_followups(ideal_expl, next_situation, data.get("executive_brief", ""))
            concepts = _extract_concepts(ideal_text, phase_type)
            guidance = _build_guidance(ph, phase_type)
        else:
            # v2 input: round-trip faithfully, keep curated content as-is
            hint = ph.get("hint", "") or _HINT_DEFAULTS[phase_type][0]
            hints = ph.get("hints", []) or []
            fg = ph.get("followup_good", "") or next_situation or "The scenario ends here."
            fw = ph.get("followup_weak", "") or fg
            concepts = ph.get("ideal_concepts") or _extract_concepts(reference_answer, phase_type)
            guidance = ph.get("guidance") or _build_guidance(ph, phase_type)

        out = {
            "id": ids[i],
            "phase_type": phase_type,
            "title": ph.get("title", ""),
            "situation": ph.get("situation", ""),
            "prompt": ph.get("prompt", "What is your next action?"),
            "guidance": guidance,
            "hint": hint,
            "hints": hints,
            "ideal_concepts": (concepts or [])[:8],
            "reference_answer": reference_answer,
            "followup_good": fg,
            "followup_weak": fw,
        }
        if ph.get("next") and ph["next"] in {q.get("id") for q in phases_in}:
            out["next"] = ph["next"]
        elif i + 1 < n:
            out["next"] = ids[i + 1]
        if ph.get("next_weak"):
            out["next_weak"] = ph["next_weak"]
        for key in ("mitre_tactic", "mitre_technique"):
            if ph.get(key):
                out[key] = ph[key]
        if ph.get("role_prompts"):
            out["role_prompts"] = ph["role_prompts"]
        phases_out.append(out)

    incident_out = {
        "title": incident.get("title", data.get("name", "")),
        "opening": _derive_opening(summary),
        "summary": summary,
    }
    for key in ("compromised_assets", "detected_via", "kill_chain", "mitre_tactics"):
        if incident.get(key):
            incident_out[key] = incident[key]

    out = {
        "id": data.get("id", ""),
        "name": data.get("name", ""),
        "category": data.get("category", ""),
        "format_version": 2,
        "difficulty": data.get("difficulty", "Medium"),
        "soc_tier": data.get("soc_tier", "L1"),
        "roles": data.get("roles", ["analyst"]),
        "industries": data.get("industries", ["all"]),
        "briefings": data.get("briefings", {}),
        "executive_brief": data.get("executive_brief", ""),
        "incident": incident_out,
        "phases": phases_out,
    }
    return out


def convert_file(path: Path, write: bool) -> tuple[str, dict]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        return "skip", {"reason": "not a mapping"}
    if data.get("format_version") == 2:
        return "skip", {"reason": "already v2"}
    out = transform(data)
    stats = {"phases": len(out["phases"]), "concepts_ok": all(len(p["ideal_concepts"]) >= 5 for p in out["phases"])}
    if write:
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(out, f, allow_unicode=True, sort_keys=False)
    return "convert", stats


def _backup(paths: list[Path]) -> Path | None:
    if not paths:
        return None
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive = ARCHIVE_DIR / stamp
    for p in paths:
        dest = archive / p.relative_to(DATA_DIR)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
    print(f"backed up {len(paths)} originals -> {archive.relative_to(ROOT)}")
    return archive


def scan() -> list[Path]:
    paths = []
    for p in sorted(DATA_DIR.rglob("*.yaml")):
        if p.parent.name in SKIP_DIRS:
            continue
        paths.append(p)
    return paths


def verify() -> None:
    import scenarios.loader as loader
    by_cat = loader._load_yaml_scenarios()[0]
    names = {p.stem for p in DATA_DIR.rglob("*.yaml") if p.parent.name not in SKIP_DIRS}
    loaded: set[str] = set()
    issues: list[str] = []
    v2_count = 0
    for clss in by_cat.values():
        for cls in clss:
            loaded.add(cls._scenario_id)
            if cls.meta.format_version >= 2:
                v2_count += 1
                for p in cls.phases:
                    if not p.ideal_concepts:
                        issues.append(f"{cls._scenario_id}:{p.id or p.title} missing ideal_concepts")
                    if not p.reference_answer:
                        issues.append(f"{cls._scenario_id}:{p.id or p.title} missing reference_answer")
                    if not p.followup_good or not p.followup_weak:
                        issues.append(f"{cls._scenario_id}:{p.id or p.title} missing followups")
    missing = names - loaded
    if missing:
        issues.append(f"YAMLs not loaded: {sorted(missing)}")
    if issues:
        raise RuntimeError("Verification failed:\n  " + "\n  ".join(issues[:15]))
    print(f"Verification OK: {len(names)} YAMLs loaded, {v2_count} in format v2")


def main() -> int:
    args = [a for a in sys.argv[1:] if a.startswith("--")]
    dry_run = "--apply" not in args
    confirm = "--yes" in args
    backup = "--backup" in args
    if not dry_run and not confirm:
        print("Refusing: --apply requires --yes")
        return 1

    paths = scan()
    to_convert: list[Path] = []
    skipped = 0
    print(f"=== CONVERT TO FORMAT V2 — {len(paths)} YAML files ===\n")
    for p in paths:
        verdict, stats = convert_file(p, write=False)
        if verdict == "convert":
            to_convert.append(p)
            print(f"  convert {p.relative_to(DATA_DIR)}  ({stats['phases']} phases, concepts_ok={stats['concepts_ok']})")
        else:
            skipped += 1
    print(f"\nTOTAL: {len(paths)} files -> convert {len(to_convert)} / already-v2 or skip {skipped}")

    if dry_run:
        print("Run with --apply --yes to execute the conversion.")
        return 0

    if backup:
        _backup(to_convert)
    for p in to_convert:
        verdict, stats = convert_file(p, write=True)
        if verdict != "convert":
            print(f"WARN: {p.name} -> {stats}")
    print(f"\nConverted {len(to_convert)} files. Verifying...")
    try:
        verify()
    except Exception as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
