"""
core/ai_evaluator.py
Sends the ENTIRE recorded session log to OpenRouter in a SINGLE request
and returns a detailed, structured evaluation.

Uses the Nemotron model by default. The prompt is designed to produce
rich, detailed analysis — not just a score.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

import config
from core.recorder import SessionLog
from core import ui
from core.grading import BANDS_TEXT, grade_for


# --------------------------------------------------------------------------- #
# System prompt — produces rich, parseable JSON for the reporter
# --------------------------------------------------------------------------- #
EVAL_SYSTEM_PROMPT = """You are a senior SOC manager evaluating a trainee's incident-response simulation.
The attack already happened; the trainee chose actions at each IR phase.

CRITICAL RULES:
1. Return ONLY a single valid JSON object — no markdown fences, no text before or after.
2. Use double quotes for all strings. No trailing commas.
3. Every array must have at least 1 item.
4. All numeric fields must be actual numbers, not strings.
5. For detailed fields (what_did_right, what_did_wrong, how_to_improve, current_gap), write 1-2 clear sentences.
6. For tightening_recommendations, ALWAYS describe what is currently lacking (current_gap) BEFORE describing the fix.
7. Be specific — name real tools, frameworks, and standards (NIST 800-61, MITRE ATT&CK, SANS, OWASP, CIS).
8. Score fairly: {BANDS_TEXT}.
9. Every trainee answer was ALSO scored offline 0-10 against reference concepts. Use that as evidence, not as the verdict: confirm it, correct it, or explain why you disagree.
10. For each phase, additionally grade the trainee's THREE answer parts separately (0-10 each): what_score = how completely they recognized/detected what happened, action_score = how effective their response action was, why_score = how well they justified it.
11. In weaknesses, missed_opportunities, and next_training, be SPECIFIC — reference the actual phase and what was missing (name real tools: SIEM queries, EDR, MFA enforcement, log sources).

Return this EXACT JSON structure (all fields required):
{
  "score": <int 0-100>,
  "grade": "<Expert|Proficient|Intermediate|Novice|Needs Work>",
  "overall_assessment": "<2-3 sentences: overall quality, key pattern, one-line verdict>",
  "final_verdict": "<1 sentence: clear pass/fail judgment>",
  "phase_evaluations": [
    {
      "phase_number": <int>,
      "phase_title": "<phase title>",
      "user_action": "<what the analyst actually did>",
      "user_action_type": "<option|custom>",
      "ideal_action": "<what they should have done>",
      "correctness": <int 0-10>,
      "offline_score": <int 0-10, their recorded offline concept-hit score>,
      "what_score": <int 0-10>,
      "action_score": <int 0-10>,
      "why_score": <int 0-10>,
      "analysis": "<1-2 sentences: overall assessment of this phase>",
      "what_did_right": "<1 sentence: what was good about their response>",
      "what_did_wrong": "<1 sentence: what was missing or incorrect>",
      "how_to_improve": "<1 sentence: specific next time advice>",
      "mitre_relevance": "<MITRE Tactic / Technique name>"
    }
  ],
  "strengths": ["<1 sentence each: 2-4 specific strengths>"],
  "weaknesses": ["<1 sentence each: 2-4 specific weaknesses>"],
  "tightening_recommendations": [
    {
      "area": "<area name>",
      "current_gap": "<1 sentence: what is currently lacking>",
      "recommendation": "<1 sentence: specific fix to implement>",
      "priority": "<Critical|High|Medium|Low>",
      "reference": "<framework, standard, or resource name>"
    }
  ],
  "missed_opportunities": ["<1 sentence each: 2-3 things they could have done>"],
  "tools_used": ["<tool/framework name>"],
  "tools_missing": ["<tool/framework name that should have been used>"],
  "communication_grade": "<Excellent|Good|Fair|Poor>",
  "communication_feedback": "<1-2 sentences on their response quality>",
  "incident_timeline_recommendation": "<1-2 sentences: recommended IR timeline for this incident>",
  "next_training": ["<1 sentence each: 2-3 recommended next topics>"]
}""".strip()


EVAL_ROLE_SUFFIX = """

When evaluating, apply role-sensitive rubrics based on the player's SOC role:

If the player is the SOC L1 ANALYST, evaluate whether they:
- Properly scoped the breach by pulling the right log sources
- Identified compromised accounts and their privilege level
- Escalated to incident manager at the right time with sufficient context
- Preserved evidence and avoided premature containment actions

If the player is the INCIDENT MANAGER, evaluate whether they:
- Coordinated containment, forensics, and stakeholder communications effectively
- Escalated to the CISO at the right decision points
- Preserved evidence chain and managed forensic isolation
- Triggered legal/regulatory communication preparation at the appropriate time

If the player is the CISO, evaluate whether they:
- Properly assessed regulatory obligations (state breach laws, GDPR, etc.)
- Engaged legal counsel at the right time
- Communicated escalation decisions with appropriate urgency and accuracy
- Considered board/stakeholder communication needs

If the player is an EXECUTIVE (CEO/CFO), evaluate whether they:
- Focused on business impact and stakeholder communication plan
- Requested appropriate technical details without micromanaging
- Allocated resources and set decision deadlines effectively
- Understood the regulatory and financial implications discussed

Always factor the role context into the overall assessment, phase evaluations, and recommendations. The same actions would be evaluated differently depending on the role — do not score executive-level responses by analyst-level technical expectations."""


def _build_user_prompt(session: SessionLog) -> str:
    """Build a compact but complete prompt — avoid duplicating the incident
    summary in every phase block (the AI already read it once)."""
    parts: list[str] = []

     # Role context block (appended before phase data)
    if session.user_role:
        role_labels = {
            "analyst": "SOC Tier-1 Analyst",
            "incident_manager": "Incident Manager",
            "ciso": "CISO",
            "executive": "Executive (CEO/CFO)",
        }
        role_label = role_labels.get(session.user_role, session.user_role.title())
        parts.append(f"PLAYER ROLE: {role_label}")
        if session.industry_filter and session.industry_filter != "all":
            parts.append(f"Industry context: {session.industry_filter}")
        parts.append("")

    # Executive brief — CISO-level summary for leadership-aware evaluation
    if session.executive_brief:
        parts.append(f"EXECUTIVE BRIEF: {session.executive_brief}")
        parts.append("")

    # One-shot incident context
    parts.append(f"INCIDENT: {session.incident_title}")
    parts.append(f"Category: {session.incident_category} | Analyst: {session.user_name}")
    parts.append(f"Detected Via: {session.detected_via}")
    parts.append(f"Compromised Assets: {', '.join(session.compromised_assets) or 'Unknown'}")
    parts.append(f"\nSummary:\n{session.incident_summary}")

    # Compact per-phase log (no repeated situation text)
    parts.append(f"\n--- {len(session.actions)} PHASES COMPLETED ---")
    for a in session.actions:
        offline = f"{a.response_score:.1f}" if a.response_score >= 0 else "n/a"
        parts.append(
            f"\nPhase {a.phase_number}: {a.phase_title}  "
            f"[MITRE: {a.mitre_tactic}/{a.mitre_technique}]\n"
            f"  Prompt: {a.prompt}\n"
            f"  Analyst chose ({a.choice_type}): {a.user_response}\n"
            f"  Ideal answer: {a.ideal_answer}\n"
            f"  Why ideal: {a.reference_explanation}\n"
            f"  Offline: {offline}/10 | hints used: {a.hints_used} | looked up answer: {a.looked_up}"
        )

    parts.append(
        "\nReturn ONLY the JSON evaluation object. No markdown fences."
    )
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Lenient JSON parsing — much more aggressive
# --------------------------------------------------------------------------- #
_FENCE_RE = re.compile(r"```(?:json)?\s*\n?|\n?```\s*", re.MULTILINE)


def _strip_fences(raw: str) -> str:
    cleaned = _FENCE_RE.sub("", raw).strip()
    brace = cleaned.find("{")
    if brace > 0:
        cleaned = cleaned[brace:]
    last = cleaned.rfind("}")
    if last != -1 and last < len(cleaned) - 1:
        cleaned = cleaned[: last + 1]
    return cleaned


def _try_repair_json(text: str) -> str:
    """Fix common JSON issues from LLM output."""
    s = text
    # Remove trailing commas before } or ]
    s = re.sub(r",\s*([\]}])", r"\1", s)
    # Fix unescaped newlines inside strings
    out: list[str] = []
    in_str = False
    esc = False
    for ch in s:
        if esc:
            out.append(ch)
            esc = False
            continue
        if ch == "\\":
            out.append(ch)
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            continue
        if in_str and ch == "\n":
            out.append("\\n")
            continue
        if in_str and ch == "\r":
            out.append("\\r")
            continue
        if in_str and ch == "\t":
            out.append("\\t")
            continue
        out.append(ch)
    return "".join(out)


def _normalize_keys(obj: Any) -> Any:
    """Recursively normalize field names that the AI might return with
    slightly different keys (e.g. 'tightening' vs 'tightening_recommendations')."""
    if not isinstance(obj, dict):
        return obj
    key_map = {
        "tightening": "tightening_recommendations",
        "tightening_rec": "tightening_recommendations",
        "recommendations": "tightening_recommendations",
        "communication_score": "communication_grade",
        "next_scenarios": "next_training",
        "next_steps": "next_training",
    }
    result = {}
    for k, v in obj.items():
        new_key = key_map.get(k, k)
        result[new_key] = _normalize_keys(v)
    return result


def _seed_part_scores(phase: dict[str, Any], action: Any) -> None:
    """Seed what/action/why + offline scores on a phase evaluation from the
    recorded offline scorer data (parts_json / response_score) when the AI
    omitted them."""
    # offline_score from the recorded response_score
    if "offline_score" not in phase:
        raw = getattr(action, "response_score", None)
        phase["offline_score"] = max(0, int(round(float(raw)))) if raw is not None and float(raw) >= 0 else 0

    parts = None
    raw_parts = getattr(action, "parts_json", "")
    if raw_parts:
        try:
            parts = json.loads(raw_parts)
        except Exception:
            parts = None

    for key in ("what_score", "action_score", "why_score"):
        if key in phase:
            continue
        part_key = key.replace("_score", "")
        if parts and isinstance(parts.get("parts"), dict):
            val = parts["parts"].get(part_key, 0)
        else:
            val = phase.get("offline_score", 0)
        try:
            phase[key] = max(0, min(10, int(round(float(val)))))
        except (TypeError, ValueError):
            phase[key] = 0


def _ensure_required_fields(ev: dict[str, Any]) -> dict[str, Any]:
    """Ensure all fields the reporter expects exist, with safe defaults.
    Also enriches nested arrays (phase_evaluations, tightening_recommendations)
    with missing keys that the reporter displays."""
    defaults = {
        "score": 0,
        "grade": "Needs Work",
        "overall_assessment": "Evaluation incomplete.",
        "final_verdict": "Evaluation incomplete.",
        "phase_evaluations": [],
        "strengths": [],
        "weaknesses": [],
        "tightening_recommendations": [],
        "missed_opportunities": [],
        "tools_used": [],
        "tools_missing": [],
        "tools_and_frameworks_used": [],
        "tools_and_frameworks_missing": [],
        "communication_grade": "N/A",
        "communication_feedback": "",
        "incident_timeline_recommendation": "",
        "next_training": [],
        "next_training_scenarios": [],
    }
    for key, default in defaults.items():
        ev.setdefault(key, default)

    # Enrich nested phase_evaluations with missing detail fields
    for phase in ev.get("phase_evaluations", []):
        if not isinstance(phase, dict):
            continue
        phase.setdefault("user_action_type", "")
        phase.setdefault("detailed_analysis", phase.get("analysis", ""))
        phase.setdefault("mitre_relevance", "")
        phase.setdefault("offline_score", phase.get("correctness", 0))
        phase.setdefault("what_score", phase.get("offline_score", 0))
        phase.setdefault("action_score", phase.get("offline_score", 0))
        phase.setdefault("why_score", phase.get("offline_score", 0))

        # Derive what_did_right / what_did_wrong / how_to_improve if missing
        analysis = phase.get("analysis", "")
        correctness = phase.get("correctness", 5)
        ideal = phase.get("ideal_action", "")

        if not phase.get("what_did_right"):
            if correctness >= 7:
                phase["what_did_right"] = analysis or "Good response aligned with best practice."
            else:
                phase["what_did_right"] = ""

        if not phase.get("what_did_wrong"):
            if correctness < 7:
                phase["what_did_wrong"] = (
                    f"Ideal action was: {ideal}" if ideal
                    else analysis or "Response diverged from the ideal action."
                )
            else:
                phase["what_did_wrong"] = ""

        if not phase.get("how_to_improve"):
            if correctness < 7:
                phase["how_to_improve"] = (
                    f"Next time, consider: {ideal}" if ideal
                    else "Review the ideal action for this phase."
                )
            else:
                phase["how_to_improve"] = "Continue this approach."

    # Enrich nested tightening_recommendations with current_gap if missing
    for rec in ev.get("tightening_recommendations", []):
        if not isinstance(rec, dict):
            continue
        rec.setdefault("current_gap", "")
        rec.setdefault("recommendation", "")
        rec.setdefault("priority", "Medium")
        rec.setdefault("reference", "")

        # Synthesize current_gap from area + recommendation if missing
        if not rec["current_gap"]:
            area = rec.get("area", "")
            fix = rec.get("recommendation", "")
            if fix:
                rec["current_gap"] = f"Currently lacking: {fix}"
            elif area:
                rec["current_gap"] = f"Gap identified in {area}"

    # Sync tools_used ↔ tools_and_frameworks_used (reporter checks both)
    if ev.get("tools_used") and not ev.get("tools_and_frameworks_used"):
        ev["tools_and_frameworks_used"] = ev["tools_used"]
    if ev.get("tools_missing") and not ev.get("tools_and_frameworks_missing"):
        ev["tools_and_frameworks_missing"] = ev["tools_missing"]
    if ev.get("next_training") and not ev.get("next_training_scenarios"):
        ev["next_training_scenarios"] = ev["next_training"]

    return ev


def _parse_json_lenient(raw_text: str) -> dict[str, Any]:
    """Try multiple strategies to extract valid JSON from LLM output."""
    # Strategy 1: try raw text directly
    candidates = []
    # Strategy 2: strip markdown fences
    stripped = _strip_fences(raw_text)
    if stripped:
        candidates.append(stripped)
    # Strategy 3: raw text
    candidates.append(raw_text)
    # Strategy 4: extract between first { and last }
    first = raw_text.find("{")
    last = raw_text.rfind("}")
    if first != -1 and last != -1 and last > first:
        candidates.append(raw_text[first:last + 1])
    # Strategy 5: try line-by-line to find JSON block
    lines = raw_text.split("\n")
    json_lines = []
    in_json = False
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("{"):
            in_json = True
        if in_json:
            json_lines.append(line)
        if in_json and stripped_line.endswith("}"):
            break
    if json_lines:
        candidates.append("\n".join(json_lines))

    last_err: Exception | None = None
    for cand in candidates:
        for variant in (cand, _try_repair_json(cand)):
            if not variant or not variant.strip():
                continue
            try:
                result = json.loads(variant)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError as e:
                last_err = e
                continue
    # Last resort: ast.literal_eval
    try:
        import ast
        result = ast.literal_eval(_strip_fences(raw_text))
        if isinstance(result, dict):
            return result
    except Exception:
        pass
    raise last_err or json.JSONDecodeError("Could not parse JSON from model response", raw_text, 0)


# --------------------------------------------------------------------------- #
# Public API — single request with retry, detailed response
# --------------------------------------------------------------------------- #
_MAX_RETRIES = 3
_RETRY_DELAY = 5  # seconds between retries


def evaluate(session: SessionLog) -> dict[str, Any]:
    """
    Send the entire session to OpenRouter and return the detailed evaluation.
    Retries up to 3 times on transient failures. Falls back to heuristic
    scoring if all attempts fail.
    """
    if not config.OPENROUTER_API_KEY:
        ui.write_warn(
            "OPENROUTER_API_KEY env var is not set. Skipping AI evaluation — "
            "using local heuristic scoring."
        )
        return _fallback(session, "OpenRouter API key not set")

    ui.write_info(
        f"Sending session to AI model: [bold]{config.OPENROUTER_MODEL}[/bold] "
        f"(timeout: {config.OPENROUTER_TIMEOUT}s, retries: {_MAX_RETRIES})... "
    )
    ui.console.print("    [dim]Free-tier inference is slow — typically 25-40s per attempt. Please wait...[/dim]")

    sys_prompt = EVAL_SYSTEM_PROMPT
    if session.user_role:
        sys_prompt = EVAL_SYSTEM_PROMPT + EVAL_ROLE_SUFFIX

    payload = {
        "model": config.OPENROUTER_MODEL,
        "temperature": config.OPENROUTER_TEMPERATURE,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": _build_user_prompt(session)},
        ],
    }
    headers = {
        "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }

    last_error: str = ""
    structured = True  # attempt structured outputs; disable if the model rejects it

    for attempt in range(1, _MAX_RETRIES + 1):
        if attempt > 1:
            ui.write_warn(f"Retry {attempt}/{_MAX_RETRIES} in {_RETRY_DELAY}s...")
            time.sleep(_RETRY_DELAY)

        try:
            ui.write_info(f"Attempt {attempt}/{_MAX_RETRIES}...")
            attempt_payload = payload
            if structured:
                attempt_payload = dict(payload)
                attempt_payload["response_format"] = {"type": "json_object"}
            with httpx.Client(timeout=config.OPENROUTER_TIMEOUT) as client:
                resp = client.post(config.OPENROUTER_API_URL, headers=headers, json=attempt_payload)

            # Fast-fail on auth/config errors — retrying won't help
            if resp.status_code in (401, 403):
                last_error = f"OpenRouter authentication failed (HTTP {resp.status_code}). Check OPENROUTER_API_KEY."
                ui.write_error(last_error)
                return _fallback(session, last_error)

            # A retired/mistyped model id cannot be fixed by retrying.
            if resp.status_code == 404:
                last_error = (
                    f"OpenRouter model '{config.OPENROUTER_MODEL}' was not found. "
                    "Set OPENROUTER_MODEL to a current model id."
                )
                ui.write_error(last_error)
                return _fallback(session, last_error)

            # Structured outputs not supported by this model — retry without it
            if structured and resp.status_code in (400, 422) and "response_format" in resp.text:
                structured = False
                last_error = "Model does not support response_format — retrying without it"
                ui.write_warn(last_error)
                continue

            # Handle rate limiting with retry
            if resp.status_code == 429:
                last_error = f"Rate limited (429). Waiting {_RETRY_DELAY}s..."
                ui.write_warn(last_error)
                continue

            resp.raise_for_status()
            data = resp.json()

            # Validate response structure
            if "choices" not in data or not data["choices"]:
                last_error = "OpenRouter returned no choices"
                ui.write_warn(last_error)
                continue

            msg = data["choices"][0].get("message", {})
            raw_text = (
                msg.get("content")
                or msg.get("reasoning")
                or msg.get("refusal")
                or ""
            )

            if not raw_text or len(raw_text.strip()) < 10:
                last_error = "OpenRouter returned empty or very short content"
                ui.write_warn(last_error)
                continue

            # Parse the JSON response
            parsed = _parse_json_lenient(raw_text)

            # Normalize field names
            parsed = _normalize_keys(parsed)

            # Unified grade bands: recompute the grade from the numeric score so
            # the DB recompute, reports, and the AI label can never drift.
            try:
                parsed["score"] = int(parsed.get("score", 0))
            except (TypeError, ValueError):
                parsed["score"] = 0
            parsed["grade"] = grade_for(parsed["score"])

            # Ensure all required fields exist
            parsed = _ensure_required_fields(parsed)

            # Seed per-phase part scores from the recorded offline data
            by_phase = {a.phase_number: a for a in session.actions}
            for phase in parsed.get("phase_evaluations", []):
                if isinstance(phase, dict):
                    _seed_part_scores(phase, by_phase.get(phase.get("phase_number")))

            # Validate it has meaningful content
            if parsed.get("score", 0) == 0 and not parsed.get("phase_evaluations"):
                last_error = "Parsed JSON is empty or missing score/phases"
                ui.write_warn(last_error)
                continue

            ui.write_success(f"AI evaluation received (attempt {attempt}/{_MAX_RETRIES}).")
            parsed.setdefault("raw_model_response", raw_text)
            parsed.setdefault("model", config.OPENROUTER_MODEL)
            parsed.setdefault("fallback", False)
            return parsed

        except httpx.HTTPStatusError as e:
            last_error = f"OpenRouter HTTP {e.response.status_code}: {e.response.text[:200]}"
            ui.write_warn(last_error)
            continue
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            last_error = f"JSON parse error: {type(e).__name__}: {e}"
            ui.write_warn(last_error)
            continue
        except Exception as e:
            last_error = f"OpenRouter call failed: {type(e).__name__}: {e}"
            ui.write_warn(last_error)
            continue

    # All retries exhausted — fall back to heuristic
    ui.write_error(f"All {_MAX_RETRIES} attempts failed. Last error: {last_error}")
    ui.write_warn("Falling back to local heuristic evaluation.")
    return _fallback(session, last_error)


# --------------------------------------------------------------------------- #
# Fallback — local heuristic when AI is completely unavailable
# --------------------------------------------------------------------------- #
def _fallback(session: SessionLog, reason: str) -> dict[str, Any]:
    """Local evaluation when AI is unavailable.

    The score is derived from the *recorded offline phase scores* — the same
    0-10 concept coverage the learner saw during the run — not from exact
    string overlap with the reference answer. Hints and reference reveals
    apply a small, capped assist penalty so the debrief stays honest.
    """
    actions = list(session.actions)
    n_total = len(actions) or 1

    scored = [
        (a, float(a.response_score))
        for a in actions
        if getattr(a, "response_score", -1.0) is not None
        and float(a.response_score) >= 0
    ]
    offline_scores = [score for _, score in scored]
    avg_offline = (
        sum(offline_scores) / len(offline_scores) if offline_scores else 0.0
    )

    hints_used = sum(int(getattr(a, "hints_used", 0) or 0) for a in actions)
    reveals = sum(1 for a in actions if getattr(a, "looked_up", False))
    penalty = min(15, hints_used * 3 + reveals * 10)
    heuristic = max(0, min(100, round(avg_offline * 10) - penalty))
    grade = grade_for(heuristic)

    strong_phases = [(a, score) for a, score in scored if score >= 6.0]
    weak_phases = [(a, score) for a, score in scored if score < 6.0]

    phase_evals = []
    for a in actions:
        offline = float(a.response_score) if float(getattr(a, "response_score", -1.0)) >= 0 else 0.0
        parts: dict[str, Any] = {}
        missing_terms: list[str] = []
        try:
            payload = json.loads(a.parts_json) if a.parts_json else {}
            if isinstance(payload, dict):
                parts = payload.get("parts", {}) or {}
                if isinstance(payload.get("missing_terms"), list):
                    missing_terms = [str(t) for t in payload["missing_terms"]]
        except Exception:
            parts = {}

        is_strong = offline >= 6.0
        if is_strong:
            analysis_text = "Strong action — covers the key elements of the ideal response."
        elif offline >= 3.0:
            analysis_text = "Partially correct — some key elements are present but the action is incomplete."
        else:
            analysis_text = "Weak action — most of the reference concepts are missing."

        if missing_terms:
            analysis_text += f" Missing: {', '.join(missing_terms[:5])}."

        correctness = max(0, min(10, int(round(offline))))
        phase_evals.append({
            "phase_number": a.phase_number,
            "phase_title": a.phase_title,
            "user_action": a.user_response,
            "user_action_type": a.choice_type,
            "ideal_action": a.ideal_answer,
            "correctness": correctness,
            "offline_score": correctness,
            "what_score": max(0, min(10, int(round(float(parts.get("what", offline)))))) if parts else correctness,
            "action_score": max(0, min(10, int(round(float(parts.get("action", offline)))))) if parts else correctness,
            "why_score": max(0, min(10, int(round(float(parts.get("why", offline)))))) if parts else correctness,
            "analysis": analysis_text,
            "detailed_analysis": analysis_text,
            "what_did_right": "Covered the core response actions." if is_strong else "Some elements may be correct.",
            "what_did_wrong": "" if is_strong else (
                f"Missing: {', '.join(missing_terms[:5])}" if missing_terms
                else "The response diverges from the ideal action."
            ),
            "how_to_improve": (
                "Continue this approach." if is_strong
                else "Review the ideal action and include the missing elements."
            ),
            "mitre_relevance": f"{a.mitre_tactic} / {a.mitre_technique}",
        })

    weaknesses = [
        f"Phase {a.phase_number} ({a.phase_title}): {score:.1f}/10 — reference concepts not fully covered."
        for a, score in weak_phases
    ]
    if penalty:
        weaknesses.append(
            f"Assist penalty applied: {hints_used} hint(s), {reveals} reference reveal(s) (-{penalty})."
        )
    if len(scored) < len(actions):
        weaknesses.append(
            f"{len(actions) - len(scored)} phase(s) had no offline score (legacy data)."
        )

    strengths = [
        f"Phase {a.phase_number} ({a.phase_title}) scored {score:.1f}/10."
        for a, score in strong_phases
    ]
    if not strengths and actions:
        strengths.append("All phases were answered — keep practicing the weak areas below.")

    missed = []
    for a, score in weak_phases[:3]:
        try:
            payload = json.loads(a.parts_json) if a.parts_json else {}
        except Exception:
            payload = {}
        missing = payload.get("missing_terms", []) if isinstance(payload, dict) else []
        missing_text = f" Focus on: {', '.join(str(t) for t in missing[:4])}." if missing else ""
        missed.append(f"Phase {a.phase_number}: re-drill '{a.phase_title}'.{missing_text}")

    return {
        "score": heuristic,
        "grade": grade,
        "overall_assessment": (
            f"Offline evaluation (AI unavailable: {reason}). "
            f"Average concept coverage {avg_offline:.1f}/10 across "
            f"{len(scored) or 0} scored phase(s); "
            f"{hints_used} hint(s) and {reveals} reference reveal(s) used "
            f"({penalty}-point assist penalty)."
        ),
        "final_verdict": f"Offline score {heuristic}/100 (grade {grade}). AI debrief unavailable.",
        "phase_evaluations": phase_evals,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "tightening_recommendations": [
            {
                "area": "AI Evaluation",
                "current_gap": "No AI evaluation available — using the offline concept scorer.",
                "recommendation": "Set OPENROUTER_API_KEY for a richer, narrative debrief.",
                "priority": "Low",
                "reference": "https://openrouter.ai/keys",
            }
        ],
        "missed_opportunities": missed,
        "tools_used": [],
        "tools_missing": [],
        "tools_and_frameworks_used": [],
        "tools_and_frameworks_missing": [],
        "communication_grade": "N/A",
        "communication_feedback": "AI unavailable for communication assessment; offline scoring covers content only.",
        "next_training": (
            [f"Re-drill phase {a.phase_number}: {a.phase_title}" for a, _ in weak_phases[:3]]
            or ["Maintain this level with a harder scenario."]
        ),
        "next_training_scenarios": (
            [f"Re-drill phase {a.phase_number}: {a.phase_title}" for a, _ in weak_phases[:3]]
            or ["Maintain this level with a harder scenario."]
        ),
        "offline_avg": round(avg_offline, 1),
        "assist_penalty": penalty,
        "fallback": True,
    }
