"""
tools/upgrade_content.py
Deterministic content upgrade for the curated scenario corpus (format v2).

Fixes the audit findings that are data (not code) defects:

1. Executive briefs were cut off at ~500 chars (82/83 ended in "...").
   Rebuilds them from the full incident summary + category-specific business
   impact / decisions / regulatory framing.
2. No scenario had a `recovery` phase. Inserts a scenario-specific
   "Recovery & Validation" phase before the lessons phase and rewires `next`.
3. 82/83 scenarios advertised only the analyst role. Adds incident-manager,
   CISO, and executive roles with role-specific briefings.
4. Hints were complete answer summaries. Replaces them with phase-type nudges.
5. `guidance.what` / `guidance.why` repeated only 5 unique strings. Rewrites
   them with context-aware variants (deterministic per scenario/phase).

Usage:
    python tools/upgrade_content.py            # dry run (default)
    python tools/upgrade_content.py --apply    # write YAML files
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "scenarios" / "data"

RECOVERY_ID = "recovery_and_validation"
LESSONS_ID = "post_incident_review"

# Final phases in the curated corpus are labeled `lessons` even when they are
# still active response work (e.g. "Credential Database Exfiltration"). Only
# append recovery *after* those; for genuine post-incident phases, insert
# recovery before them.
_RESPONSE_MARKERS = (
    "exfiltration",
    "exfiltrat",
    "persistence",
    "backdoor",
    "c2",
    "command and control",
    "lateral movement",
    "privilege abuse",
    "credential dumping",
    "golden ticket",
    "code execution",
    "execution",
    "breakout",
    "poisoning",
    "overwrite",
    "containment",
    "contain the",
    "isolate",
    "extraction",
    "deployment",
    "compromise",
    "remediation",
    "remediate",
    "rebuild",
    "remove",
    "restore",
    "fix",
    "patch",
    "attacker",
    "financial impact",
    "wire transfer",
)

IMPACT_BY_DOMAIN = {
    "Endpoint": "endpoint availability and integrity are at risk, and affected hosts may need reimaging before normal work resumes.",
    "Web App": "customer-facing service availability and data confidentiality are at risk, and customer notification may be required.",
    "Cloud": "cloud-hosted data and service availability are at risk, and provider notification plus key rotation may be required.",
    "Identity & Access": "account takeover could enable lateral movement and privilege abuse across the directory, so identity trust must be rebuilt.",
    "Network": "network availability and traffic confidentiality are at risk, and perimeter and segmentation controls are under scrutiny.",
    "AI & ML": "model integrity and data confidentiality are at risk, and AI output should be treated as untrustworthy until validated.",
    "Advanced Threats": "a sophisticated adversary may retain persistent access, so full-scope hunting and third-party notification may be required.",
}

REGULATORY_BY_DOMAIN = {
    "Endpoint": "privacy counsel should assess breach-notification duties once data access is confirmed.",
    "Web App": "privacy counsel should assess breach-notification duties for exposed customer records.",
    "Cloud": "privacy and cloud counsel should assess notification duties and contractual reporting obligations.",
    "Identity & Access": "privacy counsel should assess notification duties for any account or directory data accessed.",
    "Network": "counsel should assess contractual and regulatory notification duties if traffic or data was exposed.",
    "AI & ML": "counsel should assess notification duties for any personal or proprietary data exposed to the model.",
    "Advanced Threats": "counsel and threat-intel leads should assess notification duties and law-enforcement engagement.",
}

HINT_BY_TYPE = {
    "triage": "Start with the alert itself: which asset, account, and time window are actually in scope?",
    "analysis": "Ask which evidence source would prove or disprove the attacker's reach before you act on assumptions.",
    "containment": "Prioritize the move that limits blast radius without destroying the evidence you will need later.",
    "eradication": "Look beyond the visible payload for persistence, stolen credentials, and the original entry path.",
    "recovery": "Trusted backups and proof of cleanliness come before speed; a fast restore can reopen the incident.",
    "lessons": "Turn this incident into one detection improvement and one preventive control that outlast the report.",
}

WHAT_VARIANTS = {
    "triage": [
        "Establish what fired on {asset}, which accounts are involved, and how urgent the signal is.",
        "Separate signal from noise: confirm the alert on {asset}, its severity, and the affected accounts.",
        "Frame the decision for '{title}': the asset at risk, the evidence available, and the time pressure.",
    ],
    "analysis": [
        "Determine what the evidence says about scope, access, and privilege on {asset}.",
        "Pivot from the alert to the log sources that reveal how far the attacker reached.",
        "Test the initial theory against telemetry from {asset} before committing to a response.",
    ],
    "containment": [
        "Decide how to stop the spread from {asset} while preserving the evidence trail.",
        "Identify the smallest set of containment actions that removes the attacker's access.",
        "Balance speed against disruption: what must be isolated now, and what can wait for scoping?",
    ],
    "eradication": [
        "Find every foothold the attacker left on {asset}, including persistence and stolen credentials.",
        "Confirm the root cause and remove the artifacts that would let the attacker return.",
        "Decide what must be rebuilt or rotated rather than merely cleaned.",
    ],
    "recovery": [
        "Define what 'clean' means for {asset}: trusted backups, rebuilt hosts, rotated credentials, and validated controls.",
        "Decide how to restore service in stages while proving the environment is free of reinfection.",
        "Separate business pressure to restore from the evidence required to restore safely.",
    ],
    "lessons": [
        "Summarize what happened, what was missed, and which controls failed on {asset}.",
        "Translate the incident into concrete detection, prevention, and response improvements.",
        "Identify the decisions that would have shortened the incident if they had been made earlier.",
    ],
}

WHY_VARIANTS = {
    "triage": [
        "Rapid scoping decides everything downstream — triage is where containment starts.",
        "A wrong first read sends the whole response down the wrong path.",
        "Every later decision depends on an accurate picture of {asset} and the accounts involved.",
    ],
    "analysis": [
        "Evidence drives decisions — confirm the attacker's reach before acting.",
        "Acting on an unverified scope either misses the attacker or over-contains the business.",
        "The quality of the recovery depends on how well the investigation proves what happened.",
    ],
    "containment": [
        "Containment buys the time needed to investigate without letting the attacker expand.",
        "The first containment action sets the blast radius for everything that follows.",
        "Stopping the spread is urgent, but destroying evidence makes the incident impossible to close.",
    ],
    "eradication": [
        "The incident is not over until the attacker's footholds are gone.",
        "Cleaning the visible payload while leaving persistence in place invites a second incident.",
        "Credentials and entry paths must be removed, not just the malware that used them.",
    ],
    "recovery": [
        "Recovery is only complete when the root cause is fixed and the restored asset is proven clean.",
        "A fast restore that reintroduces the attacker is worse than a slower, verified recovery.",
        "Business trust depends on returning service with evidence that the environment is safe.",
    ],
    "lessons": [
        "The post-incident review is what turns an incident into a defense.",
        "Without durable changes, the same root cause will produce the same incident again.",
        "Lessons are only real when they change a control, a detection, or a decision right.",
    ],
}

DEFAULT_WHAT = "Decide what this phase requires: the evidence in front of you, the asset at risk, and the decision being tested."
DEFAULT_WHY = "Each phase builds on the last — an incomplete decision here weakens the rest of the response."


def _pick(options: list[str], sid: str, phase_id: str, kind: str) -> str:
    digest = hashlib.sha256(f"{sid}:{phase_id}:{kind}".encode("utf-8")).digest()
    return options[digest[0] % len(options)]


def _asset(data: dict) -> str:
    assets = (data.get("incident") or {}).get("compromised_assets") or []
    if isinstance(assets, list) and assets:
        raw = str(assets[0]).strip()
        for separator in (" (", " — ", " – ", ", "):
            if separator in raw:
                raw = raw.split(separator, 1)[0]
        return raw.strip() or "the affected systems"
    return "the affected systems"


def _clean_title(data: dict) -> str:
    incident = data.get("incident") or {}
    return str(incident.get("title") or data.get("name") or "the incident")


def _executive_brief(data: dict) -> str:
    title = _clean_title(data)
    summary = str((data.get("incident") or {}).get("summary") or "").strip()
    category = str(data.get("category") or "")
    if summary and not summary.endswith((".", "!", "?")):
        summary += "."
    impact = IMPACT_BY_DOMAIN.get(category, "business operations and data confidentiality are at risk.")
    regulatory = REGULATORY_BY_DOMAIN.get(category, "counsel should assess notification duties.")
    return (
        f"Executive summary of the {title} incident. {summary} "
        f"Business impact: {impact} "
        "Immediate decisions: authorize containment that may interrupt service, "
        "preserve forensic evidence, and agree the external communication cadence "
        "with legal and communications. "
        f"Regulatory exposure: {regulatory}"
    ).strip()


def _recovery_phase(data: dict, lessons: dict, mitre_tactic: str, mitre_technique: str) -> dict:
    asset = _asset(data)
    title = "Recovery & Validation"
    prompt = f"What must be true before you return {asset} to production?"
    return {
        "id": RECOVERY_ID,
        "phase_type": "recovery",
        "title": title,
        "situation": (
            f"Containment is holding and the attacker's active access has been removed. "
            f"{asset} is quarantined or offline, and business owners are asking when service "
            "can resume. Backups, rebuild images, and a change window are available — but the "
            "root cause must be proven fixed first."
        ),
        "prompt": prompt,
        "guidance": {
            "what": (
                f"Define what clean means for {asset}: a trusted restore point, validated "
                "integrity, rotated credentials, and monitoring for reinfection."
            ),
            "action": prompt,
            "why": (
                "Recovery is only complete when the root cause is fixed and the restored "
                "asset is proven clean; a fast restore can reopen the incident."
            ),
        },
        "hint": (
            f"Restore from a trusted source, validate integrity and credentials, and watch "
            f"for reinfection before declaring {asset} recovered. Focus: {title}."
        ),
        "hints": [
            f"Which backup or rebuild image is known-good for {asset}, and when was it validated?",
            "Which credentials or certificates were exposed and must be rotated before restore?",
            "What monitoring will prove the attacker has not returned after service resumes?",
        ],
        "ideal_concepts": [
            "known-good backup",
            "integrity validation",
            "credential rotation",
            "reinfection monitoring",
            "staged restoration",
            "business sign-off",
        ],
        "reference_answer": (
            f"Restore {asset} from a known-good backup or rebuild it from a trusted image, "
            "validate system and data integrity, rotate every credential and certificate "
            "exposed during the incident, and monitor the restored environment for "
            "reinfection before handing it back to the business.\n\n"
            "Why: Recovery is only complete when the root cause is fixed and the restored "
            "asset is proven clean; restoring compromised infrastructure reopens the incident."
        ),
        "followup_good": (
            "Services are restored in stages from trusted sources, exposed credentials are "
            "rotated, and monitoring confirms no reinfection. The business signs off on the "
            "restored service with evidence attached."
        ),
        "followup_weak": (
            "The asset is back online, but the root cause and credential exposure were not "
            "fully validated. The attacker still has a path back in, and the incident may "
            "reopen under a new alert."
        ),
        "next": lessons.get("id", ""),
        "next_weak": "",
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "role_prompts": {},
    }


def _unique_id(base: str, existing: set[str]) -> str:
    if base not in existing:
        return base
    index = 2
    while f"{base}_{index}" in existing:
        index += 1
    return f"{base}_{index}"


def _is_response_phase(phase: dict) -> bool:
    """True when the final phase is still active containment/eradication work."""
    text = " ".join(
        str(phase.get(key) or "") for key in ("title", "prompt")
    ).lower()
    return any(marker in text for marker in _RESPONSE_MARKERS)


def _lessons_phase(data: dict, mitre_tactic: str, mitre_technique: str) -> dict:
    """A genuine after-action review, appended after active-response endings."""
    asset = _asset(data)
    title = _clean_title(data)
    prompt = (
        f"What must change so an incident like {title} is detected earlier and "
        "cannot recur?"
    )
    return {
        "id": LESSONS_ID,
        "phase_type": "lessons",
        "title": "Post-Incident Review & Hardening",
        "situation": (
            f"Service has been restored and validated. Leadership wants a concise "
            f"after-action review covering the root cause of {title}, the detection "
            "gap that let the attacker operate, and the control changes that will "
            "prevent a repeat. Findings must have owners and dates."
        ),
        "prompt": prompt,
        "guidance": {
            "what": (
                "Summarize the root cause, the detection gap, and the control "
                "changes that would have shortened or prevented the incident."
            ),
            "action": prompt,
            "why": (
                "Lessons are only real when they change a control, a detection, "
                "or a decision right."
            ),
        },
        "hint": (
            "Name the root cause, the detection gap, and one control change with "
            "an owner and a date. Focus: Post-Incident Review & Hardening."
        ),
        "hints": [
            "What was the earliest signal available, and why was it missed?",
            "Which control would have stopped the attack chain the earliest?",
            "Who owns each improvement, and when will it be verified?",
        ],
        "ideal_concepts": [
            "root cause",
            "detection gap",
            "control improvement",
            "owner and date",
            "runbook update",
            "training",
        ],
        "reference_answer": (
            f"Document the root cause of {title}, identify the detection gap that "
            "let the attacker operate, and assign owners and dates to concrete "
            "control changes. Update detections, runbooks, and training, track the "
            "actions to completion, and report the outcome to leadership.\n\n"
            "Why: Without durable changes, the same root cause will produce the "
            "same incident again."
        ),
        "followup_good": (
            "The review names the root cause and detection gap, assigns owned and "
            "dated improvements, and ties them back to specific detections and "
            "controls. Leadership receives a tracked action plan."
        ),
        "followup_weak": (
            "The review retells the timeline but leaves the root cause and detection "
            "gap vague. Without owners, dates, and verification, the same incident "
            "will recur."
        ),
        "next": "",
        "next_weak": "",
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "role_prompts": {},
    }


def upgrade_scenario(data: dict) -> dict[str, Any]:
    """Mutate one scenario dict. Returns a summary of what changed."""
    sid = str(data.get("id") or "")
    changes: dict[str, Any] = {"recovery_added": False, "lessons_added": False}
    phases = data.get("phases") or []

    # 1. Executive brief
    brief = str(data.get("executive_brief") or "").strip()
    if brief.endswith(("...", "…")) or len(brief) < 900:
        data["executive_brief"] = _executive_brief(data)
        changes["brief"] = True

    # 2. Roles + briefings
    title = _clean_title(data)
    data["roles"] = ["analyst", "incident_manager", "ciso", "executive"]
    briefings = data.get("briefings") or {}
    briefings["analyst"] = briefings.get("analyst") or (
        "You are the Tier-1 SOC analyst on shift. Triage the alert, identify "
        "compromised assets and accounts, take initial containment actions, and "
        "preserve evidence for escalation."
    )
    briefings["incident_manager"] = (
        f"You are the Incident Manager coordinating the response to {title}. Drive "
        "containment, evidence preservation, escalation, and cross-team communications; "
        "keep the war-room bridge aligned and document every major decision."
    )
    briefings["ciso"] = (
        f"You are the CISO accountable for {title}. Weigh business impact, legal and "
        "regulatory notification duties, customer commitments, and the risk of "
        "disruptive containment."
    )
    briefings["executive"] = (
        f"You are the executive sponsor for {title}. Focus on business continuity, "
        "budget and resource approval, customer and partner communications, and the "
        "timing of external disclosure."
    )
    data["briefings"] = briefings
    changes["roles"] = True

    # 3. Recovery + lessons phases
    if not any((p.get("phase_type") or "") == "recovery" for p in phases):
        existing_ids = {p.get("id") for p in phases if p.get("id")}
        final = phases[-1] if phases else {}
        tactic = final.get("mitre_tactic") or ""
        technique = final.get("mitre_technique") or ""

        if final and _is_response_phase(final):
            # Active response ending: contain/eradicate first, then recover,
            # then run a real after-action review. Relabel the phase so the
            # scenario does not end up with two `lessons` phases.
            final["phase_type"] = "eradication"
            recovery = _recovery_phase(data, {}, tactic, technique)
            recovery["id"] = _unique_id(RECOVERY_ID, existing_ids)
            existing_ids.add(recovery["id"])
            phases.append(recovery)

            lessons = _lessons_phase(data, tactic, technique)
            lessons["id"] = _unique_id(LESSONS_ID, existing_ids)
            phases.append(lessons)

            final["next"] = recovery["id"]
            recovery["next"] = lessons["id"]
            changes["lessons_added"] = True
        else:
            # Post-incident ending (hardening, reporting, education): recover
            # service safely before the preventive/after-action work.
            previous = phases[-2] if len(phases) >= 2 else None
            recovery = _recovery_phase(data, final, tactic, technique)
            recovery["id"] = _unique_id(RECOVERY_ID, existing_ids)
            phases.insert(len(phases) - 1, recovery)
            if previous is not None:
                previous["next"] = recovery["id"]

        data["phases"] = phases
        changes["recovery_added"] = True

    # 4. Hints + guidance
    asset = _asset(data)
    for phase in phases:
        phase_type = str(phase.get("phase_type") or "")
        phase_id = str(phase.get("id") or phase.get("title") or "")
        phase_title = str(phase.get("title") or "")
        nudge = HINT_BY_TYPE.get(phase_type, HINT_BY_TYPE["triage"])
        phase["hint"] = f"{nudge} Focus: {phase_title}. Asset in scope: {asset}."

        guidance = phase.get("guidance") or {}
        what_options = WHAT_VARIANTS.get(phase_type, [DEFAULT_WHAT])
        why_options = WHY_VARIANTS.get(phase_type, [DEFAULT_WHY])
        guidance["what"] = _pick(what_options, sid, phase_id, "what").format(
            asset=asset, title=phase_title
        )
        guidance["why"] = _pick(why_options, sid, phase_id, "why").format(
            asset=asset, title=phase_title
        )
        guidance.setdefault("action", phase.get("prompt", "What is your next action?"))
        phase["guidance"] = guidance
        changes["hints"] = True
        changes["guidance"] = True

    return changes


class _Dumper(yaml.SafeDumper):
    pass


def _str_representer(dumper: yaml.SafeDumper, value: str):
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_Dumper.add_representer(str, _str_representer)


def _write(path: Path, data: dict) -> None:
    path.write_text(
        yaml.dump(
            data,
            Dumper=_Dumper,
            sort_keys=False,
            allow_unicode=True,
            width=1000,
            default_flow_style=False,
        ),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upgrade curated scenario content")
    parser.add_argument("--apply", action="store_true", help="Write changes (default: dry run)")
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    args = parser.parse_args(argv)

    files = sorted(args.data_dir.rglob("*.yaml"))
    if not files:
        print(f"No YAML files found under {args.data_dir}", file=sys.stderr)
        return 1

    totals = {
        "brief": 0,
        "recovery_added": 0,
        "lessons_added": 0,
        "roles": 0,
        "hints": 0,
        "guidance": 0,
    }
    for path in files:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if not isinstance(data, dict):
            continue
        changes = upgrade_scenario(data)
        for key, value in changes.items():
            if value and key in totals:
                totals[key] += 1
        if args.apply:
            _write(path, data)

    print(("APPLIED" if args.apply else "DRY RUN") + f" — {len(files)} scenarios")
    print(f"  executive briefs rebuilt: {totals['brief']}")
    print(f"  recovery phases added:    {totals['recovery_added']}")
    print(f"  lessons phases added:     {totals['lessons_added']}")
    print(f"  role coverage updated:    {totals['roles']}")
    print(f"  hints rewritten:          {totals['hints']}")
    print(f"  guidance rewritten:       {totals['guidance']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
