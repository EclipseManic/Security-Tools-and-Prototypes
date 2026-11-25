"""
scenarios/base.py
Blue-team incident-response scenario base class.

Each scenario describes an attack that HAS ALREADY HAPPENED to the
organization. The user is the SOC analyst / IR responder and must take a
series of actions. At each phase the user types their own free-text response.

CRITICAL: This class NEVER gives feedback on whether the user's response was
right or wrong. All evaluation is deferred to the AI at the very end.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass, field
from typing import Optional

from core.recorder import Recorder

ROLE_ORDER = ["analyst", "incident_manager", "ciso", "executive"]


@dataclass
class Phase:
    """A single phase of an incident-response scenario (format v2, free-text)."""
    title: str
    situation: str                  # the situation presented to the analyst
    prompt: str = "What is your next action?"
    id: str = ""                    # unique within the scenario (navigation target)
    phase_type: str = ""            # triage|analysis|containment|eradication|recovery|lessons
    guidance: dict[str, str] = field(default_factory=dict)   # what / action / why
    hint: str = ""                  # always-visible first hint
    hints: list[str] = field(default_factory=list)           # progressive ('?' reveals next)
    ideal_concepts: list[str] = field(default_factory=list)  # offline scoring targets
    reference_answer: str = ""      # full ideal response (revealed by '??')
    followup_good: str = ""         # reveal after a strong answer
    followup_weak: str = ""         # reveal after a weak answer
    next: str = ""                  # next phase id (good path; "" = end)
    next_weak: str = ""             # next phase id (weak path; defaults to next)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    role_prompts: dict[str, str] = field(default_factory=dict)  # role-specific prompt overrides


@dataclass
class ScenarioMeta:
    name: str
    category: str
    difficulty: str
    # Blue-team framing — describes the attack that already happened
    incident_title: str             # e.g. "Ransomware Outbreak — Payroll Dept"
    incident_summary: str           # full narrative of the attack (AI/ground truth)
    format_version: int = 1         # 1 = multiple-choice, 2 = free-text guided
    opening: str = ""               # v2 one-sentence scene-setter shown to the user
    compromised_assets: list[str] = field(default_factory=list)
    detected_via: str = ""          # how the SOC first detected the incident
    kill_chain: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    # SOC tier / role-aware extensions
    soc_tier: str = "L1"            # L1 | L2 | L3 | L1-L2 | L1-L3 | L2-L3
    roles: list[str] = field(default_factory=lambda: ["analyst"])
    executive_brief: str = ""       # CISO/leadership-level 2-3 sentence summary
    role_briefings: dict[str, str] = field(default_factory=dict)  # per-role briefing text
    industries: list[str] = field(default_factory=lambda: ["all"])  # industry scope


class Scenario(ABC):
    """Base class for all blue-team IR scenarios."""

    meta: ScenarioMeta = ScenarioMeta(
        name="Base",
        category="Generic",
        difficulty="Medium",
        incident_title="Generic Incident",
        incident_summary="An incident has occurred.",
    )
    phases: list[Phase] = []
    user_role: str = "analyst"  # set by set_user_role() before run()

    def set_user_role(self, role: str) -> None:
        """Set the SOC role the user is playing (analyst, incident_manager, ciso, executive)."""
        if role in ROLE_ORDER:
            self.user_role = role

    def _role_briefing(self) -> str:
        """Return the role-specific briefing text if available."""
        return self.meta.role_briefings.get(self.user_role, "")

    def _phase_prompt(self, phase: Phase) -> str:
        """Return the role-specific prompt if available, else the default."""
        return phase.role_prompts.get(self.user_role, phase.prompt)

    def phase_by_id(self, phase_id: str) -> Optional[Phase]:
        """Resolve a phase id to a Phase (used by next/next_weak navigation)."""
        if not phase_id:
            return None
        for p in self.phases:
            if p.id == phase_id:
                return p
        return None

    def run(self, recorder: Recorder) -> None:
        """Drive the IR walkthrough via the format-v2 sim engine.

        The engine handles briefing, per-phase guidance/free text/hints,
        offline scoring, followup reveal and branching. No feedback is ever
        shown to the user.
        """
        from core.sim_engine import run_scenario
        run_scenario(self, recorder)

    def _brief(self) -> str:
        if self.meta.format_version >= 2 and self.meta.opening:
            # v2: show only the scene-setter — the story is revealed phase by phase
            return (
                f"[bold]{self.meta.incident_title}[/bold]\n\n"
                f"{self.meta.opening}"
            )
        return (
            f"[bold]{self.meta.incident_title}[/bold]\n\n"
            f"{self.meta.incident_summary}"
        )
