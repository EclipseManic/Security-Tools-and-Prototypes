"""
main.py
Entry point — blue-team IR trainer with persistent sessions.

New flow:
  1. Enter name → existing user? → resume prompt | new user → onboarding (role + domains)
  2. Main menu: [Play] [Generate] [Choose Domains] [Progress] [Quit]
  3. After a scenario: AI evaluation → save to sessions.db → recommend generation
  4. Backward compatible: if SQLite unavailable, falls back to stateless operation
"""

from __future__ import annotations

import sys
import os

from config import APP_NAME, APP_VERSION
from core import ui
from core.recorder import Recorder
from core.sim_engine import run_scenario
from core.ai_evaluator import evaluate
from core.reporter import generate_all
from core.session_db import SessionDB
from core.adaptive import recommend_next, find_scenarios_for_technique, domain_for_technique
from scenarios.base import Scenario
from scenarios import ALL_CATEGORIES


CATEGORIES: dict[str, list[type[Scenario]]] = ALL_CATEGORIES

# Role menu is derived from the scenario corpus, so a role with no content can
# never be selected. ROLE_ORDER controls the display order.
ROLE_ORDER = ["analyst", "incident_manager", "ciso", "executive"]
ROLE_OPTIONS = [
    role
    for role in ROLE_ORDER
    if any(role in (cls.meta.roles or ["analyst"])
           for scns in CATEGORIES.values() for cls in scns)
] or ["analyst"]
ALL_DOMAINS = list(CATEGORIES.keys())


def _scenario_total() -> int:
    """Current scenario count (never a stale import-time constant)."""
    return sum(len(v) for v in CATEGORIES.values())


def _role_for_scenario(scenario_cls: type[Scenario], user_role: str) -> str:
    """Return the scenario's supported role closest to the user's choice."""
    supported = scenario_cls.meta.roles or ["analyst"]
    if user_role in supported:
        return user_role
    return "analyst" if "analyst" in supported else supported[0]


# --------------------------------------------------------------------------- #
# Domain-filtered scenario list
# --------------------------------------------------------------------------- #
def _filter_by_domains(domains: list[str]) -> list[tuple[str, list[type[Scenario]]]]:
    """Return (category, scenarios) pairs, filtered to user's selected domains.
    Falls back to ALL_CATEGORIES if db not available or domains empty."""
    if not domains or not CATEGORIES:
        return list(CATEGORIES.items())
    result = []
    for cat_name, scenarios in CATEGORIES.items():
        # A domain match means the category name is in the user's domain list
        if cat_name in domains:
            result.append((cat_name, scenarios))
    return result if result else list(CATEGORIES.items())


def _pick_role() -> str:
    options = ROLE_OPTIONS + ["Exit"]
    ui.print_role_menu("Choose Your SOC Role", options)
    idx = ui.ask_index("Role", len(options))
    if idx <= len(ROLE_OPTIONS):
        return ROLE_OPTIONS[idx - 1]
    return ""


def _pick_category(domain_cats: list[tuple[str, list[type[Scenario]]]]) -> tuple[str, list[type[Scenario]]] | None:
    options = [c[0] for c in domain_cats] + ["Exit"]
    ui.print_menu("Choose an Incident Category", options)
    idx = ui.ask_index("Category", len(options))
    if idx < len(options):
        return domain_cats[idx - 1]
    return None


# --------------------------------------------------------------------------- #
# Onboarding for new users
# --------------------------------------------------------------------------- #
def _onboarding(db: SessionDB, user_name: str) -> tuple[str, list[str]]:
    """Run onboarding for a new user. Returns (role, domains)."""
    ui.console.print()
    role = _pick_role()
    if not role:
        ui.console.print(f"\n[dim]Thanks for using {APP_NAME} v{APP_VERSION}.[/dim]")
        sys.exit(0)

    domains = ui.print_domain_picker(ALL_DOMAINS, ALL_DOMAINS)
    db.create_user(user_name, role, domains)
    ui.write_success(f"Profile saved! Tracking {len(domains)} domain(s).")
    return role, domains


# --------------------------------------------------------------------------- #
# Main session loop
# --------------------------------------------------------------------------- #
def _play_scenario(
    scenario_cls: type[Scenario],
    user_name: str,
    user_role: str,
    industry: str,
    domain: str,
    db: SessionDB,
    domains: list[str] | None = None,
) -> None:
    """Run a single scenario: play through all phases, get AI eval, save to DB,
    then show the adaptive next-step recommendation (P6)."""

    def _do_run(cls: type[Scenario]) -> None:
        scenario = cls()
        effective_role = _role_for_scenario(cls, user_role)
        if effective_role != user_role:
            ui.write_warn(
                f"'{user_role.replace('_', ' ').title()}' has no content in this "
                f"scenario — playing as {effective_role.replace('_', ' ').title()}."
            )
        scenario.set_user_role(effective_role)
        recorder = Recorder()
        recorder.set_context(
            user_name=user_name,
            incident_title=scenario.meta.incident_title,
            incident_category=scenario.meta.category,
            incident_summary=scenario.meta.incident_summary,
            compromised_assets=scenario.meta.compromised_assets,
            detected_via=scenario.meta.detected_via,
            user_role=effective_role,
            industry_filter=industry,
            executive_brief=scenario.meta.executive_brief,
        )
        summary: dict = {}
        try:
            summary = run_scenario(scenario, recorder)
        except KeyboardInterrupt:
            ui.console.print("\n[yellow]Simulation interrupted.[/yellow]")
            if not recorder.session.actions:
                return

        if summary.get("scored_phases"):
            ui.write_info(
                f"Offline phase scores: [bold]{summary['avg_score']}/10[/bold] "
                f"([bold green]{summary['strong']}[/bold green]/"
                f"[bold]{summary['scored_phases']}[/bold] strong phases)"
            )

        ui.clear_screen()
        ui.console.rule("[bold cyan]REQUESTING AI EVALUATION[/bold cyan]")
        evaluation = evaluate(recorder.session)

        ui.console.print()
        generate_all(recorder.session, evaluation)

        if db.available:
            run_id = db.save_run(recorder.session, evaluation, cls)
            recorder.session.run_id = run_id
            rec = recommend_next(db, user_name, domains or [domain])
            db.set_next_scenario_reason(run_id, rec["reason"])
            evaluation["next_scenario_reason"] = rec["reason"]

        ui.console.print()
        ui.write_info(f"Score: [bold]{evaluation.get('score', '?')}/100[/bold] | "
                      f"Grade: [bold]{evaluation.get('grade', 'N/A')}[/bold]")
        ui.wait_for_enter()

    _do_run(scenario_cls)

    if db.available:
        _post_run_menu(user_name, user_role, industry, domains or [domain], db)


def _post_run_menu(
    user_name: str,
    user_role: str,
    industry: str,
    domains: list[str],
    db: SessionDB,
) -> None:
    """Show the adaptive recommendation after a run and let the user act on it."""
    rec = recommend_next(db, user_name, domains)
    ui.print_recommendation(rec["reason"])

    if rec["mode"] == "play" and rec["scenario_cls"] is not None:
        options = ["Play recommended scenario", "Generate custom (targets weakness)", "Back to menu"]
    elif rec["mode"] == "generate":
        options = ["Generate custom (targets weakness)", "Back to menu"]
    else:
        options = ["Back to menu"]
    ui.print_menu("What next?", options)
    choice = ui.ask_index("Select", len(options))

    if choice == 1 and rec["mode"] == "play" and rec["scenario_cls"] is not None:
        cls = rec["scenario_cls"]
        _play_scenario(cls, user_name, user_role, industry, cls.meta.category, db, domains)
    elif choice == 1 and rec["mode"] == "generate":
        _generate_and_play(user_name, user_role, industry, domains, db, rec)
    elif choice == 2 and rec["mode"] == "play":
        _generate_and_play(user_name, user_role, industry, domains, db, rec)


def _reload_scenarios() -> int:
    """Reload YAML scenarios from disk so newly generated files are picked up.

    Mutates the shared dicts in place: `scenarios.loader`, `scenarios`, and
    every module that imported `ALL_CATEGORIES` / `SCENARIO_BY_ID` keep seeing
    the new content. Returns the new total scenario count.
    """
    import scenarios as pkg
    import scenarios.loader as loader_mod

    by_cat, _by_id = loader_mod.reload()
    CATEGORIES.clear()
    CATEGORIES.update(by_cat)
    pkg.TOTAL_SCENARIOS = loader_mod.TOTAL_SCENARIOS
    ALL_DOMAINS[:] = list(by_cat.keys())
    return loader_mod.TOTAL_SCENARIOS


def _generate_and_play(
    user_name: str,
    user_role: str,
    industry: str,
    domains: list[str],
    db: SessionDB,
    rec: dict | None = None,
) -> None:
    """Generate a custom scenario (v2) targeting the learner's weaknesses, then
    auto-play it. Fallback chain: prebuilt targeting the technique -> menu."""
    try:
        from core.scenario_generator import ScenarioGenerator

        gen = ScenarioGenerator()
        weak_tech = (rec or {}).get("technique") if rec else None
        weaknesses = [weak_tech] if weak_tech else []
        if weak_tech:
            domain = domain_for_technique(weak_tech, domains) or (domains[0] if domains else "Endpoint")
        else:
            domain = domains[0] if domains else "Endpoint"
        learner_level = db.get_learner_level(user_name)
        ui.write_info(f"Targeting weak techniques: {weaknesses if weaknesses else 'none'}")
        yaml_path = gen.generate(
            domain=domain,
            weaknesses=weaknesses,
            role=user_role,
            user_name=user_name,
            learner_level=learner_level,
        )
        if yaml_path:
            ui.write_success(f"Custom scenario generated: {os.path.basename(yaml_path)}")
            new_total = _reload_scenarios()
            ui.write_info(f"Total scenarios now: {new_total}")

            # Find the generated scenario class and auto-play it
            yaml_path_norm = os.path.normpath(yaml_path)
            gen_cls = None
            for cat_name, scns in _filter_by_domains(domains):
                for s in scns:
                    source = getattr(s, "_yaml_source", "")
                    if source and os.path.normpath(source) == yaml_path_norm:
                        gen_cls = s
                        break
                if gen_cls:
                    break

            if gen_cls:
                ui.write_success(f"Starting generated scenario: {gen_cls.meta.incident_title}")
                _play_scenario(gen_cls, user_name, user_role, industry, gen_cls.meta.category, db, domains)
            else:
                ui.write_warn("Could not locate generated scenario class. Falling back to menu.")
        else:
            # Fallback: prebuilt scenario targeting the same weak technique
            if weak_tech:
                cls = find_scenarios_for_technique(weak_tech, domains)
                if cls is not None:
                    ui.write_warn(f"Generation failed. Playing existing scenario targeting {weak_tech}.")
                    _play_scenario(cls, user_name, user_role, industry, cls.meta.category, db, domains)
                    return
            ui.write_warn("Generation failed. Falling back to domain-filtered prebuilt scenarios.")
            _play_from_menu(user_name, user_role, industry, domains, db)
    except Exception as e:
        ui.write_warn(f"Generation failed: {e}. Falling back to domain-filtered scenarios.")
        _play_from_menu(user_name, user_role, industry, domains, db)


def _play_from_menu(
    user_name: str,
    user_role: str,
    industry: str,
    domains: list[str],
    db: SessionDB,
) -> None:
    """
    Pick a category + scenario and run it.
    """
    ui.clear_screen()
    ui.write_role_header(user_role)

    domain_cats = _filter_by_domains(domains)
    picked = _pick_category(domain_cats)
    if picked is None:
        return  # user hit exit/back

    cat_name, scenarios = picked

    if industry and industry != "all":
        filtered = [s for s in scenarios if industry in (s.meta.industries or ["all"])]
        if not filtered:
            ui.write_info(f"No scenarios tagged '{industry}' — showing all incidents in this category.")
        scns = filtered if filtered else scenarios
    else:
        scns = scenarios

    scn_options = [f"{s.meta.incident_title}  [{s.meta.difficulty}]" for s in scns] + ["Back"]
    ui.print_menu(f"{cat_name} — Pick an Incident", scn_options)
    idx = ui.ask_index("Incident", len(scn_options))
    if idx >= len(scn_options):
        return  # Back

    scenario_cls = scns[idx - 1]
    _play_scenario(scenario_cls, user_name, user_role, industry, cat_name, db)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ui.banner()

    db = SessionDB()
    db_status = "enabled" if db.available else "disabled (stateless)"
    ui.write_info(f"Session tracking: [bold]{db_status}[/bold]")

    user_name = ui.console.input("[bold cyan]Enter your name (for the report)[/bold cyan] > ").strip() or "Anonymous"

    # ------------------------------------------------------------------
    # Backward-compatible stateless mode
    # ------------------------------------------------------------------
    if not db.available:
        ui.console.print(f"\n[dim]Stateless mode — no session persistence.[/dim]")
        user_role = _pick_role()
        if not user_role:
            ui.console.print(f"\n[dim]Thanks for using {APP_NAME} v{APP_VERSION}.[/dim]")
            return 0
        industry = "all"

        ui.console.print(f"\n[bold green]Welcome, {user_name}![/bold green] "
                         f"You are the {user_role.replace('_', ' ').title()}. "
                         f"Respond to each phase of the incident.\n"
                         f"[yellow]No feedback during the run — the AI evaluates everything at the end.[/yellow]\n"
                         f"[dim]Loaded {len(CATEGORIES)} categories with {_scenario_total()} attack scenarios.[/dim]\n")

        try:
            _run_stateless(user_name, user_role, industry)
        except KeyboardInterrupt:
            ui.console.print("\n[yellow]Goodbye![/yellow]")

        ui.console.print(f"\n[dim]Thanks for using {APP_NAME} v{APP_VERSION}.[/dim]")
        return 0

    # ------------------------------------------------------------------
    # Persistent mode
    # ------------------------------------------------------------------
    user = db.get_user(user_name)

    user_role: str
    domains: list[str]
    industry = "all"  # could be extended later per-user

    if user:
        # Existing user — show last session and honor the resume answer
        last_run = db.get_last_run(user_name)
        if last_run and last_run.get("completed_at"):
            if ui.print_resume_prompt(user_name, last_run):
                user_role = user["role"]
                domains = user["domains"]
            else:
                ui.console.print(
                    "\n[dim]Starting fresh — update your role and domains.[/dim]"
                )
                user_role, domains = _onboarding(db, user_name)
        else:
            user_role = user["role"]
            domains = user["domains"]
        ui.console.print(f"\n[dim]Loaded {len(CATEGORIES)} categories with {_scenario_total()} attack scenarios.[/dim]\n"
                         f"[dim]Domains: {', '.join(domains)}[/dim]\n")
    else:
        # New user — onboarding
        ui.console.print(f"\n[bold]First time, {user_name}![/bold] Let's set up your profile.\n")
        user_role, domains = _onboarding(db, user_name)
        ui.console.print(f"[dim]Loaded {len(CATEGORIES)} categories with {_scenario_total()} attack scenarios.[/dim]\n")

    run_count = db.get_run_count(user_name)

    # ------------------------------------------------------------------
    # Main menu loop
    # ------------------------------------------------------------------
    try:
        while True:
            menu_options = ["Play Scenario", "Generate Custom Scenario", "Choose Domains", "View Progress", "Quit"]
            ui.print_main_menu(menu_options)
            choice = ui.ask_index("Select", len(menu_options))

            if choice == 1:  # Play
                _play_from_menu(user_name, user_role, industry, domains, db)
                run_count = db.get_run_count(user_name)

            elif choice == 2:  # Generate
                _generate_and_play(user_name, user_role, industry, domains, db)
                run_count = db.get_run_count(user_name)

            elif choice == 3:  # Choose Domains
                domains = ui.print_domain_picker(ALL_DOMAINS, domains)
                db.update_user_domains(user_name, domains)

            elif choice == 4:  # Progress
                ui.clear_screen()
                perf = db.get_domain_performance(user_name)
                ui.print_progress_view(perf)
                last_run = db.get_last_run(user_name)
                ui.print_learner_summary(
                    level=db.get_learner_level(user_name),
                    streak=db.get_practice_streak(user_name),
                    next_reason=(last_run or {}).get("next_scenario_reason", ""),
                )
                ui.wait_for_enter()

            else:  # Quit
                break

    except KeyboardInterrupt:
        ui.console.print("\n[yellow]Goodbye![/yellow]")

    db.close()
    ui.console.print(f"\n[dim]Thanks for using {APP_NAME} v{APP_VERSION}.[/dim]")
    return 0


def _run_stateless(user_name: str, user_role: str, industry: str) -> None:
    """Legacy stateless flow — no DB, just play scenarios."""
    while True:
        ui.clear_screen()
        ui.write_role_header(user_role)

        picked = _pick_category(list(CATEGORIES.items()))
        if picked is None:
            continue
        cat_name, scenarios = picked
        if industry and industry != "all":
            filtered = [s for s in scenarios if industry in (s.meta.industries or ["all"])]
            if not filtered:
                ui.write_info(f"No scenarios tagged '{industry}' — showing all incidents in this category.")
            scns = filtered if filtered else scenarios
        else:
            scns = scenarios

        scn_options = [f"{s.meta.incident_title}  [{s.meta.difficulty}]" for s in scns] + ["Back"]
        ui.print_menu(f"{cat_name} — Pick an Incident", scn_options)
        idx = ui.ask_index("Incident", len(scn_options))
        if idx >= len(scn_options):
            continue

        scenario_cls = scns[idx - 1]
        scenario = scenario_cls()
        scenario.set_user_role(user_role)
        recorder = Recorder()
        recorder.set_context(
            user_name=user_name,
            incident_title=scenario.meta.incident_title,
            incident_category=cat_name,
            incident_summary=scenario.meta.incident_summary,
            compromised_assets=scenario.meta.compromised_assets,
            detected_via=scenario.meta.detected_via,
            user_role=user_role,
            industry_filter=industry,
            executive_brief=scenario.meta.executive_brief,
        )

        try:
            run_scenario(scenario, recorder)
        except KeyboardInterrupt:
            if not recorder.session.actions:
                continue

        ui.clear_screen()
        ui.console.rule("[bold cyan]REQUESTING AI EVALUATION[/bold cyan]")
        evaluation = evaluate(recorder.session)

        ui.console.print()
        generate_all(recorder.session, evaluation)

        again = ui.console.input(
            "[bold cyan]What next? (r=change role, n=next, q=quit) > [/bold cyan]"
        ).strip().lower()
        if again == "r":
            user_role = _pick_role() or user_role
        elif again == "q":
            return


if __name__ == "__main__":
    sys.exit(main())
