"""
test_e2e.py
Automated end-to-end test for the blue-team IR trainer.
Drives a full scenario without interactive input, calls the AI, generates reports.
"""

from __future__ import annotations

import os
import sys
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.recorder import Recorder
from core.ai_evaluator import evaluate
from core.reporter import generate_all
from core.session_db import SessionDB
from core.response_scorer import score_response
from core.grading import grade_for
import core.ai_evaluator as evaluator_mod
from core.reporter import _esc
import core.reporter as reporter_mod
from scenarios.loader import SCENARIO_BY_ID
import core.ui as ui

USER_ROLE = os.getenv("ROLE", "analyst")


def drive_scenario() -> tuple[Recorder, object]:
    """Drive the VPN credential-stuffing scenario (format v2) with scripted answers."""
    scenario_cls = SCENARIO_BY_ID.get("vpn_credential_stuffing") or next(iter(SCENARIO_BY_ID.values()))
    scenario = scenario_cls()
    scenario.set_user_role(USER_ROLE)
    recorder = Recorder()
    recorder.set_context(
        user_name="E2E-Tester",
        incident_title=scenario.meta.incident_title,
        incident_category=scenario.meta.category,
        incident_summary=scenario.meta.incident_summary,
        compromised_assets=scenario.meta.compromised_assets,
        detected_via=scenario.meta.detected_via,
        user_role=USER_ROLE,
        industry_filter=os.getenv("INDUSTRY", "all"),
    )

    # Monkey-patch UI to bypass interactive prompts
    ui.clear_screen = lambda: None
    ui.wait_for_enter = lambda *a, **k: None
    ui.banner = lambda: None

    # v2 free text: scripted substantive answers
    def fake_free_text(prompt_text, hints=None, reference_answer=""):
        return {
            "response": "Pull the VPN authentication logs, identify the successful logins, "
                        "and cross-reference them with AD group membership before acting.",
            "hints_used": 0,
            "looked_up": False,
        }
    ui.prompt_free_text = fake_free_text

    scenario.run(recorder)
    return recorder, scenario


def check_scorer() -> None:
    """Unit sanity checks for the offline response scorer."""
    print("-" * 70)
    print("Testing offline response scorer...")

    strong = score_response(
        "Block the malicious IP at the firewall and disable the compromised account",
        ["block malicious ip", "disable compromised account"],
    )
    assert strong["score"] >= 6.0, f"expected strong score, got {strong['score']} ({strong['matched']})"
    assert strong["good"] is True
    print(f"  strong: {strong['score']} (matched {len(strong['matched'])}/{strong['total']})")

    weak = score_response(
        "We should do something about it",
        ["block malicious ip", "disable compromised account"],
    )
    assert weak["score"] < 6.0, f"expected weak score, got {weak['score']}"
    assert weak["good"] is False
    print(f"  weak:   {weak['score']} (matched {len(weak['matched'])}/{weak['total']})")

    empty = score_response("ok", ["block malicious ip"])
    assert empty["score"] == 0.0
    print(f"  empty:  {empty['score']}")

    parts = score_response(
        "What I see: auth logs from Tor. What would I do: pull the SIEM "
        "authentication logs, check for successful logins, and disable the "
        "compromised accounts. Why: rapid scoping.",
        ["pull authentication logs", "check successful logins", "disable compromised accounts"],
    )
    assert parts["parts"]["action"] >= 6.0, f"action part should score, got {parts['parts']}"
    print(f"  parts:  score={parts['score']} what={parts['parts']['what']} "
          f"action={parts['parts']['action']} why={parts['parts']['why']}")
    print("Scorer OK")


def check_grading() -> None:
    """Unified grade bands must match the DB recompute (single source)."""
    print("-" * 70)
    print("Testing unified grade bands (core/grading.py)...")
    cases = {90: "Expert", 89: "Proficient", 70: "Proficient", 69: "Intermediate",
             50: "Intermediate", 49: "Novice", 30: "Novice", 29: "Needs Work", 0: "Needs Work"}
    for score, expected in cases.items():
        got = grade_for(score)
        assert got == expected, f"grade_for({score}) = {got}, expected {expected}"
    print("  boundaries 90/70/50/30 verified (Expert/Proficient/Intermediate/Novice/Needs Work)")
    print("Grading OK")


def check_fallback_seeded() -> None:
    """Fallback heuristic must use unified bands + seed weaknesses/opportunities
    from the recorded offline phase data."""
    print("-" * 70)
    print("Testing AI fallback (offline-seeded evaluation)...")
    rec = Recorder()
    rec.set_context(user_name="E2E-Tester", incident_title="Test Incident",
                    incident_category="Identity & Access", incident_summary="sum",
                    compromised_assets=[], detected_via="SIEM", user_role="analyst")
    from core.recorder import ActionRecord
    rec.session.add(ActionRecord(phase_number=1, phase_title="Triage", situation="s",
                                 mitre_tactic="Initial Access", mitre_technique="T1078",
                                 prompt="p", choice_type="free_text",
                                 user_response="turn it off", options_presented=[],
                                 ideal_answer="isolate the host",
                                 reference_explanation="Isolate first", timestamp="t1",
                                 elapsed_sec=5.0, response_score=2.5,
                                 parts_json='{"parts": {"what": 2.5, "action": 2.5, "why": 2.5}}'))
    rec.session.add(ActionRecord(phase_number=2, phase_title="Containment", situation="s",
                                 mitre_tactic="Containment", mitre_technique="T1078",
                                 prompt="p", choice_type="free_text",
                                 user_response="block the IP at the firewall and disable the account",
                                 options_presented=[], ideal_answer="block IP and disable account",
                                 reference_explanation="Block + disable", timestamp="t2",
                                 elapsed_sec=3.0, response_score=9.0,
                                 parts_json='{"parts": {"what": 9.0, "action": 9.0, "why": 9.0}}'))
    ev = evaluator_mod._fallback(rec.session, "unit-test")
    assert ev["fallback"] is True
    assert ev["grade"] == grade_for(ev["score"]), f"fallback grade {ev['grade']} != unified bands for {ev['score']}"
    assert len(ev["phase_evaluations"]) == 2
    p1 = ev["phase_evaluations"][0]
    assert p1["offline_score"] == 2, f"offline seed wrong: {p1['offline_score']}"
    assert p1["action_score"] == 2, f"parts seed wrong: {p1['action_score']}"
    assert any("Phase 1" in w for w in ev["weaknesses"]), f"weakness not seeded: {ev['weaknesses']}"
    assert any("Phase 1" in m for m in ev["missed_opportunities"]), f"missed opp not seeded: {ev['missed_opportunities']}"
    assert any("Re-drill" in n for n in ev["next_training"]), f"next_training not seeded: {ev['next_training']}"
    print(f"  fallback score={ev['score']} grade={ev['grade']} weaknesses={len(ev['weaknesses'])} "
          f"next_training={len(ev['next_training'])}")
    print("Fallback OK")


def check_report_escaping() -> None:
    """AI strings must be escaped in HTML/PDF output."""
    print("-" * 70)
    print("Testing report escaping...")
    payload = "<script>alert('x')</script> & <b>bold</b>"
    esc = _esc(payload)
    assert "<script>" not in esc and "<b>" not in esc, f"not escaped: {esc}"
    assert "&lt;script&gt;" in esc
    assert _esc(None) == ""
    print(f"  _esc ok: {esc[:50]}...")
    print("Escaping OK")


def check_mastery(db, recorder, evaluation, scenario) -> None:
    """Student model: mastery rows, unified levels, domain scoping, upsert,
    streaks, learner level."""
    print("-" * 70)
    print("Testing student model (P5)...")
    from core.grading import grade_for

    # Mastery built from the run's actions
    mastery = db.get_mastery("E2E-Tester")
    assert len(mastery) > 0, "no mastery rows after save_run"
    for m in mastery:
        assert m["attempts"] >= 1
        assert m["level"] == grade_for(int(m["avg_score"])), \
            f"mastery level {m['level']} != grade bands for avg {m['avg_score']}"
    techniques = {m["technique"] for m in mastery}
    assert any(t for t in techniques if "T" in t), f"techniques look wrong: {techniques}"

    # Domain-scoped weak techniques: the run is in Identity & Access,
    # other domains must be unaffected by it.
    weak_ia = db.get_weak_techniques("E2E-Tester", "Identity & Access")
    assert isinstance(weak_ia, list)
    weak_other = db.get_weak_techniques("E2E-Tester", "Network")
    assert weak_other == [], f"Network must not contain Identity techniques: {weak_other}"

    # Per-domain metrics are scoped (audit finding #1)
    ia_perf = db.get_domain_performance("E2E-Tester", "Identity & Access")
    assert ia_perf, "Identity & Access metrics missing after run"
    net_perf = db.get_domain_performance("E2E-Tester", "Network")
    assert not net_perf, "Network metrics must NOT include Identity & Access runs"

    # Learner level + streak derived from runs
    level = db.get_learner_level("E2E-Tester")
    assert level == grade_for(int(evaluation.get("score", 0))), \
        f"learner level {level} != grade of run score"
    assert db.get_practice_streak("E2E-Tester") >= 1

    # Upsert must NOT wipe history on re-onboarding (audit finding #10)
    db.create_user("E2E-Tester", "ciso", ["Network", "Web App"])
    assert db.get_run_count("E2E-Tester") == 1, "re-onboarding wiped run history!"
    assert db.get_user("E2E-Tester")["role"] == "ciso"
    assert db.get_user("E2E-Tester")["domains"] == ["Network", "Web App"]

    # Second run in a different domain must not leak into Identity metrics
    db.save_run(recorder.session, evaluation, scenario)  # still Identity & Access
    assert db.get_run_count("E2E-Tester") == 2
    print(f"  mastery rows={len(mastery)}, learner_level={level}, "
          f"weak_techniques(IA)={len(weak_ia)}, streak={db.get_practice_streak('E2E-Tester')}")
    print("Student model OK")


def check_migration() -> None:
    """Migration tool: renames old 12->7 domains, drops deleted domains,
    rebuilds mastery, preserves history."""
    print("-" * 70)
    print("Testing DB v2 migration tool...")
    import tempfile
    from pathlib import Path
    import json
    import tools.migrate_db_v2 as mig

    tmp = Path(tempfile.mkdtemp(prefix="trainer_mig_")) / "sessions.db"
    pre = SessionDB(str(tmp))
    pre.create_user("MigUser", "analyst", ["Network Attacks", "Web Application Attacks", "Physical Security"])
    conn = pre._conn
    conn.execute(
        "INSERT INTO runs (user_name, scenario_id, role_used, score, grade, "
        "started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("MigUser", "legacy_scenario", "analyst", 42, "Novice", "2026-08-01T10:00:00", "2026-08-01T11:00:00"),
    )
    run_id = conn.execute("SELECT last_insert_rowid() AS r").fetchone()["r"]
    conn.execute(
        "INSERT INTO actions (run_id, phase_num, phase_title, user_response, mitre_technique) "
        "VALUES (?, 1, 'Triage', 'blocked the IP', 'T1110.004 Credential Stuffing')",
        (run_id,),
    )
    conn.execute("INSERT INTO domain_metrics (user_name, domain, avg_score, total_runs) "
                 "VALUES ('MigUser', 'Network Attacks', 42.0, 1)")
    conn.commit()
    pre.close()

    summary = mig.migrate(tmp)
    assert summary["backup"] and Path(summary["backup"]).exists(), "backup missing"
    assert summary["users_domains_dropped"] == 1, "Physical Security should be dropped"

    post = SessionDB(str(tmp))
    try:
        u = post.get_user("MigUser")
        assert u["domains"] == ["Network", "Web App"], f"migration rename wrong: {u['domains']}"
        assert post.get_run_count("MigUser") == 1, "migration must preserve run history"
        mastery = post.get_mastery("MigUser")
        assert len(mastery) == 1 and mastery[0]["technique"] == "T1110.004", mastery
        assert "Credential Stuffing" in (mastery[0].get("technique_name") or ""), mastery
        assert mastery[0]["level"] == "Novice", f"level {mastery[0]['level']} != Novice for 42"
        metrics = post.get_domain_performance("MigUser", "Network")
        assert not metrics, "stale global-scope metrics should be dropped"
        conn = post._conn
        assert conn.execute("SELECT COUNT(*) AS n FROM domain_metrics").fetchone()["n"] == 0
    finally:
        post.close()
    print(f"  migration ok: domains renamed, mastery built={len(mastery)}, history preserved")
    print("Migration OK")


def check_adaptive() -> None:
    """Adaptive engine (P6): weakest-technique targeting, difficulty progression,
    spaced re-practice, generate/play/none modes."""
    print("-" * 70)
    print("Testing adaptive recommendation (P6)...")
    import tempfile
    from pathlib import Path
    from core.adaptive import recommend_next, difficulty_for_level

    sniff_cls = SCENARIO_BY_ID.get("network_sniffing___passive_packet_capture_campaign")
    assert sniff_cls is not None, "network sniffing scenario missing from library"

    tmp = Path(tempfile.mkdtemp(prefix="trainer_adapt_")) / "sessions.db"
    db = SessionDB(str(tmp))
    try:
        db.create_user("AdaptUser", "analyst", ["Network"])

        def _seed_run(user: str, technique: str, response: str, score: int) -> None:
            rec = Recorder()
            rec.set_context(user_name=user, incident_title=sniff_cls.meta.incident_title,
                            incident_category="Network", incident_summary="x")
            ph = sniff_cls.phases[0]
            rec.record(phase_number=1, phase_title=ph.title, situation=ph.situation,
                       mitre_tactic=ph.mitre_tactic, mitre_technique=technique,
                       prompt="What do you do?", choice_type="freeform",
                       user_response=response, options_presented=[],
                       ideal_answer=ph.reference_answer, reference_explanation="",
                       response_score=3.0)
            db.save_run(rec.session, {"score": score, "phase_evaluations": []}, sniff_cls)

        # One weak run on T1040 (Needs Work) -> play mode targeting T1040
        _seed_run("AdaptUser", ph_tech := sniff_cls.phases[0].mitre_technique,
                  "disable the span session and terminate tshark", 20)
        rec2 = recommend_next(db, "AdaptUser", ["Network"])
        assert rec2["mode"] == "play", f"expected play, got {rec2['mode']}: {rec2['reason']}"
        assert rec2["scenario_cls"] is not None
        assert "T1040" in rec2["technique"], rec2
        assert sniff_cls.meta.incident_title in rec2["reason"], rec2["reason"]
        print(f"  weak-run -> {rec2['mode']} targeting {rec2['technique']}")

        # Difficulty progression: level -> scenario difficulty
        assert difficulty_for_level("Needs Work") == "Easy"
        assert difficulty_for_level("Novice") == "Easy"
        assert difficulty_for_level("Intermediate") == "Medium"
        assert difficulty_for_level("Proficient") == "Hard"

        # Spaced re-practice: stale (>7 days) technique gets priority + reason says so
        db._conn.execute("UPDATE mastery SET last_practiced = date('now','-10 days') "
                         "WHERE user_name='AdaptUser'")
        db._conn.commit()
        rec3 = recommend_next(db, "AdaptUser", ["Network"])
        assert "day" in rec3["reason"], rec3["reason"]
        print(f"  stale re-practice reason: {rec3['reason'][:80]}...")

        # All mastered -> mode 'none'
        db.create_user("ProUser", "analyst", ["Network"])
        _seed_run("ProUser", ph_tech, "disable the span session and terminate tshark", 95)
        recN = recommend_next(db, "ProUser", ["Network"])
        assert recN["mode"] == "none", recN
        print(f"  all-mastered -> {recN['mode']}")

        # Technique with no existing scenario -> mode 'generate'
        db.create_user("GenUser", "analyst", ["Network"])
        _seed_run("GenUser", "T9999 — Fake Technique", "something", 10)
        recG = recommend_next(db, "GenUser", ["Network"])
        assert recG["mode"] == "generate", recG
        assert "T9999" in recG["technique"]
        print(f"  unknown-technique -> {recG['mode']}: {recG['technique']}")
    finally:
        db.close()
    print("Adaptive OK")


def check_generator_v2() -> None:
    """Generator v2 validation: format-2 schema, taxonomy category check (tautology
    killed), phase graph integrity, HTML stripping."""
    print("-" * 70)
    print("Testing scenario generator v2 validation...")
    import copy
    from core.scenario_generator import _validate_scenario, _DOMAIN_MITRE_MAP

    net_techs = _DOMAIN_MITRE_MAP.get("Network") or ["T1040"]

    def make_valid() -> dict:
        ids = [f"p{i}" for i in range(1, 7)]
        phases = []
        for i, pid in enumerate(ids):
            phases.append({
                "id": pid,
                "phase_type": ["triage", "analysis", "containment", "eradication", "recovery", "lessons"][i],
                "title": f"Phase {i+1}",
                "situation": f"Situation {i+1}",
                "prompt": "What do you do?",
                "guidance": {"what": "identify", "action": "act", "why": "why"},
                "hint": "hint",
                "hints": ["hint2"],
                "ideal_concepts": [f"concept{j}" for j in range(6)],
                "reference_answer": "reference answer text",
                "followup_good": "good followup",
                "followup_weak": "weak followup",
                "next": ids[i + 1] if i + 1 < len(ids) else "",
                "mitre_tactic": "Discovery",
                "mitre_technique": net_techs[0],
            })
        return {
            "id": "gen_test_1",
            "name": "Test Scenario",
            "category": "Network",
            "format_version": 2,
            "difficulty": "Easy",
            "incident": {"title": "T", "opening": "O", "summary": "S" * 100},
            "phases": phases,
        }

    valid = make_valid()
    assert _validate_scenario(copy.deepcopy(valid)) == [], _validate_scenario(valid)
    print("  valid v2 scenario passes")

    # Tautology fix: category outside the taxonomy must be rejected
    bad_cat = make_valid()
    bad_cat["category"] = "NotARealDomain"
    errs = _validate_scenario(bad_cat)
    assert any("category" in e for e in errs), errs
    print("  unknown category rejected (tautology killed)")

    # Missing v2 key
    no_ref = make_valid()
    no_ref["phases"][0].pop("reference_answer")
    assert _validate_scenario(no_ref), "missing reference_answer must fail"

    # Dangling next link
    bad_next = make_valid()
    bad_next["phases"][0]["next"] = "ghost_phase"
    assert any("next" in e for e in _validate_scenario(bad_next)), _validate_scenario(bad_next)

    # Too few ideal_concepts
    bad_concepts = make_valid()
    bad_concepts["phases"][0]["ideal_concepts"] = ["a", "b"]
    assert any("ideal_concepts" in e for e in _validate_scenario(bad_concepts))

    # Fewer than 6 phases
    short = make_valid()
    short["phases"] = short["phases"][:3]
    assert _validate_scenario(short), "short scenario must fail"

    # Bad phase_type
    bad_type = make_valid()
    bad_type["phases"][0]["phase_type"] = "nonsense"
    assert any("phase_type" in e for e in _validate_scenario(bad_type))

    # Technique from another domain must fail
    web_techs = _DOMAIN_MITRE_MAP.get("Web App") or ["T1190"]
    bad_tech = make_valid()
    bad_tech["phases"][0]["mitre_technique"] = web_techs[0]
    assert any("MITRE" in e for e in _validate_scenario(bad_tech)), _validate_scenario(bad_tech)
    print("  v2 key requirements enforced")

    # HTML stripping happens in-place
    dirty = make_valid()
    dirty["phases"][0]["title"] = "<script>alert(1)</script>Phase 1"
    _validate_scenario(dirty)
    assert "<script>" not in dirty["phases"][0]["title"], "HTML must be stripped"
    print("  HTML stripped")
    print("Generator v2 OK")


def check_converter_roundtrip() -> None:
    """Converter (P2/P8): v1 -> v2 derivation works, and every curated v2 YAML
    round-trips through transform() with curated content preserved and stays
    loadable by the app's own loader."""
    print("-" * 70)
    print("Testing converter round-trip (all curated YAMLs)...")
    import yaml
    from pathlib import Path
    from tools import convert_to_freeform as conv
    from scenarios.loader import _build_scenario_class, PHASE_TYPES

    # Part A: synthetic v1 fixture -> v2 must derive free-text content
    v1 = {
        "id": "conv_v1_fixture",
        "name": "Converter Fixture",
        "category": "Network",
        "format_version": 1,
        "difficulty": "Easy",
        "incident": {"title": "T", "summary": "First sentence of the summary. Second sentence gives context."},
        "phases": [
            {
                "title": "Phase 1 Triage",
                "situation": "S1",
                "prompt": "What is your first action?",
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1040",
                "choices": [
                    {"text": "Pull the packet captures and identify the span session", "is_ideal": True,
                     "explanation": "Packet captures reveal the scope of the sniffing campaign."},
                    {"text": "Reboot the switch", "is_ideal": False,
                     "explanation": "But rebooting destroys volatile evidence."},
                ],
            },
            {
                "title": "Phase 2 Containment",
                "situation": "S2",
                "prompt": "Contain the compromise.",
                "mitre_tactic": "Containment",
                "mitre_technique": "T1040",
                "choices": [
                    {"text": "Disable the span session and terminate tshark", "is_ideal": True,
                     "explanation": "This stops further collection while preserving logs."},
                    {"text": "Do nothing and watch", "is_ideal": False,
                     "explanation": "Waiting without action misses the ongoing collection."},
                ],
            },
        ],
    }
    out = conv.transform(v1)
    assert out["format_version"] == 2
    assert out["id"] == "conv_v1_fixture" and out["category"] == "Network"
    assert len(out["phases"]) == 2
    assert "packet captures" in out["phases"][0]["reference_answer"].lower()
    assert "Why:" in out["phases"][0]["reference_answer"]
    assert out["phases"][0]["hint"] and out["phases"][0]["hints"]
    assert len(out["phases"][0]["ideal_concepts"]) >= 5
    assert out["phases"][0]["followup_good"] == "S2"  # next phase's situation
    assert out["phases"][0]["next"] == out["phases"][1]["id"]
    assert "reboot" not in out["phases"][0]["hint"].lower(), "hint must not leak the weak option"
    print("  v1 fixture -> v2 derivation OK (reference_answer, hints, concepts, followups)")

    # Part B: every curated v2 YAML round-trips faithfully + reloads
    data_dir = Path(__file__).resolve().parents[1] / "scenarios" / "data"
    files = [p for p in sorted(data_dir.rglob("*.yaml")) if p.parent.name != "generated"]
    assert len(files) >= 80, f"expected ~83 curated YAMLs, found {len(files)}"
    failures: list[str] = []
    checked = 0
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rt = conv.transform(dict(data))
        if rt["format_version"] != 2 or rt["id"] != data.get("id") or rt["category"] != data.get("category"):
            failures.append(f"{path.name}: id/category/format changed")
            continue
        if len(rt["phases"]) != len(data.get("phases", [])):
            failures.append(f"{path.name}: phase count {len(rt['phases'])} != {len(data.get('phases', []))}")
            continue
        ids = {p["id"] for p in rt["phases"]}
        for p in rt["phases"]:
            g = p.get("guidance") or {}
            if not all((g.get(k) or "").strip() for k in ("what", "action", "why")):
                failures.append(f"{path.name}:{p['id']} guidance broken")
            if not (p.get("reference_answer") or "").strip():
                failures.append(f"{path.name}:{p['id']} reference_answer lost")
            if len(p.get("ideal_concepts") or []) < 5:
                failures.append(f"{path.name}:{p['id']} ideal_concepts lost")
            if not (p.get("followup_good") or "").strip() or not (p.get("followup_weak") or "").strip():
                failures.append(f"{path.name}:{p['id']} followups lost")
            if not (p.get("hint") or "").strip():
                failures.append(f"{path.name}:{p['id']} hint lost")
            if p.get("phase_type") and p["phase_type"] not in PHASE_TYPES:
                failures.append(f"{path.name}:{p['id']} phase_type {p['phase_type']}")
            for nav in ("next", "next_weak"):
                if p.get(nav) and p[nav] not in ids:
                    failures.append(f"{path.name}:{p['id']} dangling {nav}={p[nav]}")
        # the transformed dict must load through the app's own loader
        cls = _build_scenario_class(rt, str(path))
        if cls._scenario_id != data.get("id") or len(cls.phases) != len(rt["phases"]):
            failures.append(f"{path.name}: loader mismatch after round-trip")
        checked += 1
    assert not failures, "round-trip failures:\n  " + "\n  ".join(failures[:10])
    print(f"  {checked} curated YAMLs round-trip OK (content preserved, loader-accepted)")
    print("Converter OK")


def main() -> int:
    print("=" * 70)
    print(f"E2E TEST: Blue-team IR pipeline (VPN Credential Stuffing, free-text, role={USER_ROLE})")
    print("=" * 70)

    # Audit #10: never pollute the real reports/ dir or sessions.db — temp dir + in-memory DB
    report_dir = Path(tempfile.mkdtemp(prefix="trainer_report_"))
    reporter_mod.REPORT_DIR = report_dir

    # P8 guard: no file may be created inside the repo during the run
    repo_root = Path(__file__).resolve().parents[1]
    before = {str(p.relative_to(repo_root)) for p in repo_root.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts}

    recorder, scenario = drive_scenario()

    check_scorer()
    check_grading()
    check_fallback_seeded()
    check_report_escaping()
    check_migration()
    check_adaptive()
    check_generator_v2()
    check_converter_roundtrip()

    print(f"\nRecorded {len(recorder.session.actions)} actions:")
    for a in recorder.session.actions:
        print(f"  Phase {a.phase_number}: {a.phase_title}")
        print(f"    Type: {a.choice_type} | Response: {a.user_response[:60]}")
        print(f"    Ideal: {a.ideal_answer[:60]}")
        assert a.response_score >= 0.0, f"phase {a.phase_number} missing response_score"
        assert isinstance(a.hints_used, int) and a.hints_used >= 0
        assert isinstance(a.looked_up, bool)
        print(f"    Offline score: {a.response_score}/10 | parts={a.parts_json} "
              f"| hints={a.hints_used} | looked_up={a.looked_up}")
        print()

    print("-" * 70)
    print("Calling AI evaluator (single request)...")
    evaluation = evaluate(recorder.session)

    score = evaluation.get("score", "?")
    grade = evaluation.get("grade", "?")
    fallback = evaluation.get("fallback", False)
    print(f"AI score: {score}")
    print(f"Grade:    {grade}")
    print(f"Fallback? {fallback}")

    if not fallback:
        phases = evaluation.get("phase_evaluations", [])
        print(f"Phase evaluations returned: {len(phases)}")
        for p in phases[:2]:
            print(f"  Phase {p.get('phase_number')}: {p.get('correctness')}/10 - {str(p.get('detailed_analysis',''))[:100]}")

        tightening = evaluation.get("tightening_recommendations", [])
        print(f"Tightening recommendations: {len(tightening)}")
        for t in tightening[:2]:
            if isinstance(t, dict):
                print(f"  [{t.get('priority')}] {t.get('area')}: {str(t.get('recommendation',''))[:80]}")

        print(f"Strengths: {len(evaluation.get('strengths', []))}")
        print(f"Weaknesses: {len(evaluation.get('weaknesses', []))}")
        print(f"Next training: {len(evaluation.get('next_training_scenarios', []))}")

    print()
    print("-" * 70)
    print("Generating reports...")
    paths = generate_all(recorder.session, evaluation)

    print()
    all_ok = True
    for kind, p in paths.items():
        if not p:
            print(f"  WARN: {kind} missing")
            continue
        if not Path(p).exists():
            print(f"  FAIL: {kind} file not created")
            all_ok = False
            continue
        sz = Path(p).stat().st_size
        if sz == 0:
            print(f"  FAIL: {kind} file empty")
            all_ok = False
        else:
            print(f"  OK: {kind} = {sz}B  {p}")

    if all_ok:
        # Phase 1: DB integration test
        print("-" * 70)
        print("Testing DB integration...")
        db = SessionDB(":memory:")

        if db.available:
            db.create_user("E2E-Tester", USER_ROLE, ["Identity & Access"])
            run_id = db.save_run(recorder.session, evaluation, scenario)
            assert run_id > 0, f"save_run should return positive id, got {run_id}"
            assert db.get_run_count("E2E-Tester") == 1
            last = db.get_last_run("E2E-Tester")
            assert last is not None
            assert last["score"] == evaluation.get("score")
            assert last["grade"] == evaluation.get("grade")
            perf = db.get_domain_performance("E2E-Tester")
            assert len(perf) > 0
            print(f"  DB OK: run_id={run_id}, last_score={last['score']}")
            check_mastery(db, recorder, evaluation, scenario)
            db.close()
        else:
            print("  WARN: DB not available")

        print()
        print("=" * 70)
        print("E2E TEST PASSED")
        print("=" * 70)
        after = {str(p.relative_to(repo_root)) for p in repo_root.rglob("*")
                 if p.is_file() and "__pycache__" not in p.parts}
        new_files = sorted(after - before)
        assert not new_files, f"files written outside temp dirs: {new_files[:10]}"
        shutil.rmtree(report_dir, ignore_errors=True)
        return 0
    else:
        print("\n" + "=" * 70)
        print("E2E TEST FAILED")
        print("=" * 70)
        shutil.rmtree(report_dir, ignore_errors=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
