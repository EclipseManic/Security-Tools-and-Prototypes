"""SessionDB: canonical mastery, migrations, live runs, analytics scoping."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

import pytest

from core.recorder import Recorder
from core.session_db import SessionDB
from scenarios.loader import SCENARIO_BY_ID

VPN = SCENARIO_BY_ID["vpn_credential_stuffing"]


def _recorder(
    *,
    user: str = "DbUser",
    technique: str = "T1110.004 — Credential Stuffing",
    response_score: float = 6.0,
    category: str = "Identity & Access",
) -> Recorder:
    rec = Recorder()
    rec.set_context(
        user_name=user,
        incident_title="Credential Stuffing",
        incident_category=category,
        incident_summary="x",
    )
    rec.record(
        phase_number=1,
        phase_title="Triage",
        situation="x",
        mitre_tactic="TA0006",
        mitre_technique=technique,
        prompt="What do you do?",
        choice_type="freeform",
        user_response="pull the logs",
        options_presented=[],
        ideal_answer="pull the logs and reset credentials",
        reference_explanation="because",
        response_score=response_score,
    )
    return rec


@pytest.fixture()
def db(tmp_path):
    database = SessionDB(str(tmp_path / "sessions.db"))
    assert database.available
    yield database
    database.close()


def test_user_upsert_preserves_history(db) -> None:
    db.create_user("DbUser", "analyst", ["Identity & Access"])
    db.save_run(_recorder().session, {"score": 50, "phase_evaluations": []}, VPN)
    db.create_user("DbUser", "ciso", ["Network"])
    assert db.get_user("DbUser")["role"] == "ciso"
    assert db.get_run_count("DbUser") == 1


def test_canonical_mastery_merges_label_variants(db) -> None:
    db.create_user("DbUser", "analyst", ["Identity & Access"])
    db.save_run(
        _recorder(technique="T1110.004 Credential Stuffing").session,
        {"score": 40, "phase_evaluations": []},
        VPN,
    )
    db.save_run(
        _recorder(technique="T1110.004 — Credential Stuffing").session,
        {"score": 80, "phase_evaluations": []},
        VPN,
    )
    mastery = db.get_mastery("DbUser")
    assert len(mastery) == 1, mastery
    row = mastery[0]
    assert row["technique"] == "T1110.004"
    assert "Credential Stuffing" in row["technique_name"]
    assert row["attempts"] == 2
    assert row["avg_score"] == 60.0
    assert row["best_score"] == 80
    assert row["level"] == "Intermediate"


def test_mastery_domain_filter_uses_canonical_key(db) -> None:
    db.create_user("DbUser", "analyst", ["Identity & Access"])
    db.save_run(_recorder().session, {"score": 50, "phase_evaluations": []}, VPN)
    assert db.get_mastery("DbUser", "Network") == []
    assert db.get_mastery("DbUser", "Identity & Access")[0]["technique"] == "T1110.004"
    assert db.get_weak_techniques("DbUser", "Network") == []
    assert db.get_weak_techniques("DbUser", "Identity & Access") == ["T1110.004"]


def test_live_run_lifecycle(db) -> None:
    db.create_user("DbUser", "analyst", ["Identity & Access"])
    run_id = db.start_run(
        "DbUser", "vpn_credential_stuffing", "analyst", domain="Identity & Access"
    )
    assert run_id > 0
    assert db.get_run_count("DbUser") == 0
    live = db.get_live_run("DbUser")
    assert live and live["run_id"] == run_id

    rec = _recorder()
    completed = db.save_run(
        rec.session, {"score": 70, "phase_evaluations": []}, VPN, run_id=run_id
    )
    assert completed == run_id
    assert db.get_live_run("DbUser") is None
    assert db.get_run_count("DbUser") == 1
    assert db.get_last_run("DbUser")["score"] == 70
    # Only one run row, and its actions were not duplicated.
    assert db._conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"] == 1
    assert db._conn.execute("SELECT COUNT(*) AS n FROM actions").fetchone()["n"] == 1


def test_abandoned_run_excluded_from_analytics(db) -> None:
    db.create_user("DbUser", "analyst", ["Identity & Access"])
    run_id = db.start_run(
        "DbUser", "vpn_credential_stuffing", "analyst", domain="Identity & Access"
    )
    db.abandon_run(run_id)
    assert db.get_run_count("DbUser") == 0
    assert db.get_recent_scenarios("DbUser") == []
    assert db.get_live_run("DbUser") is None


def test_domain_performance_shapes(db) -> None:
    db.create_user("DbUser", "analyst", ["Identity & Access"])
    db.save_run(_recorder().session, {"score": 60, "phase_evaluations": []}, VPN)
    one = db.get_domain_performance("DbUser", "Identity & Access")
    assert isinstance(one, dict) and one["domain"] == "Identity & Access"
    assert one["total_runs"] == 1
    assert one["weakest_technique"] == "T1110.004"
    every = db.get_domain_performance("DbUser")
    assert isinstance(every, list) and len(every) == 1
    assert db.get_domain_performance("DbUser", "Network") == {}


OLD_SCHEMA = """
CREATE TABLE users (
    name TEXT PRIMARY KEY, role TEXT NOT NULL, domains TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL REFERENCES users(name),
    scenario_id TEXT NOT NULL, yaml_source TEXT, role_used TEXT NOT NULL,
    score INTEGER NOT NULL, grade TEXT NOT NULL,
    started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
    evaluation_json TEXT, domain TEXT, format_version INTEGER DEFAULT 1,
    difficulty TEXT, next_scenario_reason TEXT, learner_level TEXT
);
CREATE TABLE actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    phase_num INTEGER NOT NULL, phase_title TEXT NOT NULL,
    user_response TEXT NOT NULL, ideal_answer TEXT, correctness INTEGER,
    mitre_tactic TEXT, mitre_technique TEXT, response_score REAL,
    parts_json TEXT, hints_used INTEGER NOT NULL DEFAULT 0,
    looked_up INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE domain_metrics (
    user_name TEXT NOT NULL REFERENCES users(name), domain TEXT NOT NULL,
    avg_score REAL, weakest_technique TEXT, total_runs INTEGER DEFAULT 0,
    last_practiced TEXT, PRIMARY KEY (user_name, domain)
);
CREATE TABLE mastery (
    user_name TEXT NOT NULL REFERENCES users(name), technique TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, avg_score REAL NOT NULL DEFAULT 0,
    best_score INTEGER NOT NULL DEFAULT 0, last_practiced TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'Unpracticed',
    PRIMARY KEY (user_name, technique)
);
"""


def test_legacy_database_migrates_in_place(tmp_path) -> None:
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        ("Legacy", "analyst", json.dumps(["Identity & Access"]), now),
    )
    conn.execute(
        "INSERT INTO runs (user_name, scenario_id, role_used, score, grade, "
        "started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("Legacy", "vpn_credential_stuffing", "analyst", 42, "Novice", now, now),
    )
    run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO actions (run_id, phase_num, phase_title, user_response, "
        "mitre_technique, response_score) VALUES (?, ?, ?, ?, ?, ?)",
        (run_id, 1, "Triage", "check logs", "T1110.004 Credential Stuffing", 4.2),
    )
    conn.execute(
        "INSERT INTO mastery (user_name, technique, attempts, avg_score, "
        "best_score, last_practiced, level) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("Legacy", "T1110.004 Credential Stuffing", 1, 42.0, 42, now, "Novice"),
    )
    conn.commit()
    conn.close()

    db = SessionDB(str(path))
    try:
        info = {r["name"]: r for r in db._conn.execute("PRAGMA table_info(runs)")}
        assert info["score"]["notnull"] == 0
        assert info["grade"]["notnull"] == 0
        assert info["completed_at"]["notnull"] == 0
        assert "status" in info

        mastery = db.get_mastery("Legacy")
        assert len(mastery) == 1
        assert mastery[0]["technique"] == "T1110.004"
        assert mastery[0]["technique_name"]

        run = db._conn.execute(
            "SELECT domain, status FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        assert run["domain"] == "Identity & Access"
        assert run["status"] == "completed"

        action = db._conn.execute(
            "SELECT technique_key FROM actions WHERE run_id = ?", (run_id,)
        ).fetchone()
        assert action["technique_key"] == "T1110.004"

        metrics = db.get_domain_performance("Legacy", "Identity & Access")
        assert metrics["weakest_technique"] == "T1110.004"
    finally:
        db.close()
