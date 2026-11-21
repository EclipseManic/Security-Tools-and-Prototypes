"""
core/session_db.py
SQLite persistence layer for the blue-team IR trainer.

Tracks:
  - users (name, role, domains)
  - runs (one per scenario attempt; completed or live)
  - actions (per-phase details within a run)
  - domain_metrics (materialized per-domain performance summary)
  - mastery (one canonical row per MITRE technique)

Always-on: every session is recorded, even if AI generation is declined.
Backward compatible: if the DB can't be created, the app falls back to
stateless operation (existing behavior).

Schema notes
------------
- Mastery is keyed by the **canonical technique id** (`T1110.004`) rather than
  the free-text label. `actions.technique_key` stores the same key so domain
  filters can join without parsing strings in SQL.
- `runs.status` separates `in_progress`, `completed`, `abandoned`. Analytics
  only consider `completed` runs; legacy rows default to `completed`.
- Older databases are migrated in place: the `runs` table is rebuilt once so
  `score`/`grade`/`completed_at` may be NULL while a run is live.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Optional

from config import BASE_DIR
from core.grading import grade_for as _grade_for
from core.mitre import canonical_technique, display_technique, parse_technique


DB_PATH = str(BASE_DIR / "sessions.db")
DEFAULT_DB_PATH = DB_PATH

RUN_STATUSES = ("in_progress", "completed", "abandoned")

# Bump when the schema changes. `_init_schema` becomes a cheap PRAGMA read for
# every connection after the first one in a process (FastAPI opens one
# connection per request), while a deleted/recreated file still migrates.
SCHEMA_VERSION = 3

_UNSET = object()

# Grade-band order used for "weakest first" sorting. Alphabetical ORDER BY on
# `level` would put Intermediate before Needs Work — wrong.
_LEVEL_RANK_SQL = (
    "CASE m.level "
    "WHEN 'Needs Work' THEN 0 "
    "WHEN 'Novice' THEN 1 "
    "WHEN 'Intermediate' THEN 2 "
    "WHEN 'Proficient' THEN 3 "
    "WHEN 'Expert' THEN 4 "
    "ELSE 5 END"
)


def _grade_from_score(score: int) -> str:
    return _grade_for(score)


def _json_load(raw: Any, default: Any) -> Any:
    """Decode a JSON column, tolerating NULL/corrupt legacy values."""
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def _connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Open a connection with sensible PRAGMAs.

    `check_same_thread=False` is required for FastAPI: sync dependencies and
    endpoints run on different threadpool workers, so a per-request connection
    can be entered in one thread and closed in another. Each request still
    owns its own connection, so statements remain serialized per connection.
    """
    conn = sqlite3.connect(
        db_path,
        detect_types=sqlite3.PARSE_DECLTYPES,
        check_same_thread=False,
        timeout=10.0,
    )
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
def _init_schema(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version >= SCHEMA_VERSION:
        return

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            name       TEXT PRIMARY KEY,
            role       TEXT NOT NULL,
            domains    TEXT NOT NULL,           -- JSON array
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name      TEXT NOT NULL REFERENCES users(name),
            scenario_id    TEXT NOT NULL,
            yaml_source    TEXT,
            role_used      TEXT NOT NULL,
            score          INTEGER,             -- NULL while in progress
            grade          TEXT,                -- NULL while in progress
            started_at     TEXT NOT NULL,
            completed_at   TEXT,                -- NULL while in progress
            evaluation_json TEXT,
            domain         TEXT,
            format_version INTEGER DEFAULT 1,
            difficulty     TEXT,
            next_scenario_reason TEXT,
            learner_level  TEXT,
            status         TEXT NOT NULL DEFAULT 'completed',
            current_phase_id TEXT,              -- live-run cursor
            visited_json   TEXT,                -- JSON array of visited phase ids
            draft_answer   TEXT,                -- unsaved answer in the composer
            assist_json    TEXT,                -- JSON map of hints/reveals used
            updated_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS actions (
            action_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id       INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            phase_num    INTEGER NOT NULL,
            phase_title  TEXT NOT NULL,
            user_response TEXT NOT NULL,
            ideal_answer TEXT,
            correctness  INTEGER,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            technique_key TEXT,
            response_score REAL,
            parts_json   TEXT,
            hints_used   INTEGER NOT NULL DEFAULT 0,
            looked_up    INTEGER NOT NULL DEFAULT 0,
            action_json  TEXT
        );

        CREATE TABLE IF NOT EXISTS domain_metrics (
            user_name      TEXT NOT NULL REFERENCES users(name),
            domain         TEXT NOT NULL,
            avg_score      REAL,
            weakest_technique TEXT,
            total_runs     INTEGER DEFAULT 0,
            last_practiced TEXT,
            PRIMARY KEY (user_name, domain)
        );

        CREATE TABLE IF NOT EXISTS mastery (
            user_name     TEXT NOT NULL REFERENCES users(name),
            technique     TEXT NOT NULL,           -- canonical id, e.g. "T1110.004"
            technique_name TEXT,                   -- display label
            attempts      INTEGER NOT NULL DEFAULT 0,
            avg_score     REAL NOT NULL DEFAULT 0, -- 0-100 run-score average
            best_score    INTEGER NOT NULL DEFAULT 0,
            last_practiced TEXT NOT NULL,
            level         TEXT NOT NULL DEFAULT 'Unpracticed',  -- via grade bands
            PRIMARY KEY (user_name, technique)
        );
    """)
    _ensure_run_columns(conn)
    _ensure_action_columns(conn)
    _ensure_mastery_columns(conn)
    _migrate_runs_allow_live(conn)

    # Indexes are recreated here because a table rebuild drops them.
    conn.executescript("""
        CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(user_name);
        CREATE INDEX IF NOT EXISTS idx_runs_user_status ON runs(user_name, status);
        CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id);
        CREATE INDEX IF NOT EXISTS idx_actions_technique ON actions(technique_key);
        CREATE INDEX IF NOT EXISTS idx_domain_metrics_user ON domain_metrics(user_name);
        CREATE INDEX IF NOT EXISTS idx_mastery_user ON mastery(user_name);
    """)

    _backfill_action_keys(conn)
    _backfill_run_domains(conn)
    _migrate_mastery_keys(conn)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()


def _table_info(conn: sqlite3.Connection, table: str) -> dict[str, sqlite3.Row]:
    return {row["name"]: row for row in conn.execute(f"PRAGMA table_info({table})")}


def _ensure_run_columns(conn: sqlite3.Connection) -> None:
    """Add student-model / lifecycle run columns to existing databases."""
    existing = _table_info(conn, "runs")
    additions = [
        ("domain", "TEXT"),
        ("format_version", "INTEGER DEFAULT 1"),
        ("difficulty", "TEXT"),
        ("next_scenario_reason", "TEXT"),
        ("learner_level", "TEXT"),
        ("status", "TEXT NOT NULL DEFAULT 'completed'"),
        ("current_phase_id", "TEXT"),
        ("visited_json", "TEXT"),
        ("draft_answer", "TEXT"),
        ("assist_json", "TEXT"),
        ("updated_at", "TEXT"),
    ]
    for name, ddl in additions:
        if name not in existing:
            conn.execute(f"ALTER TABLE runs ADD COLUMN {name} {ddl}")


def _ensure_action_columns(conn: sqlite3.Connection) -> None:
    """Add format-v2 / canonical-key action columns to existing databases."""
    existing = _table_info(conn, "actions")
    additions = [
        ("response_score", "REAL"),
        ("parts_json", "TEXT"),
        ("hints_used", "INTEGER NOT NULL DEFAULT 0"),
        ("looked_up", "INTEGER NOT NULL DEFAULT 0"),
        ("technique_key", "TEXT"),
        ("action_json", "TEXT"),
    ]
    for name, ddl in additions:
        if name not in existing:
            conn.execute(f"ALTER TABLE actions ADD COLUMN {name} {ddl}")


def _ensure_mastery_columns(conn: sqlite3.Connection) -> None:
    existing = _table_info(conn, "mastery")
    if "technique_name" not in existing:
        conn.execute("ALTER TABLE mastery ADD COLUMN technique_name TEXT")


def _migrate_runs_allow_live(conn: sqlite3.Connection) -> None:
    """Rebuild `runs` once so score/grade/completed_at can be NULL.

    SQLite cannot drop NOT NULL in place. The copy preserves run ids and all
    existing data; `actions` keeps its FK by table name after the rename.
    """
    info = _table_info(conn, "runs")
    needs_rebuild = any(
        info.get(column) is not None and info[column]["notnull"]
        for column in ("score", "grade", "completed_at")
    )
    if not needs_rebuild:
        return

    columns = [row["name"] for row in info.values()]
    quoted = ", ".join(f'"{c}"' for c in columns)
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF;")
    try:
        conn.executescript(f"""
            BEGIN;
            CREATE TABLE runs_new (
                run_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name      TEXT NOT NULL REFERENCES users(name),
                scenario_id    TEXT NOT NULL,
                yaml_source    TEXT,
                role_used      TEXT NOT NULL,
                score          INTEGER,
                grade          TEXT,
                started_at     TEXT NOT NULL,
                completed_at   TEXT,
                evaluation_json TEXT,
                domain         TEXT,
                format_version INTEGER DEFAULT 1,
                difficulty     TEXT,
                next_scenario_reason TEXT,
                learner_level  TEXT,
                status         TEXT NOT NULL DEFAULT 'completed',
                current_phase_id TEXT,
                visited_json   TEXT,
                draft_answer   TEXT,
                assist_json    TEXT,
                updated_at     TEXT
            );
            INSERT INTO runs_new ({quoted})
                SELECT {quoted} FROM runs;
            DROP TABLE runs;
            ALTER TABLE runs_new RENAME TO runs;
            COMMIT;
        """)
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON;")

    # Verify the parent/child relationship survived the rebuild.
    violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
    if violations:
        raise sqlite3.IntegrityError(
            f"runs table migration left foreign-key violations: {violations}"
        )


def _backfill_action_keys(conn: sqlite3.Connection) -> None:
    """Compute `technique_key` for legacy action rows (idempotent)."""
    rows = conn.execute(
        """
        SELECT DISTINCT mitre_technique FROM actions
        WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
          AND (technique_key IS NULL OR technique_key = '')
        """
    ).fetchall()
    for row in rows:
        raw = row["mitre_technique"]
        conn.execute(
            """
            UPDATE actions SET technique_key = ?
            WHERE mitre_technique = ?
              AND (technique_key IS NULL OR technique_key = '')
            """,
            (canonical_technique(raw), raw),
        )


def _backfill_run_domains(conn: sqlite3.Connection) -> None:
    """Fill `runs.domain` for legacy rows using the scenario registry."""
    try:
        missing = conn.execute(
            "SELECT DISTINCT scenario_id FROM runs "
            "WHERE domain IS NULL OR domain = ''"
        ).fetchall()
    except sqlite3.Error:
        return
    if not missing:
        return

    by_category: dict[str, str] = {}
    try:
        from scenarios.loader import SCENARIO_BY_ID  # lazy: avoids import cycle

        for sid, cls in SCENARIO_BY_ID.items():
            category = getattr(getattr(cls, "meta", None), "category", "") or ""
            if category:
                by_category[sid] = category
    except Exception:
        return

    for row in missing:
        category = by_category.get(row["scenario_id"])
        if category:
            conn.execute(
                "UPDATE runs SET domain = ? WHERE scenario_id = ? "
                "AND (domain IS NULL OR domain = '')",
                (category, row["scenario_id"]),
            )


# --------------------------------------------------------------------------- #
# Student model — module-level so schema migration can reuse it
# --------------------------------------------------------------------------- #
def _rebuild_mastery(conn: sqlite3.Connection, user_name: str) -> None:
    """Rebuild per-technique mastery from the user's completed history.

    - grouped by canonical technique key (legacy labels merge into one row);
    - attempts count distinct runs, not phase rows;
    - avg/best are run scores (0-100), banded via core/grading.
    """
    rows = conn.execute(
        """
        SELECT a.mitre_technique AS technique,
               r.run_id AS run_id,
               r.score AS score,
               r.completed_at AS completed_at
        FROM actions a
        JOIN runs r ON a.run_id = r.run_id
        WHERE r.user_name = ? AND r.status = 'completed'
          AND a.mitre_technique IS NOT NULL AND a.mitre_technique != ''
        """,
        (user_name,),
    ).fetchall()

    buckets: dict[str, dict[str, Any]] = {}
    for r in rows:
        raw = r["technique"]
        key = canonical_technique(raw)
        if not key:
            continue
        bucket = buckets.setdefault(
            key,
            {"runs": set(), "scores": [], "best": 0, "last": "", "name": ""},
        )
        score = int(r["score"] or 0)
        bucket["runs"].add(r["run_id"])
        bucket["scores"].append(score)
        bucket["best"] = max(bucket["best"], score)
        completed = r["completed_at"] or ""
        if completed > bucket["last"]:
            bucket["last"] = completed
        _, parsed_name = parse_technique(raw)
        if len(parsed_name) > len(bucket["name"]):
            bucket["name"] = parsed_name

    # Full rebuild: stale rows (including legacy free-text keys) disappear.
    conn.execute("DELETE FROM mastery WHERE user_name = ?", (user_name,))
    for key, bucket in buckets.items():
        avg = round(sum(bucket["scores"]) / len(bucket["scores"]), 1) if bucket["scores"] else 0.0
        label = display_technique(key, bucket["name"] or None)
        conn.execute(
            """
            INSERT INTO mastery (
                user_name, technique, technique_name, attempts, avg_score,
                best_score, last_practiced, level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_name,
                key,
                label,
                len(bucket["runs"]),
                avg,
                bucket["best"],
                bucket["last"],
                _grade_from_score(int(avg)),
            ),
        )
    conn.commit()


def _recalc_domain_metrics(conn: sqlite3.Connection, user_name: str, domain: str) -> None:
    """Recalculate avg_score and weakest_technique for one domain.

    Scoped to completed runs that actually belong to that domain. The weakest
    technique uses the average RUN score per canonical technique, so a
    scenario with several phases on one technique cannot outvote a run.
    """
    if not domain:
        return

    score_row = conn.execute(
        """
        SELECT COUNT(*) AS n, AVG(r.score) AS avg_score,
               MAX(r.completed_at) AS last_practiced
        FROM runs r
        WHERE r.user_name = ? AND r.domain = ? AND r.status = 'completed'
        """,
        (user_name, domain),
    ).fetchone()

    total_runs = score_row["n"] if score_row else 0
    avg_score = score_row["avg_score"] if score_row and score_row["avg_score"] is not None else 0.0
    last_practiced = score_row["last_practiced"] if score_row and score_row["last_practiced"] else None

    weakest = conn.execute(
        """
        SELECT a.technique_key AS technique
        FROM actions a
        JOIN runs r ON a.run_id = r.run_id
        WHERE r.user_name = ? AND r.domain = ? AND r.status = 'completed'
          AND a.technique_key IS NOT NULL AND a.technique_key != ''
        GROUP BY a.technique_key
        ORDER BY AVG(r.score) ASC, COUNT(DISTINCT r.run_id) DESC
        LIMIT 1
        """,
        (user_name, domain),
    ).fetchone()

    conn.execute(
        """
        INSERT INTO domain_metrics (user_name, domain, avg_score, weakest_technique, total_runs, last_practiced)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_name, domain) DO UPDATE SET
            avg_score = excluded.avg_score,
            weakest_technique = excluded.weakest_technique,
            total_runs = excluded.total_runs,
            last_practiced = excluded.last_practiced
        """,
        (
            user_name,
            domain,
            round(avg_score, 1),
            weakest["technique"] if weakest else None,
            total_runs,
            last_practiced,
        ),
    )
    conn.commit()


def _migrate_mastery_keys(conn: sqlite3.Connection) -> None:
    """Rebuild mastery for users whose rows still use free-text technique keys."""
    rows = conn.execute(
        "SELECT user_name, technique, technique_name FROM mastery"
    ).fetchall()
    stale_users = {
        row["user_name"]
        for row in rows
        if canonical_technique(row["technique"]) != row["technique"]
        or not row["technique_name"]
    }
    for user_name in stale_users:
        _rebuild_mastery(conn, user_name)
        domains = [
            r["domain"]
            for r in conn.execute(
                "SELECT DISTINCT domain FROM runs "
                "WHERE user_name = ? AND domain IS NOT NULL AND domain != '' "
                "AND status = 'completed'",
                (user_name,),
            ).fetchall()
        ]
        for domain in domains:
            _recalc_domain_metrics(conn, user_name, domain)


# --------------------------------------------------------------------------- #
# SessionDB
# --------------------------------------------------------------------------- #
class SessionDB:
    """Thin wrapper around SQLite for persistence. All methods use parameterized queries."""

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        try:
            self._conn = _connect(db_path)
            _init_schema(self._conn)
        except sqlite3.Error:
            self._conn = None  # fallback to stateless

    @property
    def available(self) -> bool:
        return self._conn is not None

    # ------------------------------------------------------------------ #
    # Users
    # ------------------------------------------------------------------ #
    def create_user(self, name: str, role: str, domains: list[str]) -> None:
        """Create a user, or update role/domains on re-onboarding.

        Upsert (not INSERT OR REPLACE) so runs/mastery history is never wiped
        by a re-onboarding (audit finding #10).
        """
        if not self._conn:
            return
        self._conn.execute(
            """
            INSERT INTO users (name, role, domains, created_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET role = excluded.role, domains = excluded.domains
            """,
            (name, role, json.dumps(domains), datetime.now().isoformat(timespec="seconds")),
        )
        self._conn.commit()

    def get_user(self, name: str) -> Optional[dict[str, Any]]:
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT name, role, domains, created_at FROM users WHERE name = ?",
            (name,),
        ).fetchone()
        if not row:
            return None
        return {
            "name": row["name"],
            "role": row["role"],
            "domains": json.loads(row["domains"]) if row["domains"] else [],
            "created_at": row["created_at"],
        }

    def get_users(self) -> list[dict[str, Any]]:
        """All known users (used by the web UI account picker)."""
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT name, role, domains, created_at FROM users ORDER BY name"
        ).fetchall()
        return [
            {
                "name": r["name"],
                "role": r["role"],
                "domains": json.loads(r["domains"]) if r["domains"] else [],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def update_user_domains(self, name: str, domains: list[str]) -> None:
        if not self._conn:
            return
        self._conn.execute(
            "UPDATE users SET domains = ? WHERE name = ?",
            (json.dumps(domains), name),
        )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # Runs — lifecycle
    # ------------------------------------------------------------------ #
    def start_run(
        self,
        user_name: str,
        scenario_id: str,
        role_used: str,
        *,
        domain: str = "",
        format_version: int = 2,
        difficulty: str = "",
        yaml_source: str = "",
        started_at: Optional[str] = None,
    ) -> int:
        """Create an `in_progress` run. Returns 0 when persistence is off."""
        if not self._conn:
            return 0
        stamp = started_at or datetime.now().isoformat(timespec="seconds")
        cur = self._conn.execute(
            """
            INSERT INTO runs (
                user_name, scenario_id, yaml_source, role_used, score, grade,
                started_at, completed_at, domain, format_version, difficulty,
                status, updated_at
            ) VALUES (?, ?, ?, ?, NULL, NULL, ?, NULL, ?, ?, ?, 'in_progress', ?)
            """,
            (
                user_name,
                scenario_id,
                yaml_source or None,
                role_used,
                stamp,
                domain or None,
                format_version,
                difficulty or None,
                stamp,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def get_run(
        self, run_id: int, user_name: Optional[str] = None
    ) -> Optional[dict[str, Any]]:
        """Full run row, with `visited`/`assist` decoded from JSON."""
        if not self._conn or not run_id:
            return None
        if user_name:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ? AND user_name = ?",
                (run_id, user_name),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["visited"] = _json_load(data.get("visited_json"), [])
        data["assist"] = _json_load(data.get("assist_json"), {})
        return data

    def get_live_run(self, user_name: str) -> Optional[dict[str, Any]]:
        """Most recent unfinished run for a user, if any."""
        if not self._conn:
            return None
        row = self._conn.execute(
            """
            SELECT run_id, scenario_id, role_used, started_at, domain,
                   format_version, difficulty, current_phase_id, visited_json,
                   draft_answer, assist_json, updated_at
            FROM runs
            WHERE user_name = ? AND status = 'in_progress'
            ORDER BY started_at DESC, run_id DESC LIMIT 1
            """,
            (user_name,),
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["visited"] = _json_load(data.get("visited_json"), [])
        data["assist"] = _json_load(data.get("assist_json"), {})
        return data

    def update_run_state(
        self,
        run_id: int,
        *,
        current_phase_id: Any = _UNSET,
        visited: Any = _UNSET,
        draft_answer: Any = _UNSET,
        assist: Any = _UNSET,
    ) -> None:
        """Persist the live-run cursor/draft. Omitted arguments are untouched."""
        if not self._conn or not run_id:
            return
        sets: list[str] = []
        params: list[Any] = []
        if current_phase_id is not _UNSET:
            sets.append("current_phase_id = ?")
            params.append(current_phase_id)
        if visited is not _UNSET:
            sets.append("visited_json = ?")
            params.append(json.dumps(list(visited), ensure_ascii=False))
        if draft_answer is not _UNSET:
            sets.append("draft_answer = ?")
            params.append(draft_answer)
        if assist is not _UNSET:
            sets.append("assist_json = ?")
            params.append(json.dumps(assist, ensure_ascii=False))
        sets.append("updated_at = ?")
        params.append(datetime.now().isoformat(timespec="seconds"))
        params.append(run_id)
        self._conn.execute(
            f"UPDATE runs SET {', '.join(sets)} WHERE run_id = ?", params
        )
        self._conn.commit()

    def add_action(self, run_id: int, action: dict[str, Any]) -> int:
        """Append one answered phase to a live run. Returns action_id."""
        if not self._conn or not run_id:
            return 0
        technique_raw = str(action.get("mitre_technique") or "")
        cur = self._conn.execute(
            """
            INSERT INTO actions (
                run_id, phase_num, phase_title, user_response,
                ideal_answer, correctness, mitre_tactic, mitre_technique,
                technique_key, response_score, parts_json, hints_used,
                looked_up, action_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                int(action.get("phase_num") or 0),
                str(action.get("phase_title") or ""),
                str(action.get("user_response") or ""),
                str(action.get("ideal_answer") or ""),
                action.get("correctness"),
                str(action.get("mitre_tactic") or ""),
                technique_raw,
                canonical_technique(technique_raw) if technique_raw else "",
                float(action.get("response_score", -1.0) or -1.0),
                str(action.get("parts_json") or ""),
                int(action.get("hints_used") or 0),
                1 if action.get("looked_up") else 0,
                json.dumps(action, ensure_ascii=False, default=str),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def get_run_actions(self, run_id: int) -> list[dict[str, Any]]:
        """All answered phases for a run, with the stored action blob decoded."""
        if not self._conn or not run_id:
            return []
        rows = self._conn.execute(
            "SELECT * FROM actions WHERE run_id = ? ORDER BY phase_num, action_id",
            (run_id,),
        ).fetchall()
        actions: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            data["action"] = _json_load(data.pop("action_json", None), None)
            actions.append(data)
        return actions

    def abandon_live_runs(self, user_name: str, *, except_run_id: int = 0) -> int:
        """Abandon every unfinished run for a user except `except_run_id`."""
        if not self._conn:
            return 0
        stamp = datetime.now().isoformat(timespec="seconds")
        cur = self._conn.execute(
            """
            UPDATE runs SET status = 'abandoned', completed_at = ?, updated_at = ?
            WHERE user_name = ? AND status = 'in_progress' AND run_id != ?
            """,
            (stamp, stamp, user_name, except_run_id),
        )
        self._conn.commit()
        return int(cur.rowcount or 0)

    def abandon_run(self, run_id: int) -> None:
        if not self._conn or not run_id:
            return
        self._conn.execute(
            "UPDATE runs SET status = 'abandoned', completed_at = ? "
            "WHERE run_id = ? AND status = 'in_progress'",
            (datetime.now().isoformat(timespec="seconds"), run_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------ #
    # Runs — save a completed scenario
    # ------------------------------------------------------------------ #
    def save_run(
        self,
        session_log: Any,  # types.SessionLog-like object
        evaluation: dict[str, Any],
        scenario_cls: Any,  # Scenario subclass
        *,
        run_id: int = 0,
    ) -> int:
        """Persist a completed run + all phase actions. Returns run_id.

        When `run_id` refers to a live run created by `start_run`, that row is
        completed in place; otherwise a completed row is inserted.
        """
        if not self._conn:
            return 0

        scenario_id = getattr(scenario_cls, "_scenario_id", "") or scenario_cls.meta.name
        yaml_source = getattr(scenario_cls, "_yaml_source", "") or None
        domain = getattr(scenario_cls.meta, "category", "") or session_log.incident_category
        format_version = getattr(scenario_cls.meta, "format_version", 1)
        difficulty = getattr(scenario_cls.meta, "difficulty", "")

        score = int(evaluation.get("score", 0) or 0)
        grade = _grade_from_score(score)
        completed_at = datetime.now().isoformat(timespec="seconds")

        if run_id:
            existing = self._conn.execute(
                "SELECT run_id FROM runs WHERE run_id = ? AND user_name = ?",
                (run_id, session_log.user_name),
            ).fetchone()
        else:
            existing = None

        if existing:
            self._conn.execute(
                """
                UPDATE runs SET
                    scenario_id = ?, yaml_source = ?, role_used = ?, score = ?,
                    grade = ?, started_at = ?, completed_at = ?, evaluation_json = ?,
                    domain = ?, format_version = ?, difficulty = ?,
                    next_scenario_reason = ?, status = 'completed',
                    current_phase_id = NULL, visited_json = NULL,
                    draft_answer = NULL, assist_json = NULL, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    scenario_id,
                    yaml_source,
                    session_log.user_role,
                    score,
                    grade,
                    session_log.started_at,
                    completed_at,
                    json.dumps(evaluation),
                    domain,
                    format_version,
                    difficulty,
                    evaluation.get("next_scenario_reason", ""),
                    completed_at,
                    run_id,
                ),
            )
            # Replace any partial actions from a resumed live run.
            self._conn.execute("DELETE FROM actions WHERE run_id = ?", (run_id,))
        else:
            cur = self._conn.execute(
                """
                INSERT INTO runs (
                    user_name, scenario_id, yaml_source, role_used, score, grade,
                    started_at, completed_at, evaluation_json,
                    domain, format_version, difficulty, next_scenario_reason,
                    status, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
                """,
                (
                    session_log.user_name,
                    scenario_id,
                    yaml_source,
                    session_log.user_role,
                    score,
                    grade,
                    session_log.started_at,
                    completed_at,
                    json.dumps(evaluation),
                    domain,
                    format_version,
                    difficulty,
                    evaluation.get("next_scenario_reason", ""),
                    completed_at,
                ),
            )
            run_id = int(cur.lastrowid or 0)

        # Save each phase action
        for a in session_log.actions:
            technique_raw = getattr(a, "mitre_technique", "") or ""
            self._conn.execute(
                """
                INSERT INTO actions (
                    run_id, phase_num, phase_title, user_response,
                    ideal_answer, correctness, mitre_tactic, mitre_technique,
                    technique_key, response_score, parts_json, hints_used,
                    looked_up, action_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    a.phase_number,
                    a.phase_title,
                    a.user_response,
                    a.ideal_answer,
                    None,  # correctness from AI evaluation will be populated below
                    a.mitre_tactic,
                    technique_raw,
                    canonical_technique(technique_raw),
                    getattr(a, "response_score", -1.0),
                    getattr(a, "parts_json", ""),
                    getattr(a, "hints_used", 0),
                    1 if getattr(a, "looked_up", False) else 0,
                    json.dumps(
                        getattr(a, "to_dict", lambda: {})(),
                        ensure_ascii=False,
                        default=str,
                    ),
                ),
            )

        # Backfill correctness from AI phase_evaluations
        phase_evals = evaluation.get("phase_evaluations", [])
        for pe in phase_evals:
            if not isinstance(pe, dict):
                continue
            phase_num = pe.get("phase_number")
            correctness = pe.get("correctness")
            if phase_num is not None and correctness is not None:
                self._conn.execute(
                    "UPDATE actions SET correctness = ? WHERE run_id = ? AND phase_num = ?",
                    (correctness, run_id, phase_num),
                )

        self._conn.commit()

        # Student model: rebuild per-technique mastery, backfill the run's
        # learner level, then refresh the (domain-scoped) domain metrics.
        self._update_mastery(session_log.user_name)
        learner_level = self.get_learner_level(session_log.user_name)
        self._conn.execute(
            "UPDATE runs SET learner_level = ? WHERE run_id = ?",
            (learner_level, run_id),
        )
        self._conn.commit()
        self._recalc_domain_metrics(session_log.user_name, domain)
        return run_id

    # ------------------------------------------------------------------ #
    # Queries — user history
    # ------------------------------------------------------------------ #
    def clear_user_history(self, user_name: str) -> dict[str, int]:
        """Delete runs, actions, mastery and domain metrics for one profile."""
        if not self._conn:
            return {"runs_deleted": 0, "actions_deleted": 0}

        actions = self._conn.execute(
            """
            SELECT COUNT(*) AS n FROM actions a
            JOIN runs r ON a.run_id = r.run_id
            WHERE r.user_name = ?
            """,
            (user_name,),
        ).fetchone()
        runs = self._conn.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE user_name = ?", (user_name,)
        ).fetchone()

        self._conn.execute("DELETE FROM runs WHERE user_name = ?", (user_name,))
        self._conn.execute("DELETE FROM domain_metrics WHERE user_name = ?", (user_name,))
        self._conn.execute("DELETE FROM mastery WHERE user_name = ?", (user_name,))
        self._conn.commit()
        return {
            "runs_deleted": int(runs["n"] if runs else 0),
            "actions_deleted": int(actions["n"] if actions else 0),
        }

    def delete_user(self, user_name: str) -> dict[str, Any]:
        """Delete a profile and every row that belongs to it."""
        if not self._conn:
            return {
                "runs_deleted": 0,
                "actions_deleted": 0,
                "profile_deleted": False,
            }

        counts = self.clear_user_history(user_name)
        cursor = self._conn.execute("DELETE FROM users WHERE name = ?", (user_name,))
        self._conn.commit()
        counts["profile_deleted"] = cursor.rowcount > 0
        return counts

    def get_run_count(self, user_name: str) -> int:
        if not self._conn:
            return 0
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE user_name = ? AND status = 'completed'",
            (user_name,),
        ).fetchone()
        return row["n"] if row else 0

    def get_last_run(self, user_name: str) -> Optional[dict[str, Any]]:
        if not self._conn:
            return None
        row = self._conn.execute(
            """
            SELECT run_id, scenario_id, score, grade, completed_at,
                   domain, learner_level, next_scenario_reason
            FROM runs WHERE user_name = ? AND status = 'completed'
            ORDER BY completed_at DESC, run_id DESC LIMIT 1
            """,
            (user_name,),
        ).fetchone()
        if not row:
            return None
        return dict(row)

    def set_next_scenario_reason(self, run_id: int, reason: str) -> None:
        """Store the adaptive recommendation made right after a run (P6)."""
        if not self._conn:
            return
        self._conn.execute(
            "UPDATE runs SET next_scenario_reason = ? WHERE run_id = ?",
            (reason, run_id),
        )
        self._conn.commit()

    def get_domain_performance(
        self, user_name: str, domain: Optional[str] = None
    ) -> dict[str, Any] | list[dict[str, Any]]:
        """Per-domain performance summary.

        Returns one dict when `domain` is given, otherwise a list ordered from
        weakest to strongest.
        """
        if not self._conn:
            return {} if domain else []
        if domain:
            row = self._conn.execute(
                """
                SELECT domain, avg_score, weakest_technique, total_runs, last_practiced
                FROM domain_metrics WHERE user_name = ? AND domain = ?
                """,
                (user_name, domain),
            ).fetchone()
            return dict(row) if row else {}
        rows = self._conn.execute(
            """
            SELECT domain, avg_score, weakest_technique, total_runs, last_practiced
            FROM domain_metrics WHERE user_name = ?
            ORDER BY avg_score ASC
            """,
            (user_name,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_weak_techniques(self, user_name: str, domain: str) -> list[str]:
        """Return the user's weakest canonical technique keys within ONE domain."""
        if not self._conn:
            return []
        rows = self._conn.execute(
            f"""
            SELECT m.technique
            FROM mastery m
            WHERE m.user_name = ?
              AND m.level != 'Expert' AND m.level != 'Proficient'
              AND EXISTS (
                  SELECT 1 FROM actions a
                  JOIN runs r ON a.run_id = r.run_id
                  WHERE r.user_name = m.user_name AND r.domain = ?
                    AND r.status = 'completed'
                    AND a.technique_key = m.technique
              )
            ORDER BY
              {_LEVEL_RANK_SQL} ASC,
              m.avg_score ASC, m.last_practiced ASC
            LIMIT 10
            """,
            (user_name, domain),
        ).fetchall()
        return [r["technique"] for r in rows]

    def get_mastery(self, user_name: str, domain: Optional[str] = None) -> list[dict[str, Any]]:
        """Return mastery rows for the user, optionally filtered to techniques
        practiced inside one domain."""
        if not self._conn:
            return []
        if domain:
            rows = self._conn.execute(
                f"""
                SELECT m.technique, m.technique_name, m.attempts, m.avg_score,
                       m.best_score, m.last_practiced, m.level
                FROM mastery m
                WHERE m.user_name = ?
                  AND EXISTS (
                      SELECT 1 FROM actions a
                      JOIN runs r ON a.run_id = r.run_id
                      WHERE r.user_name = m.user_name AND r.domain = ?
                        AND r.status = 'completed'
                        AND a.technique_key = m.technique
                  )
                ORDER BY {_LEVEL_RANK_SQL} ASC, m.avg_score ASC
                """,
                (user_name, domain),
            ).fetchall()
        else:
            rows = self._conn.execute(
                f"""
                SELECT technique, technique_name, attempts, avg_score, best_score,
                       last_practiced, level
                FROM mastery WHERE user_name = ?
                ORDER BY {_LEVEL_RANK_SQL.replace('m.', '')} ASC, avg_score ASC
                """,
                (user_name,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_learner_level(self, user_name: str) -> str:
        """Overall learner level: grade band of the user's average run score."""
        if not self._conn:
            return "Unpracticed"
        row = self._conn.execute(
            "SELECT AVG(score) AS avg_score FROM runs "
            "WHERE user_name = ? AND status = 'completed'",
            (user_name,),
        ).fetchone()
        if not row or row["avg_score"] is None:
            return "Unpracticed"
        return _grade_from_score(int(row["avg_score"]))

    def get_practice_streak(self, user_name: str) -> int:
        """Consecutive practice days ending today (or yesterday if not yet
        practiced today), derived from runs.started_at."""
        if not self._conn:
            return 0
        rows = self._conn.execute(
            "SELECT DISTINCT date(started_at) AS d FROM runs "
            "WHERE user_name = ? AND status = 'completed' ORDER BY d DESC",
            (user_name,),
        ).fetchall()
        if not rows:
            return 0
        from datetime import date, timedelta

        days = sorted(date.fromisoformat(r["d"]) for r in rows)
        today = date.today()
        if today not in days:
            today -= timedelta(days=1)  # streak survives an un-practiced today
        streak = 0
        for d in reversed(days):
            if d == today:
                streak += 1
                today -= timedelta(days=1)
            elif d < today:
                break
        return streak

    def get_recent_scenarios(self, user_name: str, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent completed scenario attempts with scores."""
        if not self._conn:
            return []
        rows = self._conn.execute(
            """
            SELECT run_id, scenario_id, score, grade, completed_at, domain
            FROM runs WHERE user_name = ? AND status = 'completed'
            ORDER BY completed_at DESC, run_id DESC LIMIT ?
            """,
            (user_name, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_runs(
        self,
        user_name: str,
        *,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Paginated run history (all statuses unless `status` is given)."""
        if not self._conn:
            return {"items": [], "total": 0, "limit": limit, "offset": offset}

        where = "user_name = ?"
        params: list[Any] = [user_name]
        if status:
            where += " AND status = ?"
            params.append(status)

        total_row = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM runs WHERE {where}", params
        ).fetchone()
        total = int(total_row["n"] if total_row else 0)

        rows = self._conn.execute(
            f"""
            SELECT run_id, scenario_id, role_used, score, grade, started_at,
                   completed_at, domain, difficulty, status, learner_level,
                   next_scenario_reason, updated_at
            FROM runs
            WHERE {where}
            ORDER BY COALESCE(completed_at, updated_at, started_at) DESC, run_id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, max(1, min(int(limit), 100)), max(0, int(offset))],
        ).fetchall()
        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    # ------------------------------------------------------------------ #
    # Internal — student model + recalculation
    # ------------------------------------------------------------------ #
    def _update_mastery(self, user_name: str) -> None:
        """Rebuild per-technique mastery (see module-level `_rebuild_mastery`)."""
        if not self._conn:
            return
        _rebuild_mastery(self._conn, user_name)

    def _recalc_domain_metrics(self, user_name: str, domain: str) -> None:
        """Refresh one domain's materialized metrics."""
        if not self._conn:
            return
        _recalc_domain_metrics(self._conn, user_name, domain)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "SessionDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["SessionDB", "DB_PATH", "DEFAULT_DB_PATH", "RUN_STATUSES"]
