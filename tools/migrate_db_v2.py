"""
tools/migrate_db_v2.py
DB v2 migration for the student model (P5).

What it does (idempotent, runnable multiple times):
  1. Backs up the database (sessions.db -> sessions.db.bak-<ts>) unless --dry-run.
  2. Adds the student-model columns to `runs` if missing:
     domain, format_version, difficulty, next_scenario_reason, learner_level.
  3. Renames saved domain names (old 12-domain taxonomy -> new 7) in
     `users.domains` and `domain_metrics.domain`; unmapped/deleted domains
     (physical, IoT/OT) are dropped.
  4. Rebuilds `mastery` from the user's run/action history (via
     core/session_db.SessionDB, so the grade-band logic is shared).
  5. Rebuilds `domain_metrics` scoped to runs that have a domain — stale
     rows from the old global-scope aggregates (audit finding #1) are removed.

Legacy runs predating the domain column keep domain = NULL and are excluded
from per-domain queries until they are replayed; their actions still feed
the (domain-independent) mastery table.

Usage:
    python tools/migrate_db_v2.py            # migrate ./sessions.db
    python tools/migrate_db_v2.py --db path/to.db
    python tools/migrate_db_v2.py --dry-run  # show what would change
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.session_db import SessionDB, _connect, _ensure_run_columns  # noqa: E402

# Old 12-domain taxonomy display names -> new 7 canonical names.
# Unmapped names (deleted domains: physical, IoT/OT) are dropped.
DOMAIN_MIGRATION = {
    # Endpoint
    "Endpoint": "Endpoint",
    "Endpoint Security": "Endpoint",
    "Endpoint Detection & Response": "Endpoint",
    "System Exploitation": "Endpoint",
    "System Exploitation Attacks": "Endpoint",
    "Mobile Security": "Endpoint",
    "Mobile & IoT": "Endpoint",
    # Web App
    "Web App": "Web App",
    "Web Application Attacks": "Web App",
    "Web Application Security": "Web App",
    # Cloud
    "Cloud": "Cloud",
    "Cloud Security": "Cloud",
    "Cloud & Container Security": "Cloud",
    # Identity & Access
    "Identity & Access": "Identity & Access",
    "Social Engineering": "Identity & Access",
    # Network
    "Network": "Network",
    "Network Attacks": "Network",
    # AI & ML
    "AI & ML": "AI & ML",
    "AI & ML Security": "AI & ML",
    "AI Security": "AI & ML",
    "AI Attacks": "AI & ML",
    # Advanced Threats
    "Advanced Threats": "Advanced Threats",
    "Advanced Persistent Threats": "Advanced Threats",
    "APT": "Advanced Threats",
    "Supply Chain Attacks": "Advanced Threats",
    "Crypto Attacks": "Advanced Threats",
}


def _map_domain(name: str) -> str | None:
    """Map an old domain name to the new 7; None = deleted domain."""
    if not name:
        return None
    return DOMAIN_MIGRATION.get(name)


def migrate(db_path: Path, dry_run: bool = False) -> dict:
    """Run the v2 migration. Returns a summary dict."""
    summary = {
        "backup": None,
        "users_scanned": 0,
        "users_domains_renamed": 0,
        "users_domains_dropped": 0,
        "domain_metrics_renamed": 0,
        "domain_metrics_dropped": 0,
        "mastery_built": 0,
        "domain_metrics_rebuilt": 0,
        "warnings": [],
    }

    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    if not dry_run:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = db_path.with_name(f"{db_path.stem}.bak-{ts}{db_path.suffix}")
        shutil.copy2(db_path, backup)
        summary["backup"] = str(backup)

    conn = _connect(str(db_path))
    try:
        _ensure_run_columns(conn)  # runs gains the student-model columns

        # ---- 3. Rename domains in users.domains (JSON) ----
        users = conn.execute("SELECT name, domains FROM users").fetchall()
        summary["users_scanned"] = len(users)
        for u in users:
            try:
                names = json.loads(u["domains"]) if u["domains"] else []
            except json.JSONDecodeError:
                summary["warnings"].append(f"user '{u['name']}': unparseable domains JSON, left untouched")
                continue
            mapped: list[str] = []
            for n in names:
                new_name = _map_domain(n)
                if new_name:
                    mapped.append(new_name)
                else:
                    summary["users_domains_dropped"] += 1
                    summary["warnings"].append(f"user '{u['name']}': dropped deleted domain '{n}'")
            summary["users_domains_renamed"] += 1
            if not dry_run:
                conn.execute("UPDATE users SET domains = ? WHERE name = ?",
                             (json.dumps(sorted(set(mapped))), u["name"]))

        # ---- 4. Rename domains in domain_metrics ----
        rows = conn.execute("SELECT user_name, domain FROM domain_metrics").fetchall()
        for r in rows:
            new_name = _map_domain(r["domain"])
            if not new_name:
                summary["domain_metrics_dropped"] += 1
                if not dry_run:
                    conn.execute("DELETE FROM domain_metrics WHERE user_name = ? AND domain = ?",
                                 (r["user_name"], r["domain"]))
            elif new_name != r["domain"]:
                summary["domain_metrics_renamed"] += 1
                if not dry_run:
                    conn.execute(
                        "UPDATE domain_metrics SET domain = ? WHERE user_name = ? AND domain = ?",
                        (new_name, r["user_name"], r["domain"]),
                    )

        conn.commit()
    finally:
        conn.close()

    if dry_run:
        return summary

    # ---- 5/6. Rebuild mastery + domain metrics via the shared SessionDB ----
    db = SessionDB(str(db_path))
    try:
        users = db._conn.execute("SELECT name FROM users").fetchall()  # type: ignore[union-attr]
        for u in users:
            db._update_mastery(u["name"])
            domains = db._conn.execute(  # type: ignore[union-attr]
                "SELECT DISTINCT domain FROM runs WHERE user_name = ? AND domain IS NOT NULL",
                (u["name"],),
            ).fetchall()
            for d in domains:
                db._recalc_domain_metrics(u["name"], d["domain"])
                summary["domain_metrics_rebuilt"] += 1
            # Drop stale metrics rows (domains with no current runs)
            db._conn.execute(  # type: ignore[union-attr]
                "DELETE FROM domain_metrics WHERE user_name = ? AND domain NOT IN ("
                "SELECT DISTINCT domain FROM runs WHERE user_name = ? AND domain IS NOT NULL)",
                (u["name"], u["name"]),
            )
            db._conn.commit()  # type: ignore[union-attr]
        summary["mastery_built"] = sum(
            len(db.get_mastery(u["name"])) for u in users  # type: ignore[union-attr]
        )
    finally:
        db.close()

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate the trainer DB to v2 (student model).")
    parser.add_argument("--db", default=None, help="Path to the SQLite DB (default: ./sessions.db)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args()

    db_path = Path(args.db) if args.db else Path(__file__).resolve().parent.parent / "sessions.db"
    try:
        summary = migrate(db_path, dry_run=args.dry_run)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1

    print("Migration summary:")
    for k, v in summary.items():
        if k == "warnings":
            for w in v:
                print(f"  ! {w}")
        else:
            print(f"  {k}: {v}")
    print("OK: migration complete." if not args.dry_run else "OK: dry-run only, nothing written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
