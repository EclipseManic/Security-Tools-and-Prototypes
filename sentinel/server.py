"""Flask application: REST API plus the single-page interface."""

from __future__ import annotations

import hmac
import os
import secrets
import shutil
import socket
import threading
import time
from datetime import datetime, timedelta

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from . import analysis, baseline, config, exports, maintenance, management, storage, triage
from .collector import CollectionError, Collector
from .management import ManagementError

MAX_BODY_BYTES = 1024 * 1024
LOGIN_ATTEMPT_LIMIT = 8
LOGIN_LOCKOUT_SECONDS = 60

CSRF_HEADER = "X-Sentinel-Token"
HELP_SECTIONS = [
    {
        "id": "services",
        "title": "Windows services and the Service Control Manager",
        "body": [
            "A Windows service is a background program managed by Windows. Services can start before a user "
            "signs in, run continuously, and operate under powerful accounts. The Service Control Manager (SCM), "
            "implemented by services.exe, keeps the service database under "
            "HKLM\\SYSTEM\\CurrentControlSet\\Services and starts, stops and tracks services.",
            "Own-process services run in their own executable. Shared-process services usually run inside "
            "svchost.exe and may load a ServiceDll. LocalSystem has very high local privilege; LocalService and "
            "NetworkService have fewer rights. Attackers abuse services for persistence, privilege escalation, "
            "execution and defence evasion.",
        ],
    },
    {
        "id": "unknowns",
        "title": "Why the tool reports unknown data instead of guessing",
        "body": [
            "A non-elevated process cannot read the binary path or account of some protected services. Earlier "
            "versions treated those blanks as evidence: a blank path looked like a non-standard location, and a "
            "blank account was rewritten as LocalSystem. That produced confident findings built on missing data, "
            "and false 'account changed' results in baseline comparisons.",
            "Every finding here separates 'checked and clean' from 'could not check'. Data gaps are listed as "
            "notes with zero points and the interface tells you to re-run elevated for the full picture.",
        ],
    },
    {
        "id": "scoring",
        "title": "Threat and reliability scoring",
        "body": [
            "Threat indicators: executable in a user-writable or temporary location (+40), outside Windows and "
            "Program Files (+15), missing binary (+20), unquoted path with spaces (+20), unsigned (+15), invalid "
            "signature (+30), script or proxy-execution host (+25), SYSTEM paired with a non-standard path (+15), "
            "automatic startup in a user-writable location (+10), Windows component impersonation (+35), created "
            "inside the event window (+10), startup type changed (+5).",
            "Reliability is scored separately: unexpected stops (10 each, capped at 40) and other failure or "
            "timeout events (5 each, capped at 30). Breaks are not maliciousness.",
            "Levels: Critical 75-100, High 50-74, Medium 25-49, Low 1-24, Informational 0. A score prioritises "
            "investigation; it is not a malware verdict.",
        ],
    },
    {
        "id": "localisation",
        "title": "Event 7036 on non-English Windows",
        "body": [
            "Event 7036 stores the new service state as a localised word rather than a number. ServiceSentinel "
            "learns this host's wording by matching the most recent 7036 word for each service against its "
            "current state, then reuses the mapping for older events.",
            "An unrecognised word is shown verbatim instead of being guessed, so it can be reported rather than "
            "silently degrading the timeline, run counts and runtime estimates.",
        ],
    },
    {
        "id": "baseline",
        "title": "Baselines and change detection",
        "body": [
            "A baseline is a trusted snapshot of service name, display name, command line, executable path, "
            "startup mode, account and service type. Create one only when the computer is believed to be clean.",
            "Comparison reports created, deleted and modified services. Values that were unreadable in either "
            "snapshot are reported as unverifiable instead of as changes, and version-stamped name rotations "
            "(GoogleUpdaterService159 becoming 162, for example) are classified as Low-severity replacements so "
            "routine application updates do not drown real findings.",
        ],
    },
    {
        "id": "triage",
        "title": "Triage decisions",
        "body": [
            "Decisions are Investigate, Monitor, Allow, Contain, FalsePositive and Resolved. Each record stores a "
            "live evidence snapshot: threat and reliability scores, category, account, executable path, signer, "
            "signature and SHA-256, plus analyst and notes.",
            "Records are append-only, so the history of a decision is preserved. Choosing Contain records intent "
            "only; it never changes a service. Use the Management page for that.",
        ],
    },
    {
        "id": "timeline",
        "title": "Events, timestamps and runtime",
        "body": [
            "The timeline reads Service Control Manager events from the System log: 7035 control requests, 7036 "
            "state changes, 7040 startup-type changes, 7045 creation, 7031/7034 unexpected termination, and the "
            "7000-series failure and timeout events.",
            "For a running service the runtime prefers the latest SCM start event and otherwise falls back to the "
            "host process start time, which is labelled in the interface. Shared svchost services can therefore "
            "show an estimate rather than the exact service start time.",
        ],
    },
    {
        "id": "management",
        "title": "Management safety",
        "body": [
            "Every action requires the exact service name, case-sensitively, and disruptive actions first write a "
            "configuration backup to the evidence folder. Dependent services are listed before you confirm.",
            "Core operating-system services are refused outright. Results are reported per step: a failed stop or "
            "a non-zero sc.exe exit code is shown as a failure, never as success. Containment can be reversed from "
            "the backup list on the same page.",
        ],
    },
    {
        "id": "workflow",
        "title": "Suggested investigation workflow",
        "body": [
            "1. Launch elevated for complete metadata. 2. Review the inventory and categories. 3. Create a "
            "baseline while the host is trusted. 4. Hunt over a relevant window. 5. Open findings and read every "
            "reason. 6. Check the timeline and baseline comparison. 7. Record a triage decision. 8. Export the "
            "report and preserve evidence. 9. Only then consider management, after validating business impact.",
        ],
    },
    {
        "id": "limitations",
        "title": "Limitations",
        "body": [
            "Scores are heuristics, not detections. ServiceDll values and full executable ACLs are not audited. "
            "There is no VirusTotal or other external reputation lookup, by design: nothing leaves the host. Event "
            "visibility depends on retention, permissions and audit policy. Only the local computer is inspected.",
        ],
    },
]


def create_app(collector: Collector | None = None, prune_on_start: bool = True) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        JSON_SORT_KEYS=False,
        MAX_CONTENT_LENGTH=MAX_BODY_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )
    app.secret_key = config.session_secret()
    collector = collector or Collector()
    app.extensions["collector"] = collector
    app.extensions["token"] = secrets.token_urlsafe(24)
    attempts = {"count": 0, "until": 0.0}
    attempts_lock = threading.Lock()

    def token() -> str:
        return app.extensions["token"]

    def auth_enabled() -> bool:
        return bool(config.auth_password())

    def authenticated() -> bool:
        return not auth_enabled() or bool(session.get("auth"))

    def error(message: str, status: int = 400, **extra):
        payload = {"ok": False, "error": message}
        payload.update(extra)
        return jsonify(payload), status

    def page_context(**extra) -> dict:
        context = {
            "app_name": config.APP_NAME,
            "version": config.VERSION,
            "auth_enabled": auth_enabled(),
        }
        context.update(extra)
        return context

    @app.before_request
    def guard():
        path = request.path
        if path == "/api/health" or path.startswith("/static/") or path == "/login":
            return None
        if not authenticated():
            if path.startswith("/api/"):
                return error("Authentication required.", 401)
            return redirect(url_for("login_page"))
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return None
        supplied = request.headers.get(CSRF_HEADER)
        if not supplied and request.is_json:
            body = request.get_json(silent=True) or {}
            supplied = body.get("token")
        if supplied != token():
            return error("Invalid or missing request token. Reload the page and try again.", 403)
        return None

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'",
        )
        # The console page carries a per-session request token; never cache it.
        if not request.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    @app.get("/login")
    def login_page():
        if not auth_enabled() or authenticated():
            return redirect(url_for("index"))
        return render_template("login.html", **page_context(error=None))

    @app.post("/login")
    def login_submit():
        if not auth_enabled():
            return redirect(url_for("index"))
        now = time.monotonic()
        with attempts_lock:
            if attempts["until"] > now:
                wait = int(attempts["until"] - now) + 1
                return (
                    render_template(
                        "login.html",
                        **page_context(error=f"Too many failed attempts. Try again in {wait}s."),
                    ),
                    429,
                )
        supplied = request.form.get("password", "")
        expected = config.auth_password() or ""
        if hmac.compare_digest(supplied, expected):
            with attempts_lock:
                attempts["count"] = 0
                attempts["until"] = 0.0
            session.clear()
            session["auth"] = True
            session.permanent = True
            storage.log("INFO", f"Console login from {request.remote_addr}")
            return redirect(url_for("index"))
        with attempts_lock:
            attempts["count"] += 1
            if attempts["count"] >= LOGIN_ATTEMPT_LIMIT:
                attempts["count"] = 0
                attempts["until"] = now + LOGIN_LOCKOUT_SECONDS
        storage.log("WARN", f"Failed console login from {request.remote_addr}")
        return render_template("login.html", **page_context(error="Invalid password.")), 401

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login_page"))

    # ------------------------------------------------------------------ #
    # Pages
    # ------------------------------------------------------------------ #
    @app.get("/")
    def index():
        return render_template("index.html", **page_context(token=token()))

    @app.get("/api/status")
    def status():
        info = collector.status()
        info.update(
            {
                "ok": True,
                "help_sections": [{"id": item["id"], "title": item["title"]} for item in HELP_SECTIONS],
                "actions": management.action_catalog(),
                "decisions": list(triage.DECISIONS),
                "triage_counts": triage.counts(),
                "log_tail": storage.tail_log(40),
                "baseline": _baseline_summary(),
            }
        )
        return jsonify(info)

    @app.get("/api/help")
    def help_content():
        return jsonify({"ok": True, "sections": HELP_SECTIONS})

    # ------------------------------------------------------------------ #
    # Inventory
    # ------------------------------------------------------------------ #
    @app.get("/api/inventory")
    def inventory():
        evidence = request.args.get("evidence", "0") in {"1", "true", "yes"}
        refresh = request.args.get("refresh", "0") in {"1", "true", "yes"}
        try:
            payload = collector.inventory(evidence=evidence, refresh=refresh)
        except CollectionError as exc:
            return error(str(exc), 503)
        return jsonify({"ok": True, **payload})

    @app.get("/api/service/<path:name>")
    def service_detail(name: str):
        try:
            detail = collector.service_detail(name)
        except KeyError:
            return error(f"Service '{name}' was not found.", 404)
        except CollectionError as exc:
            return error(str(exc), 503)
        return jsonify({"ok": True, **detail})

    # ------------------------------------------------------------------ #
    # Hunt and timeline
    # ------------------------------------------------------------------ #
    @app.get("/api/hunt")
    def hunt():
        hours = _read_hours(default=168)
        refresh = request.args.get("refresh", "0") in {"1", "true", "yes"}
        try:
            payload = collector.assessments(hours=hours, refresh=refresh)
        except CollectionError as exc:
            return error(str(exc), 503)
        return jsonify({"ok": True, **payload})

    @app.get("/api/timeline")
    def timeline():
        hours = _read_hours(default=168)
        name = (request.args.get("name") or "").strip()
        bucket = request.args.get("bucket") or "day"
        refresh = request.args.get("refresh", "0") in {"1", "true", "yes"}
        try:
            payload = collector.timeline(hours=hours, name=name, bucket=bucket, refresh=refresh)
        except CollectionError as exc:
            return error(str(exc), 503)
        return jsonify({"ok": True, **payload})

    # ------------------------------------------------------------------ #
    # Baseline
    # ------------------------------------------------------------------ #
    @app.get("/api/baseline")
    def baseline_view():
        document = baseline.load_baseline()
        if not document:
            return jsonify(
                {
                    "ok": True,
                    "exists": False,
                    "changes": [],
                    "unverifiable": [],
                    "summary": {},
                    "baseline": None,
                    "history": baseline.history_files(),
                    "message": "No baseline exists yet. Create one when this computer is known to be clean.",
                }
            )
        try:
            current = collector.inventory(evidence=False)["services"]
        except CollectionError as exc:
            return error(str(exc), 503)
        result = baseline.diff(document, current)
        return jsonify({"ok": True, "exists": True, "history": baseline.history_files(), **result})

    @app.post("/api/baseline")
    def baseline_create():
        payload = request.get_json(silent=True) or {}
        if str(payload.get("confirm", "")).strip().upper() != "BASELINE":
            return error("Type BASELINE to confirm capturing a new trusted snapshot.")
        try:
            inventory_payload = collector.inventory(evidence=False, refresh=True)
        except CollectionError as exc:
            return error(str(exc), 503)
        created = baseline.create_baseline(
            inventory_payload["services"],
            collector.status()["hostname"],
            analysis.iso_now(),
        )
        storage.log("ACTION", f"Baseline created: {created['path']}")
        document = created["document"]
        return jsonify(
            {
                "ok": True,
                "created_at": document["created_at"],
                "services": len(document["services"]),
                "path": created["path"],
                "history": created["history"],
            }
        )

    # ------------------------------------------------------------------ #
    # Triage
    # ------------------------------------------------------------------ #
    @app.get("/api/triage")
    def triage_list():
        return jsonify(
            {
                "ok": True,
                "records": triage.list_all(),
                "counts": triage.counts(),
                "decisions": list(triage.DECISIONS),
            }
        )

    @app.post("/api/triage")
    def triage_create():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("service", "")).strip()
        decision = str(payload.get("decision", "")).strip()
        if not name:
            return error("Service name is required.")
        try:
            detail = collector.service_detail(name)
        except KeyError:
            return error(f"Service '{name}' was not found, so no evidence snapshot could be attached.", 404)
        except CollectionError as exc:
            return error(str(exc), 503)
        try:
            entry = triage.record(
                service_name=detail["service"]["name"],
                decision=decision,
                assessment=detail["assessment"],
                analyst=str(payload.get("analyst", "")),
                notes=str(payload.get("notes", "")),
                hostname=collector.status()["hostname"],
            )
        except ValueError as exc:
            return error(str(exc))
        return jsonify({"ok": True, "record": entry})

    # ------------------------------------------------------------------ #
    # Exports
    # ------------------------------------------------------------------ #
    @app.post("/api/export")
    def export_report():
        payload = request.get_json(silent=True) or {}
        report = str(payload.get("report", "")).strip().lower()
        fmt = str(payload.get("format", "Csv")).strip()
        hours = _read_hours(default=168, raw=payload.get("hours"))

        try:
            if report == "inventory":
                rows = collector.inventory(evidence=True)["services"]
            elif report == "assessment":
                rows = collector.assessments(hours=hours)["findings"]
            elif report == "timeline":
                name = str(payload.get("service") or "").strip()
                rows = collector.timeline(hours=hours, name=name)["events"]
            elif report == "baseline":
                document = baseline.load_baseline()
                if not document:
                    return error("No baseline exists to compare against.")
                rows = baseline.diff(document, collector.inventory(evidence=False)["services"])["changes"]
            elif report == "triage":
                rows = triage.list_all()
            else:
                return error(f"Unknown report '{report}'.")
        except CollectionError as exc:
            return error(str(exc), 503)

        if not rows:
            return error("There is nothing to export for that selection.")

        result = exports.export(report, rows, fmt)
        return jsonify({"ok": True, **result, "url": f"/api/download/{result['file']}"})

    @app.get("/api/download/<path:filename>")
    def download(filename: str):
        if "/" in filename or "\\" in filename or ".." in filename:
            return error("Invalid file name.", 403)
        target = config.export_dir() / filename
        if not target.exists():
            return error("File not found.", 404)
        return send_from_directory(config.export_dir(), filename, as_attachment=True)

    # ------------------------------------------------------------------ #
    # Management
    # ------------------------------------------------------------------ #
    @app.get("/api/manage")
    def manage_view():
        return jsonify(
            {
                "ok": True,
                "actions": management.action_catalog(),
                "descriptions": {item: management.describe(item) for item in management.ACTIONS},
                "startup_types": sorted(management.STARTUP_TYPES),
                "protected": sorted(management.PROTECTED_SERVICES),
                "backups": management.list_backups(),
                "admin": collector.status()["admin"],
            }
        )

    @app.get("/api/manage/preflight")
    def manage_preflight():
        name = (request.args.get("service") or "").strip()
        if not name:
            return error("Service name is required.")
        try:
            return jsonify({"ok": True, **management.preflight(collector, name)})
        except (ManagementError, CollectionError) as exc:
            return error(str(exc), 404)

    @app.post("/api/manage")
    def manage_action():
        payload = request.get_json(silent=True) or {}
        try:
            result = management.perform(
                collector,
                name=str(payload.get("service", "")),
                action=str(payload.get("action", "")),
                confirm=str(payload.get("confirm", "")),
                startup=str(payload.get("startup", "Manual")),
                force=bool(payload.get("force", False)),
                analyst=str(payload.get("analyst", "")),
            )
        except (ManagementError, CollectionError) as exc:
            return error(str(exc), 400)
        return jsonify({"ok": result["ok"], **result})

    @app.post("/api/manage/restore")
    def manage_restore():
        payload = request.get_json(silent=True) or {}
        try:
            result = management.restore(
                collector,
                backup_file=str(payload.get("file", "")),
                start_service=bool(payload.get("start", False)),
            )
        except (ManagementError, CollectionError) as exc:
            return error(str(exc), 400)
        return jsonify(result)

    # ------------------------------------------------------------------ #
    # Misc
    # ------------------------------------------------------------------ #
    @app.get("/api/log")
    def log_view():
        return jsonify({"ok": True, "lines": storage.tail_log(200), "file": str(config.log_file())})

    @app.get("/api/health")
    def health():
        """Unauthenticated liveness probe for monitoring and startups scripts."""
        checks = {
            "windows": config.IS_WINDOWS,
            "collector_script": config.PS_SCRIPT.exists(),
            "powershell": bool(shutil.which("powershell")) if config.IS_WINDOWS else False,
            "evidence_writable": os.access(str(config.data_root()), os.W_OK),
            "baseline": config.baseline_file().exists(),
        }
        healthy = all(checks[key] for key in ("windows", "collector_script", "evidence_writable"))
        payload = {
            "ok": True,
            "status": "ok" if healthy else "degraded",
            "version": config.VERSION,
            "hostname": socket.gethostname(),
            "auth_enabled": auth_enabled(),
            "checks": checks,
            "time": analysis.iso_now(),
        }
        return jsonify(payload), (200 if healthy else 503)

    @app.get("/api/maintenance")
    def maintenance_view():
        return jsonify(
            {
                "ok": True,
                "usage": maintenance.disk_usage(),
                "retention_days": config.retention_days(),
                "max_exports": config.max_export_files(),
                "cache_entries": len(collector._load_evidence_cache()),
                "baseline_history": len(baseline.history_files()),
            }
        )

    @app.post("/api/maintenance/prune")
    def maintenance_prune():
        result = maintenance.prune()
        collector.invalidate()
        return jsonify({"ok": True, **result})

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return error("Not found.", 404)
        return render_template("index.html", **page_context(token=token()))

    @app.errorhandler(500)
    def server_error(exc):  # pragma: no cover - exercised by manual fault injection
        app.logger.exception("Unhandled error: %s", exc)
        if request.path.startswith("/api/"):
            return error("Internal error. See the application log for details.", 500)
        return render_template("index.html", **page_context(token=token())), 500

    if prune_on_start:
        try:
            maintenance.prune()
        except Exception as exc:  # noqa: BLE001 - retention must never block startup
            storage.log("WARN", f"Startup retention pass failed: {exc}")

    return app


def _read_hours(default: int = 168, raw=None) -> int:
    value = raw
    if value is None:
        value = request.args.get("hours")
    try:
        hours = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(hours, 24 * 90))


def _baseline_summary() -> dict | None:
    document = baseline.load_baseline()
    if not document:
        return None
    created = analysis.parse_time(document.get("created_at"))
    return {
        "created_at": document.get("created_at"),
        "hostname": document.get("hostname"),
        "services": len(document.get("services") or []),
        "age": f"{(datetime.now(created.tzinfo) - created).days} days" if created else "unknown",
    }
