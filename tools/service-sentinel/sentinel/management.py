"""Guarded service management.

Production safety properties:

* exact, case-sensitive name confirmation;
* an elevation check before any state change;
* a configuration backup before disruptive actions, built from raw service
  facts (fast and independent of the full inventory);
* dependent-service visibility;
* core operating-system services refused outright;
* per-step results with real ``sc.exe`` exit codes;
* automatic rollback if containment only partially succeeds;
* post-delete verification that the service is gone.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

from . import config, paths, storage

ACTIONS = ("start", "stop", "restart", "setstartup", "contain", "delete")
DISRUPTIVE = {"stop", "restart", "contain", "delete"}

STARTUP_TYPES = {"Automatic": "Automatic", "Manual": "Manual", "Disabled": "Disabled"}
_STARTUP_FROM_CIM = {"Auto": "Automatic", "Manual": "Manual", "Disabled": "Disabled"}

# Services whose removal or stoppage breaks the operating-system session.
PROTECTED_SERVICES = {
    "rpcss",
    "dcomlaunch",
    "eventlog",
    "lsm",
    "samss",
    "winmgmt",
    "plugplay",
    "pow",
    "system",
    "services",
    "appinfo",
    "seclogon",
}


class ManagementError(RuntimeError):
    pass


def _require_admin(collector) -> None:
    if not collector.status().get("admin"):
        raise ManagementError(
            "Service management requires an elevated console. Restart ServiceSentinel "
            "from a prompt running as Administrator."
        )


def preflight(collector, name: str) -> dict:
    payload = collector.run_action({"name": name, "action": "preflight"}, timeout=90)
    if not payload.get("found"):
        raise ManagementError(f"Service '{name}' was not found.")
    payload["protected"] = str(name).casefold() in PROTECTED_SERVICES
    payload["admin"] = bool(collector.status().get("admin"))
    payload.setdefault("dependents", [])
    return payload


def _raw_service(collector, name: str) -> dict:
    """Facts for one service without running a full inventory with hashing."""
    for raw in collector.raw_services(refresh=True):
        if str(raw.get("name") or "").casefold() == name.casefold():
            return raw
    raise ManagementError(f"Service '{name}' was not found while preparing the backup.")


def backup(collector, name: str) -> dict:
    raw = _raw_service(collector, name)
    exe_path = paths.normalize_service_path(raw.get("command_line"))
    evidence = {}
    if exe_path:
        try:
            evidence = collector.evidence([exe_path]).get(exe_path.casefold(), {})
        except Exception as exc:  # noqa: BLE001 - a backup must still be written
            storage.log("WARN", f"Evidence unavailable for backup of {name}: {exc}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in name)
    path = config.containment_dir() / f"containment_{safe}_{stamp}.json"
    document = {
        "hostname": socket.gethostname(),
        "captured_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "name": raw.get("name"),
        "display_name": raw.get("display_name"),
        "state": raw.get("state"),
        "start_mode": raw.get("start_mode"),
        "account": raw.get("start_name"),
        "command_line": raw.get("command_line"),
        "exe_path": exe_path,
        "sha256": evidence.get("sha256"),
        "signature": evidence.get("signature"),
    }
    storage.write_json(path, document)
    storage.log("ACTION", f"Configuration backup written to {path}")
    return {"file": path.name, "path": str(path), "document": document}


def _verify_deleted(collector, name: str) -> bool:
    try:
        return not any(
            str(raw.get("name") or "").casefold() == name.casefold()
            for raw in collector.raw_services(refresh=True)
        )
    except Exception:  # noqa: BLE001 - verification is best effort
        return False


def perform(
    collector,
    name: str,
    action: str,
    confirm: str,
    startup: str | None = None,
    force: bool = False,
    analyst: str = "",
) -> dict:
    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise ManagementError(f"Unsupported action '{action}'.")
    if not name or not name.strip():
        raise ManagementError("A service name is required.")
    if confirm != name:
        raise ManagementError(
            "Confirmation did not match. Type the exact service name (case-sensitive) to proceed."
        )
    if action in DISRUPTIVE and name.casefold() in PROTECTED_SERVICES:
        raise ManagementError(
            f"'{name}' is a core Windows service. ServiceSentinel refuses to stop, disable or delete it."
        )

    _require_admin(collector)

    startup_type = STARTUP_TYPES.get(str(startup or ""), "Manual")
    result = {
        "service": name,
        "action": action,
        "analyst": analyst,
        "backup": None,
        "steps": [],
        "ok": False,
        "rolled_back": False,
    }

    prepared = None
    if action in {"contain", "delete"}:
        result["backup"] = backup(collector, name)
        prepared = result["backup"]["document"]

    payload = collector.run_action(
        {
            "name": name,
            "action": action,
            "startup": startup_type,
            "force": bool(force),
        }
    )
    steps = list(payload.get("steps") or [])
    result["dependents"] = payload.get("dependents") or []

    if action == "contain" and prepared:
        steps, rolled_back = _rollback_contain(collector, name, prepared, steps)
        result["rolled_back"] = rolled_back

    if action == "delete":
        if any(item.get("step") == "delete" and item.get("ok") for item in steps):
            gone = _verify_deleted(collector, name)
            steps.append(
                {
                    "step": "verify",
                    "ok": gone,
                    "message": "Service is no longer present." if gone else
                    "sc.exe reported success but the service is still registered.",
                }
            )
        if prepared and not all(item.get("ok") for item in steps):
            steps.append(
                {
                    "step": "recovery",
                    "ok": False,
                    "message": (
                        f"Deletion did not fully succeed. Configuration backup "
                        f"{result['backup']['file']} is available for manual recovery."
                    ),
                }
            )

    result["steps"] = steps
    result["ok"] = bool(steps) and all(item.get("ok") for item in steps)

    storage.log(
        "ACTION" if result["ok"] else "ERROR",
        f"Management {action} for {name} by {analyst or 'unattributed'}: "
        f"{'succeeded' if result['ok'] else 'FAILED'} "
        f"({'; '.join(str(step.get('message', '')) for step in steps)})",
    )
    collector.invalidate()
    return result


def _rollback_contain(collector, name: str, prepared: dict, steps: list[dict]) -> tuple[list[dict], bool]:
    """If containment only partly applied, put the service back the way it was.

    A half-contained service (stopped but still enabled, or disabled but still
    running) is worse than either end state because the operator may believe it
    is contained.
    """
    steps = list(steps)
    failed = [step for step in steps if not step.get("ok")]
    if not failed:
        return steps, False

    original_startup = _STARTUP_FROM_CIM.get(str(prepared.get("start_mode") or ""), "Manual")
    was_running = str(prepared.get("state") or "") == "Running"
    restore = collector.run_action(
        {
            "name": name,
            "action": "restore",
            "startup": original_startup,
            "start_service": was_running,
        }
    )
    restore_steps = list(restore.get("steps") or [])
    ok = bool(restore_steps) and all(step.get("ok") for step in restore_steps)
    steps.extend(restore_steps)
    steps.append(
        {
            "step": "rollback",
            "ok": ok,
            "message": (
                f"Containment failed, so the configuration was restored to {original_startup}"
                + (" and the service restarted." if was_running else ".")
                if ok
                else "Containment failed and the automatic rollback also failed. "
                f"Restore manually from {prepared.get('name')}'s backup file."
            ),
        }
    )
    storage.log(
        "WARN" if ok else "ERROR",
        f"Containment rollback for {name}: {'restored' if ok else 'FAILED'}",
    )
    return steps, ok


def list_backups() -> list[dict]:
    items = []
    for path in sorted(config.containment_dir().glob("containment_*.json"), reverse=True):
        document = storage.read_json(path) or {}
        items.append(
            {
                "file": path.name,
                "path": str(path),
                "service": document.get("name"),
                "captured_at": document.get("captured_at"),
                "start_mode": document.get("start_mode"),
                "state": document.get("state"),
                "exe_path": document.get("exe_path"),
                "sha256": document.get("sha256"),
            }
        )
    return items


def restore(collector, backup_file: str, start_service: bool = False) -> dict:
    """Undo a containment action using its saved configuration."""
    _require_admin(collector)
    name = str(backup_file or "").strip()
    if not name or "/" in name or "\\" in name or ".." in name:
        raise ManagementError("Invalid backup file name.")
    path = config.containment_dir() / name
    document = storage.read_json(path)
    if not document:
        raise ManagementError(f"Backup '{name}' could not be read.")
    service_name = str(document.get("name") or "")
    if not service_name:
        raise ManagementError("Backup does not contain a service name.")
    startup = _STARTUP_FROM_CIM.get(str(document.get("start_mode") or ""), "Manual")

    payload = collector.run_action(
        {
            "name": service_name,
            "action": "restore",
            "startup": startup,
            "start_service": bool(start_service),
        }
    )
    steps = list(payload.get("steps") or [])
    ok = bool(steps) and all(step.get("ok") for step in steps)
    storage.log(
        "ACTION" if ok else "ERROR",
        f"Restore from {name} for {service_name}: {'succeeded' if ok else 'FAILED'}",
    )
    collector.invalidate()
    return {"service": service_name, "ok": ok, "steps": steps, "startup": startup}


def action_catalog() -> list[dict]:
    return [
        {"action": "start", "label": "Start service", "danger": "info"},
        {"action": "stop", "label": "Stop service", "danger": "warn"},
        {"action": "restart", "label": "Restart service", "danger": "warn"},
        {"action": "setstartup", "label": "Change startup type", "danger": "warn"},
        {"action": "contain", "label": "Contain: back up, stop, disable", "danger": "high"},
        {"action": "delete", "label": "Delete service", "danger": "critical"},
    ]


def describe(action: str) -> str:
    return {
        "start": "Requests a start and reports the real result.",
        "stop": "Stops the service; dependents are listed first.",
        "restart": "Stops then starts the service.",
        "setstartup": "Changes only the startup type.",
        "contain": "Saves configuration, stops the service and sets it to Disabled. "
        "Partial failure is rolled back automatically.",
        "delete": "Saves configuration, stops the service and deletes it with sc.exe, then verifies removal.",
    }.get(action, "")
