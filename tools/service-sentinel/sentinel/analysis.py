"""Service categorisation, SCM event interpretation and risk scoring.

Scoring rules differ deliberately from the legacy PowerShell tool in three ways:

1. **Unknown is not suspicious.** A blank executable path or an unchecked
   signature contributes zero points and is reported as a data gap, so a
   non-elevated run no longer invents risk for services whose metadata is
   simply unreadable.
2. **User-writable locations are detected by path segment**, on any drive.
3. **Categories ignore the executable path**, which used to file unrelated
   software under "Update and Deployment" merely because a folder was named
   ``...Installer``.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import paths

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CRITICAL_SERVICE_NAMES = (
    "svchost",
    "lsass",
    "winlogon",
    "csrss",
    "smss",
    "services",
    "dcomlaunch",
    "rpcss",
    "plugplay",
    "eventlog",
    "profsvc",
    "termservice",
    "schedule",
    "spoolsv",
    "wuauserv",
    "cryptsvc",
    "bits",
    "winmgmt",
    "seclogon",
    "mssmbios",
)

ACCOUNT_EQUIVALENTS = {"localsystem", "nt authority\\system", ".\\localsystem", "system"}

# Keyword weights: the internal service name and display name are far more
# descriptive than the free-text description.
CATEGORY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Security",
        ("defender", "antivirus", "antimalware", "firewall", "endpoint", "edr", "security agent"),
    ),
    (
        "Database",
        ("sql", "database", "postgres", "mysql", "oracle", "mongo", "mariadb", "db2"),
    ),
    (
        "Web and Application",
        ("iis", "apache", "nginx", "web server", "http", "tomcat", "application server"),
    ),
    (
        "Update and Deployment",
        ("windows update", "wuauserv", "bits", "updater", "update service", "servicing", "patch"),
    ),
    (
        "Network and Remote Access",
        ("network", " dns", "dhcp", " wlan", "winrm", "remote access", " smb", "vpn", "wi-fi"),
    ),
    (
        "Backup and Recovery",
        ("backup", "restore", "snapshot", " vss", "replication"),
    ),
)

CATEGORY_PRIORITY = [name for name, _keywords in CATEGORY_KEYWORDS]

RISK_LEVELS = (
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (1, "Low"),
    (0, "Informational"),
)

# Points awarded per indicator. Documented in README and shown in the UI.
POINTS = {
    "user_writable_path": 40,
    "outside_roots": 15,
    "unquoted_path": 20,
    "missing_binary": 20,
    "unsigned": 15,
    "invalid_signature": 30,
    "script_host": 25,
    "system_nonstandard_path": 15,
    "auto_start_user_writable": 10,
    "name_impersonation": 35,
    "created_recently": 10,
    "startup_type_changed": 5,
}

SCRIPT_HOST_PATTERN = (
    "powershell",
    "pwsh",
    "cmd.exe",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
)

SEEDED_STATE_WORDS = {
    "running": "Running",
    "started": "Running",
    "stopped": "Stopped",
    "paused": "Paused",
    "start pending": "Start pending",
    "stop pending": "Stop pending",
    "continue pending": "Continue pending",
    "pause pending": "Pause pending",
    "not applicable": "Stopped",
}


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #


def parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Trim sub-microsecond precision that fromisoformat rejects on some builds.
    for candidate in (text, text[:26] + text[27:] if len(text) > 26 and text[26] not in "+-" else text):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def format_duration(start: Any, end: Any = None) -> str:
    begin = parse_time(start)
    if begin is None:
        return "Unknown"
    finish = parse_time(end) or datetime.now(begin.tzinfo)
    if finish.tzinfo and not begin.tzinfo:
        begin = begin.replace(tzinfo=finish.tzinfo)
    if not finish.tzinfo and begin.tzinfo:
        finish = finish.replace(tzinfo=begin.tzinfo)
    span = finish - begin
    seconds = span.total_seconds()
    if seconds < 0:
        return "Clock mismatch"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {int(seconds % 60)}s"


def iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def normalize_account(raw: Any) -> tuple[str, bool]:
    """Return (account, known).

    An empty *StartName* means Windows would not tell us the account (typically
    because the caller is not elevated). The legacy tool rewrote that to
    ``LocalSystem``, which turned a data gap into a false privilege finding and
    a false baseline change.
    """
    text = "" if raw is None else str(raw).strip()
    if not text or text.casefold() == "unknown":
        return "Unknown", False
    if text.casefold() in ACCOUNT_EQUIVALENTS:
        return "LocalSystem", True
    return text, True


def category_for(record: dict) -> str:
    service_type = str(record.get("service_type") or "")
    if "driver" in service_type.casefold():
        return "Driver"

    name = str(record.get("name") or "")
    display = str(record.get("display_name") or "")
    description = str(record.get("description") or "")

    scores: Counter[str] = Counter()
    for category, keywords in CATEGORY_KEYWORDS:
        for keyword in keywords:
            needle = keyword.strip().casefold()
            if needle in name.casefold():
                scores[category] += 3
            if needle in display.casefold():
                scores[category] += 3
            if needle in description.casefold():
                scores[category] += 1

    if scores:
        best = max(scores.values())
        for category in CATEGORY_PRIORITY:
            if scores.get(category, 0) == best:
                return category

    company = str(record.get("company") or "")
    exe_path = record.get("exe_path")
    if "microsoft" in company.casefold() or (
        exe_path and paths.is_under_roots(exe_path, [paths.protected_roots()[0]])
    ):
        return "Windows and Microsoft"
    if company:
        return "Third Party"
    return "Unclassified"


def risk_level(score: int) -> str:
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label
    return "Informational"


# --------------------------------------------------------------------------- #
# Event interpretation
# --------------------------------------------------------------------------- #


def _value(values: list, index: int, fallback: str = "") -> str:
    if index < len(values) and values[index] is not None:
        text = str(values[index]).strip()
        return text or fallback
    return fallback


def interpret_event(event: dict, state_words: dict[str, str] | None = None) -> dict:
    """Turn a raw SCM event record into an activity with a stable meaning.

    Event 7036 carries a *localised* state word. ``state_words`` maps the words
    observed on this host onto canonical states so classification does not break
    on non-English Windows; an unrecognised word is surfaced instead of guessed.
    """
    return _interpret_event(event, _state_mapping(state_words))


def _interpret_event(event: dict, mapping: dict[str, str]) -> dict:
    try:
        event_id = int(event.get("id", 0))
    except (TypeError, ValueError):
        event_id = 0
    values = event.get("values") or []
    if not isinstance(values, list):
        values = [values]

    service = _value(values, 0)
    activity = "Other"
    severity = "Information"
    detail = "Service event"
    state_word = None
    state = None

    if event_id == 7035:
        control = _value(values, 1, "control")
        activity = "Control requested"
        detail = f"Control requested: {control}"
    elif event_id == 7036:
        state_word = _value(values, 1)
        state = mapping.get(state_word.casefold())
        if state == "Running":
            activity, detail = "Started", "Entered the running state"
        elif state == "Stopped":
            activity, detail = "Stopped", "Entered the stopped state"
        elif state == "Paused":
            activity, detail = "Paused", "Entered the paused state"
        elif state in {"Start pending", "Stop pending", "Continue pending", "Pause pending"}:
            activity, detail = "State pending", f"Transitional state: {state}"
        else:
            activity = "State changed"
            detail = (
                f"Entered state '{state_word}'. This wording is not recognised yet; "
                "ServiceSentinel learns it from the running state on this host."
            )
    elif event_id == 7040:
        old = _value(values, 1, "?")
        new = _value(values, 2, "?")
        activity = "Startup type changed"
        detail = f"{old} -> {new}"
        severity = "Warning"
    elif event_id == 7045:
        image = _value(values, 1, "unknown image")
        account = _value(values, 4, "unknown account")
        activity = "Created"
        detail = f"Image={image}; Account={account}"
        severity = "Warning"
    elif event_id in (7031, 7034):
        activity = "Unexpected stop"
        detail = "Terminated unexpectedly; recovery action may follow"
        severity = "Error"
    elif event_id == 7032:
        activity, detail, severity = "Recovery failed", "Service recovery action failed", "Error"
    elif event_id == 7000:
        activity, detail, severity = "Start failed", "Failed to start", "Error"
    elif event_id == 7001:
        activity, detail, severity = "Dependency failure", "Dependency prevented startup", "Error"
    elif event_id == 7009:
        activity, detail, severity = "Start timeout", "Timed out waiting for connection", "Error"
    elif event_id == 7011:
        activity, detail, severity = "Control timeout", "Timed out waiting for a transaction", "Error"
    elif event_id == 7022:
        activity, detail, severity = "Start stalled", "Hung while starting", "Error"
    elif event_id in (7023, 7024):
        activity, detail, severity = "Stopped with error", "Terminated with an error", "Error"
    elif event_id == 7026:
        activity, detail, severity = "Driver load failed", "Boot or system-start driver failed to load", "Error"
    else:
        detail = " ".join(str(v) for v in values if v)[:300] or "Service event"

    return {
        "time": event.get("time"),
        "event_id": event_id,
        "service_name": service,
        "activity": activity,
        "severity": severity,
        "detail": detail,
        "record_id": event.get("record_id"),
        "state_word": state_word,
        "source": "System/Service Control Manager",
    }


def _state_mapping(state_words: dict[str, str] | None = None) -> dict[str, str]:
    mapping = dict(SEEDED_STATE_WORDS)
    if state_words:
        mapping.update({str(key).casefold(): value for key, value in state_words.items()})
    return mapping


def interpret_events(raw_events: Iterable[dict], state_words: dict | None = None) -> list[dict]:
    """Interpret a whole event window once, building the state mapping a single time."""
    mapping = _state_mapping(state_words)
    return [_interpret_event(event, mapping) for event in raw_events]


def event_index(interpreted: Iterable[dict]) -> dict[str, list[dict]]:
    """Index interpreted events by service name so scoring is linear, not quadratic."""
    index: dict[str, list[dict]] = defaultdict(list)
    for event in interpreted:
        key = str(event.get("service_name") or "").casefold()
        if key:
            index[key].append(event)
    return index


_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def events_for(
    record: dict,
    interpreted: list[dict] | None = None,
    index: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """Events belonging to one service, matched on internal or display name."""
    keys = {
        str(record.get("name") or "").casefold(),
        str(record.get("display_name") or "").casefold(),
    }
    keys.discard("")

    if index is not None:
        mine: list[dict] = []
        seen: set[tuple] = set()
        for key in keys:
            for event in index.get(key, []):
                marker = (event.get("record_id"), event.get("event_id"), event.get("time"))
                if marker in seen:
                    continue
                seen.add(marker)
                mine.append(event)
    else:
        mine = [
            event
            for event in (interpreted or [])
            if str(event.get("service_name") or "").casefold() in keys
        ]
    mine.sort(key=lambda item: parse_time(item.get("time")) or _EPOCH)
    return mine


def learn_state_words(
    raw_events: Iterable[dict],
    inventory: Iterable[dict],
    known: dict[str, str] | None = None,
) -> dict[str, str]:
    """Infer this host's localised 7036 state words from known service states."""
    learned = {str(k).casefold(): v for k, v in (known or {}).items()}
    for word in SEEDED_STATE_WORDS:
        learned.setdefault(word, SEEDED_STATE_WORDS[word])

    latest_word: dict[str, tuple[datetime, str]] = {}
    for event in raw_events:
        if int(event.get("id", 0) or 0) != 7036:
            continue
        values = event.get("values") or []
        if len(values) < 2:
            continue
        service = str(values[0] or "").strip().casefold()
        word = str(values[1] or "").strip()
        stamp = parse_time(event.get("time"))
        if not service or not word or stamp is None:
            continue
        current = latest_word.get(service)
        if current is None or stamp > current[0]:
            latest_word[service] = (stamp, word)

    votes: dict[str, Counter[str]] = defaultdict(Counter)
    for service in inventory:
        name = str(service.get("name") or "").strip().casefold()
        state = str(service.get("state") or "")
        if state not in {"Running", "Stopped", "Paused"} or name not in latest_word:
            continue
        word = latest_word[name][1]
        if word.casefold() in learned:
            continue
        votes[word.casefold()][state] += 1

    candidates = {word: counts for word, counts in votes.items() if len(counts) == 1}
    for word, counts in candidates.items():
        learned[word] = counts.most_common(1)[0][0]
    return learned


# --------------------------------------------------------------------------- #
# Inventory enrichment
# --------------------------------------------------------------------------- #


def build_record(
    raw: dict,
    evidence: dict | None = None,
    events: list[dict] | None = None,
    state_words: dict[str, str] | None = None,
    interpreted: list[dict] | None = None,
    index: dict[str, list[dict]] | None = None,
) -> dict:
    """Combine a raw Win32_Service record with file evidence and event history."""
    command_line = raw.get("command_line")
    exe_path = paths.normalize_service_path(command_line)
    evidence = evidence or {}
    account, account_known = normalize_account(raw.get("start_name"))

    if interpreted is None and index is None:
        interpreted = interpret_events(events or [], state_words)
    mine = events_for(raw, interpreted, index)

    last_activity = mine[-1] if mine else None
    starts = [event for event in mine if event["activity"] == "Started"]
    stops = [event for event in mine if event["activity"] in {"Stopped", "Unexpected stop"}]
    last_start = starts[-1]["time"] if starts else None
    last_stop = stops[-1]["time"] if stops else None

    state = str(raw.get("state") or "")
    runtime_start = None
    runtime_source = None
    if state == "Running" and last_start:
        runtime_start, runtime_source = last_start, "SCM start event"
    elif state == "Running" and raw.get("process_start"):
        runtime_start, runtime_source = raw["process_start"], "Host process start time"

    signature = str(evidence.get("signature") or "") or "NotChecked"
    file_exists = bool(evidence.get("exists")) if evidence else paths.exists(exe_path)

    record = {
        "name": str(raw.get("name") or ""),
        "display_name": str(raw.get("display_name") or ""),
        "description": str(raw.get("description") or ""),
        "state": state or "Unknown",
        "start_mode": str(raw.get("start_mode") or "Unknown"),
        "account": account,
        "account_known": account_known,
        "service_type": str(raw.get("service_type") or ""),
        "process_id": int(raw.get("process_id") or 0),
        "command_line": str(command_line or ""),
        "exe_path": exe_path,
        "path_known": bool(exe_path),
        "file_exists": file_exists,
        "signature": signature,
        "signer": evidence.get("signer") or "",
        "company": evidence.get("company") or "",
        "version": evidence.get("version") or "",
        "sha256": evidence.get("sha256") or "",
        "file_size": evidence.get("size") or 0,
        "unquoted_path": paths.is_unquoted_path(command_line),
        "user_writable": paths.is_user_writable(exe_path),
        "outside_protected": paths.is_outside_protected_roots(exe_path),
        "runtime_start": runtime_start,
        "runtime": format_duration(runtime_start) if state == "Running" else "Not running",
        "runtime_source": runtime_source,
        "last_activity": last_activity["activity"] if last_activity else "No event in window",
        "last_activity_time": last_activity["time"] if last_activity else None,
        "last_stop_time": last_stop,
        "run_count": len(starts),
        "last_duration": (
            format_duration(runtime_start)
            if state == "Running" and runtime_start
            else (format_duration(last_start, last_stop) if last_start and last_stop else None)
        ),
        "evidence_collected": bool(evidence),
    }
    record["category"] = category_for(record)
    return record


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


def _add(reasons: list[dict], notes: list[str], text: str, points: int) -> None:
    reasons.append({"text": text, "points": points})


def assess(
    record: dict,
    events: list[dict] | None = None,
    state_words: dict | None = None,
    interpreted: list[dict] | None = None,
    index: dict[str, list[dict]] | None = None,
) -> dict:
    """Score one service for threat and reliability, explaining every point."""
    threat: list[dict] = []
    reliability: list[dict] = []
    notes: list[str] = []

    exe_path = record.get("exe_path")
    path_known = bool(exe_path)
    service_type = str(record.get("service_type") or "")
    is_driver = "driver" in service_type.casefold()
    signature = str(record.get("signature") or "")
    signed_valid = signature == "Valid"
    microsoft_signed = signed_valid and (
        "microsoft" in str(record.get("signer") or "").casefold()
        or "microsoft" in str(record.get("company") or "").casefold()
    )
    user_writable = bool(record.get("user_writable"))
    outside = bool(record.get("outside_protected"))

    # --- Threat indicators -------------------------------------------------
    if user_writable:
        _add(
            threat,
            notes,
            "Executable sits in a user-writable or temporary location "
            f"(+{POINTS['user_writable_path']}).",
            POINTS["user_writable_path"],
        )
    if outside and not microsoft_signed:
        _add(
            threat,
            notes,
            f"Executable is outside Windows and Program Files (+{POINTS['outside_roots']}).",
            POINTS["outside_roots"],
        )
    if record.get("unquoted_path"):
        _add(
            threat,
            notes,
            "Unquoted executable path contains spaces, allowing path interception "
            f"(+{POINTS['unquoted_path']}).",
            POINTS["unquoted_path"],
        )
    if path_known and not is_driver and record.get("file_exists") is False:
        _add(
            threat,
            notes,
            f"Configured executable is missing (+{POINTS['missing_binary']}).",
            POINTS["missing_binary"],
        )
    if signature == "NotSigned":
        _add(threat, notes, f"Executable is not digitally signed (+{POINTS['unsigned']}).", POINTS["unsigned"])
    elif signature in {"HashMismatch", "NotTrusted", "UnknownError"}:
        _add(
            threat,
            notes,
            f"Signature validation returned {signature} (+{POINTS['invalid_signature']}).",
            POINTS["invalid_signature"],
        )

    command_line = str(record.get("command_line") or "")
    lowered = command_line.casefold()
    if any(host in lowered for host in SCRIPT_HOST_PATTERN):
        _add(
            threat,
            notes,
            "Service runs a script or proxy-execution host "
            f"(+{POINTS['script_host']}).",
            POINTS["script_host"],
        )

    privileged = str(record.get("account") or "").casefold() in {"localsystem", "system"} or str(
        record.get("account") or ""
    ).upper().startswith("NT AUTHORITY\\SYSTEM")
    if privileged and path_known and outside:
        _add(
            threat,
            notes,
            f"High-privilege account is paired with a nonstandard path (+{POINTS['system_nonstandard_path']}).",
            POINTS["system_nonstandard_path"],
        )
    if str(record.get("start_mode") or "") == "Auto" and user_writable:
        _add(
            threat,
            notes,
            f"Automatic startup increases persistence impact (+{POINTS['auto_start_user_writable']}).",
            POINTS["auto_start_user_writable"],
        )

    name_lower = str(record.get("name") or "").casefold()
    impersonating = name_lower in CRITICAL_SERVICE_NAMES and not (
        exe_path and "\\windows\\system32\\" in exe_path.casefold()
    )
    if impersonating:
        _add(
            threat,
            notes,
            f"Name imitates a Windows component from an unexpected path (+{POINTS['name_impersonation']}).",
            POINTS["name_impersonation"],
        )

    # --- Data gaps: reported, never scored --------------------------------
    if not path_known:
        notes.append(
            "Executable path was not readable, so path, signature and hash checks were skipped. "
            "Run the server as Administrator to collect them."
        )
    if signature in {"", "NotChecked"}:
        notes.append("Authenticode signature was not checked; no unsigned-binary points were applied.")
    if signature == "FileNotFound" and path_known:
        notes.append("Binary could not be opened for signature inspection.")
    if not record.get("account_known", True):
        notes.append("Service account was not readable; privilege checks were limited to the binary itself.")

    # --- Event-derived threat context -------------------------------------
    if interpreted is None and index is None:
        interpreted = interpret_events(events or [], state_words)
    mine = events_for(record, interpreted, index)
    if any(event["activity"] == "Created" for event in mine):
        _add(
            threat,
            notes,
            f"Service was created inside the selected event window (+{POINTS['created_recently']}).",
            POINTS["created_recently"],
        )
    if any(event["activity"] == "Startup type changed" for event in mine):
        _add(
            threat,
            notes,
            f"Startup type changed inside the selected event window (+{POINTS['startup_type_changed']}).",
            POINTS["startup_type_changed"],
        )

    # --- Reliability ------------------------------------------------------
    unexpected = sum(1 for event in mine if event["activity"] == "Unexpected stop")
    failures = sum(1 for event in mine if event["severity"] == "Error")
    if unexpected:
        points = min(40, 10 * unexpected)
        reliability.append(
            {"text": f"{unexpected} unexpected stop event(s) (+{points}).", "points": points}
        )
    other_failures = max(0, failures - unexpected)
    if other_failures:
        points = min(30, 5 * other_failures)
        reliability.append(
            {"text": f"{other_failures} other failure or timeout event(s) (+{points}).", "points": points}
        )

    threat_score = min(100, sum(item["points"] for item in threat))
    reliability_score = min(100, sum(item["points"] for item in reliability))
    threat_level = risk_level(threat_score)
    reliability_level = risk_level(reliability_score)

    return {
        "service_name": record.get("name"),
        "display_name": record.get("display_name"),
        "category": record.get("category"),
        "state": record.get("state"),
        "start_mode": record.get("start_mode"),
        "account": record.get("account"),
        "account_known": record.get("account_known", True),
        "service_type": record.get("service_type"),
        "exe_path": exe_path or "",
        "file_exists": bool(record.get("file_exists")),
        "signature": signature or "NotChecked",
        "signer": record.get("signer") or "",
        "company": record.get("company") or "",
        "version": record.get("version") or "",
        "sha256": record.get("sha256") or "",
        "threat_score": threat_score,
        "threat_level": threat_level,
        "reliability_score": reliability_score,
        "reliability_level": reliability_level,
        "threat_reasons": threat,
        "threat_reasons_text": " ".join(item["text"] for item in threat),
        "reliability_reasons": reliability,
        "reliability_reasons_text": " ".join(item["text"] for item in reliability),
        "recommendation": recommendation(threat, notes, threat_level),
        "notes": notes,
        "last_activity": record.get("last_activity"),
        "last_activity_time": record.get("last_activity_time"),
        "runtime": record.get("runtime"),
    }


def recommendation(threat: list[dict], notes: list[str], level: str) -> str:
    texts = " ".join(item["text"].casefold() for item in threat)
    if level == "Critical":
        if "user-writable" in texts:
            return (
                "Binary runs from a user-writable location. Capture the file and hash, verify the installer "
                "source, then contain the service after confirming business impact."
            )
        if "script" in texts or "proxy-execution" in texts:
            return (
                "Service executes through an interpreter. Inspect the full command line for encoded payloads "
                "and contain only after validating its purpose."
            )
        if "imitates" in texts:
            return (
                "Name impersonates a Windows component from a non-standard path. Treat as high-confidence "
                "persistence: preserve evidence, then contain."
            )
        return "Collect the binary and service configuration, then contain after confirming business impact."
    if level == "High":
        if "signature" in texts:
            return (
                "Signature validation failed or is missing. Re-obtain the binary from the vendor, verify the "
                "signer, and check the hash against threat intelligence."
            )
        if "missing" in texts:
            return (
                "The configured binary no longer exists. Decide whether this is an abandoned install or a "
                "tampered service, then delete or repair it deliberately."
            )
        return "Investigate the signer, hash, path permissions, creation event and owner before taking action."
    if level == "Medium":
        return "Verify the software is approved, confirm the publisher, and record a triage decision."
    if level == "Low" and threat:
        return "Low-weight indicators were recorded. Confirm the service owner and purpose, then record a triage decision."
    if notes:
        return "No threat indicator was found, but some metadata could not be read. Re-run elevated to complete the picture."
    return "No indicator was identified; keep the service in normal monitoring."


# --------------------------------------------------------------------------- #
# Timeline summaries
# --------------------------------------------------------------------------- #


def summarize_timeline(events: list[dict], bucket: str = "day") -> dict:
    """Aggregate interpreted events by activity and by day or week."""
    weekly = str(bucket or "day").lower().startswith("w")
    activity_counts: Counter[str] = Counter(event.get("activity") or "Other" for event in events)
    buckets: dict[str, dict] = {}

    for event in events:
        stamp = parse_time(event.get("time"))
        if stamp is None:
            continue
        if weekly:
            start = stamp.date() - timedelta(days=stamp.weekday())
            key = f"Week of {start.isoformat()}"
        else:
            key = stamp.date().isoformat()
        entry = buckets.setdefault(
            key, {"key": key, "events": 0, "created": 0, "started": 0, "stopped": 0, "failures": 0}
        )
        entry["events"] += 1
        if event.get("activity") == "Created":
            entry["created"] += 1
        if event.get("activity") == "Started":
            entry["started"] += 1
        if event.get("activity") == "Stopped":
            entry["stopped"] += 1
        if event.get("severity") == "Error":
            entry["failures"] += 1

    return {
        "by_activity": [
            {"name": name, "count": count} for name, count in activity_counts.most_common()
        ],
        "by_bucket": sorted(buckets.values(), key=lambda item: item["key"], reverse=True),
        "total": len(events),
        "created": activity_counts.get("Created", 0),
        "started": activity_counts.get("Started", 0),
        "stopped": activity_counts.get("Stopped", 0),
        "failures": sum(1 for event in events if event.get("severity") == "Error"),
        "unrecognised_state_words": sorted(
            {
                event.get("state_word")
                for event in events
                if event.get("state_word") and event.get("activity") == "State changed"
            }
        ),
    }
