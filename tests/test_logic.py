"""Unit tests for the parts of ServiceSentinel that can be checked without Windows.

Every test here pins one of the defects found in the legacy PowerShell tool, so
a regression is caught rather than re-discovered.
"""

from __future__ import annotations

import pytest

from sentinel import analysis, baseline, config, exports, maintenance, paths, storage, triage
from sentinel.collector import Collector


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    config.set_data_root(tmp_path)
    return tmp_path


def make_record(**overrides) -> dict:
    record = {
        "name": "TestSvc",
        "display_name": "Test Service",
        "description": "A service used by tests.",
        "state": "Running",
        "start_mode": "Manual",
        "account": "LocalSystem",
        "account_known": True,
        "service_type": "Own Process",
        "process_id": 4242,
        "command_line": '"C:\\Program Files\\App\\svc.exe" -run',
        "exe_path": "C:\\Program Files\\App\\svc.exe",
        "path_known": True,
        "file_exists": True,
        "signature": "Valid",
        "signer": "CN=Microsoft Windows, O=Microsoft Corporation",
        "company": "Microsoft Corporation",
        "sha256": "A" * 64,
        "unquoted_path": False,
        "user_writable": False,
        "outside_protected": False,
        "run_count": 0,
        "runtime": "1h 0m",
    }
    record.update(overrides)
    return record


def inventory_row(**overrides) -> dict:
    row = {
        "name": "Svc",
        "display_name": "Service",
        "state": "Running",
        "start_mode": "Auto",
        "account": "LocalSystem",
        "service_type": "Own Process",
        "command_line": '"C:\\Program Files\\App\\svc.exe"',
        "exe_path": "C:\\Program Files\\App\\svc.exe",
    }
    row.update(overrides)
    return row


# --------------------------------------------------------------------------- #
# Path handling
# --------------------------------------------------------------------------- #
def test_quoted_path_is_extracted():
    assert paths.normalize_service_path('"C:\\Program Files\\App\\svc.exe" -k x') == (
        "C:\\Program Files\\App\\svc.exe"
    )


def test_unquoted_path_with_arguments_is_extracted():
    assert paths.normalize_service_path("C:\\Windows\\system32\\svchost.exe -k netsvcs") == (
        "C:\\Windows\\system32\\svchost.exe"
    )


def test_native_prefix_is_stripped():
    assert paths.normalize_service_path("\\??\\C:\\Windows\\System32\\drv.sys") == (
        "C:\\Windows\\System32\\drv.sys"
    )


def test_systemroot_prefix_is_expanded():
    result = paths.normalize_service_path("\\SystemRoot\\System32\\svchost.exe -k x")
    assert result is not None
    assert result.lower().endswith("system32\\svchost.exe")


def test_blank_command_line_is_unknown_not_a_path():
    assert paths.normalize_service_path("") is None
    assert paths.normalize_service_path(None) is None
    assert paths.normalize_service_path("   ") is None


def test_unquoted_path_detection():
    assert paths.is_unquoted_path("C:\\Program Files\\My App\\svc.exe -run") is True
    assert paths.is_unquoted_path('"C:\\Program Files\\My App\\svc.exe" -run') is False
    assert paths.is_unquoted_path("C:\\Windows\\system32\\svchost.exe -k netsvcs") is False


def test_user_writable_detection_covers_any_drive():
    # A user-writable vendor folder on a non-system drive must still be detected.
    assert paths.is_user_writable("E:\\Downloads\\UvxInstaller\\svc.exe") is True
    assert paths.is_user_writable("C:\\Users\\bob\\AppData\\Local\\App\\svc.exe") is True
    assert paths.is_user_writable("C:\\Windows\\Temp\\svc.exe") is True
    assert paths.is_user_writable("D:\\Downloads\\svc.exe") is True


def test_protected_locations_are_not_user_writable():
    assert paths.is_user_writable("C:\\Program Files\\App\\svc.exe") is False
    assert paths.is_user_writable("C:\\ProgramData\\App\\svc.exe") is False
    assert paths.is_user_writable("C:\\Windows\\System32\\svc.exe") is False


def test_unknown_path_is_not_outside_protected_roots():
    assert paths.is_outside_protected_roots(None) is False
    assert paths.is_outside_protected_roots("") is False


def test_protected_root_comparison():
    assert paths.is_outside_protected_roots("C:\\Windows\\System32\\svc.exe") is False
    assert paths.is_outside_protected_roots("D:\\Tools\\svc.exe") is True


# --------------------------------------------------------------------------- #
# Account handling
# --------------------------------------------------------------------------- #
def test_blank_account_is_unknown_not_localsystem():
    assert analysis.normalize_account("") == ("Unknown", False)
    assert analysis.normalize_account(None) == ("Unknown", False)


def test_account_aliases_normalise():
    assert analysis.normalize_account("LocalSystem") == ("LocalSystem", True)
    assert analysis.normalize_account(".\\LocalSystem") == ("LocalSystem", True)
    assert analysis.normalize_account("NT AUTHORITY\\SYSTEM") == ("LocalSystem", True)
    assert analysis.normalize_account("NT SERVICE\\Mssense") == ("NT SERVICE\\Mssense", True)


# --------------------------------------------------------------------------- #
# Scoring: unknown is not suspicious
# --------------------------------------------------------------------------- #
def test_unreadable_metadata_scores_zero_and_is_reported():
    record = make_record(
        exe_path=None,
        path_known=False,
        command_line="",
        signature="NotChecked",
        account="Unknown",
        account_known=False,
        file_exists=False,
        signer="",
        company="",
    )
    result = analysis.assess(record)
    assert result["threat_score"] == 0
    assert result["threat_level"] == "Informational"
    assert result["threat_reasons"] == []
    assert any("not readable" in note.lower() for note in result["notes"])
    assert any("signature was not checked" in note.lower() for note in result["notes"])


def test_missing_binary_only_counts_when_path_is_known():
    known = analysis.assess(make_record(file_exists=False, signature="Valid"))
    assert any("missing" in reason["text"].lower() for reason in known["threat_reasons"])
    unknown = analysis.assess(make_record(file_exists=False, path_known=False, exe_path=None))
    assert unknown["threat_score"] == 0


def test_unsigned_points_require_a_real_signature_status():
    checked = analysis.assess(make_record(signature="NotSigned", signer="", company=""))
    assert any("not digitally signed" in reason["text"].lower() for reason in checked["threat_reasons"])
    unchecked = analysis.assess(make_record(signature="NotChecked", signer="", company=""))
    assert not any("not digitally signed" in reason["text"].lower() for reason in unchecked["threat_reasons"])


def test_user_writable_location_is_the_heaviest_indicator():
    record = make_record(
        exe_path="C:\\Users\\bob\\Downloads\\svc.exe",
        command_line="C:\\Users\\bob\\Downloads\\svc.exe",
        user_writable=True,
        outside_protected=True,
        signature="NotSigned",
        signer="",
        company="",
    )
    result = analysis.assess(record)
    texts = " ".join(reason["text"] for reason in result["threat_reasons"])
    assert "user-writable" in texts
    assert result["threat_score"] >= 70
    assert result["threat_level"] in {"High", "Critical"}


def test_unquoted_path_alone_is_low_not_high():
    record = make_record(
        command_line="C:\\Program Files\\My App\\svc.exe",
        exe_path="C:\\Program Files\\My App\\svc.exe",
        unquoted_path=True,
    )
    result = analysis.assess(record)
    assert result["threat_score"] == analysis.POINTS["unquoted_path"]
    assert result["threat_level"] == "Low"


def test_low_threat_does_not_claim_no_indicator_was_found():
    record = make_record(
        command_line="C:\\Program Files\\My App\\svc.exe",
        exe_path="C:\\Program Files\\My App\\svc.exe",
        unquoted_path=True,
    )
    result = analysis.assess(record)
    assert result["threat_reasons"]
    assert "Low-weight indicators" in result["recommendation"]
    assert "No indicator was identified" not in result["recommendation"]


def test_name_impersonation_is_flagged():
    record = make_record(
        name="svchost",
        command_line="C:\\Users\\Public\\svchost.exe",
        exe_path="C:\\Users\\Public\\svchost.exe",
        user_writable=True,
        outside_protected=True,
        signature="NotSigned",
        signer="",
    )
    result = analysis.assess(record)
    assert any("imitates" in reason["text"].lower() for reason in result["threat_reasons"])


def test_reliability_is_scored_separately_with_caps():
    events = [
        {"id": 7034, "time": f"2026-01-0{day + 1}T10:00:00+00:00", "values": ["TestSvc"]}
        for day in range(6)
    ]
    result = analysis.assess(make_record(), events)
    assert result["reliability_score"] == 40  # capped
    assert result["threat_score"] == 0
    assert result["reliability_level"] == "Medium"


def test_category_ignores_executable_path():
    record = make_record(
        name="UVexplorerDiscoveryService",
        display_name="UVexplorer Discovery Service",
        description="Discovers network devices.",
        exe_path="C:\\Program Files\\UVexplorer\\svc.exe",
    )
    assert analysis.category_for(record) == "Network and Remote Access"


def test_driver_service_type_wins_category():
    assert analysis.category_for(make_record(service_type="Kernel Driver")) == "Driver"


# --------------------------------------------------------------------------- #
# Event interpretation and localisation
# --------------------------------------------------------------------------- #
def test_7036_running_maps_to_started():
    event = analysis.interpret_event({"id": 7036, "time": "2026-01-01T10:00:00+00:00", "values": ["Svc", "running"]})
    assert event["activity"] == "Started"
    assert event["severity"] == "Information"


def test_7045_creation_is_a_warning():
    event = analysis.interpret_event(
        {"id": 7045, "time": "2026-01-01T10:00:00+00:00", "values": ["Svc", "C:\\x.exe", "own", "auto", "SYSTEM"]}
    )
    assert event["activity"] == "Created"
    assert event["severity"] == "Warning"
    assert "SYSTEM" in event["detail"]


def test_unknown_state_word_is_surfaced_not_guessed():
    event = analysis.interpret_event(
        {"id": 7036, "time": "2026-01-01T10:00:00+00:00", "values": ["Svc", "Wird ausgeführt"]}
    )
    assert event["activity"] == "State changed"
    assert event["state_word"] == "Wird ausgeführt"


def test_state_words_are_learned_from_current_state():
    events = [{"id": 7036, "time": "2026-01-01T10:00:00+00:00", "values": ["Svc", "Wird ausgeführt"]}]
    learned = analysis.learn_state_words(events, [{"name": "Svc", "state": "Running"}])
    assert learned["wird ausgeführt"] == "Running"


def test_learned_state_word_is_used_by_the_interpreter():
    learned = analysis.learn_state_words(
        [{"id": 7036, "time": "2026-01-01T10:00:00+00:00", "values": ["Svc", "Wird ausgeführt"]}],
        [{"name": "Svc", "state": "Running"}],
    )
    event = analysis.interpret_event(
        {"id": 7036, "time": "2026-01-01T09:00:00+00:00", "values": ["Svc", "Wird ausgeführt"]}, learned
    )
    assert event["activity"] == "Started"


def test_ambiguous_state_words_are_not_learned():
    events = [
        {"id": 7036, "time": "2026-01-01T10:00:00+00:00", "values": ["A", "unbekannt"]},
        {"id": 7036, "time": "2026-01-01T11:00:00+00:00", "values": ["B", "unbekannt"]},
    ]
    learned = analysis.learn_state_words(
        events, [{"name": "A", "state": "Running"}, {"name": "B", "state": "Stopped"}]
    )
    assert "unbekannt" not in learned


# --------------------------------------------------------------------------- #
# Baseline comparison
# --------------------------------------------------------------------------- #
def test_unreadable_value_is_unverifiable_not_a_change():
    document = baseline.capture([inventory_row()], "HOST", "2026-01-01T00:00:00+00:00")
    current = [inventory_row(account="Unknown", command_line="")]
    result = baseline.diff(document, current)
    assert result["changes"] == []
    assert {item["field"] for item in result["unverifiable"]} == {"Account", "Command line"}


def test_account_alias_is_not_a_change():
    document = baseline.capture([inventory_row(account="LocalSystem")], "HOST", "2026-01-01T00:00:00+00:00")
    result = baseline.diff(document, [inventory_row(account="NT AUTHORITY\\SYSTEM")])
    assert result["changes"] == []


def test_command_line_change_is_high_severity():
    document = baseline.capture([inventory_row()], "HOST", "2026-01-01T00:00:00+00:00")
    current = [inventory_row(command_line='"C:\\Users\\bob\\evil.exe"')]
    result = baseline.diff(document, current)
    assert len(result["changes"]) == 1
    assert result["changes"][0]["severity"] == "High"
    assert result["changes"][0]["field"] == "Command line"


def test_versioned_name_rotation_is_low_severity():
    document = baseline.capture(
        [inventory_row(name="GoogleUpdaterService159.0.8140.0")], "HOST", "2026-01-01T00:00:00+00:00"
    )
    current = [inventory_row(name="GoogleUpdaterService162.0.8150.0")]
    result = baseline.diff(document, current)
    assert result["summary"]["created"] == 0
    assert result["summary"]["deleted"] == 0
    assert result["changes"][0]["change_type"] == "Versioned replacement"
    assert result["changes"][0]["severity"] == "Low"


def test_genuine_creation_and_deletion_stay_high():
    document = baseline.capture([inventory_row(name="OldService")], "HOST", "2026-01-01T00:00:00+00:00")
    current = [inventory_row(name="NewPersistence")]
    result = baseline.diff(document, current)
    severities = {change["change_type"]: change["severity"] for change in result["changes"]}
    assert severities["Created since baseline"] == "High"
    assert severities["Deleted since baseline"] == "High"


def test_missing_baseline_returns_guidance():
    result = baseline.diff(None, [inventory_row()])
    assert result["changes"] == []
    assert "No baseline exists" in result["message"]


# --------------------------------------------------------------------------- #
# Triage
# --------------------------------------------------------------------------- #
def test_triage_records_real_evidence_snapshot(data_dir):
    assessment = analysis.assess(make_record())
    entry = triage.record(
        "TestSvc",
        "Investigate",
        assessment=assessment,
        analyst="Analyst A",
        notes="Checked signer.",
        hostname="HOST",
    )
    assert entry["threat_score"] == assessment["threat_score"]
    assert entry["sha256"] == "A" * 64
    assert entry["executable_path"].endswith("svc.exe")
    assert entry["evidence_complete"] is True
    assert [item["id"] for item in triage.list_all()] == [entry["id"]]


def test_triage_rejects_invalid_decision(data_dir):
    with pytest.raises(ValueError):
        triage.record("TestSvc", "Banish", assessment={}, analyst="x")


def test_triage_is_append_only(data_dir):
    triage.record("TestSvc", "Monitor", assessment={}, analyst="a")
    triage.record("TestSvc", "Allow", assessment={}, analyst="b")
    records = triage.list_all()
    assert len(records) == 2
    assert triage.latest_by_service()["testsvc"]["decision"] == "Allow"


# --------------------------------------------------------------------------- #
# Exports
# --------------------------------------------------------------------------- #
def test_html_export_escapes_service_metadata(data_dir):
    result = exports.export(
        "inventory",
        [{"name": "<script>alert(1)</script>", "threat_score": 5, "notes": ["a & b"]}],
        "Html",
    )
    content = (data_dir / result["file"]).read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


def test_csv_export_has_friendly_headers(data_dir):
    result = exports.export("inventory", [{"name": "Svc", "start_mode": "Auto"}], "Csv")
    content = (data_dir / result["file"]).read_text(encoding="utf-8-sig")
    assert "Startup" in content
    assert "Svc" in content


def test_concurrent_exports_do_not_overwrite(data_dir):
    first = exports.export("inventory", [{"name": "A"}], "Csv")
    second = exports.export("inventory", [{"name": "B"}], "Csv")
    assert first["file"] != second["file"]
    assert (data_dir / first["file"]).exists()
    assert (data_dir / second["file"]).exists()


def test_json_export_is_structured(data_dir):
    result = exports.export("triage", [{"service_name": "Svc", "decision": "Allow"}], "Json")
    import json

    payload = json.loads((data_dir / result["file"]).read_text(encoding="utf-8"))
    assert payload["row_count"] == 1
    assert payload["rows"][0]["decision"] == "Allow"


# --------------------------------------------------------------------------- #
# Web layer
# --------------------------------------------------------------------------- #
class FakeCollector:
    """Stands in for the PowerShell collector so the API can be tested anywhere."""

    def status(self, refresh: bool = False):
        return {
            "app": config.APP_NAME,
            "version": config.VERSION,
            "hostname": "TESTHOST",
            "admin": False,
            "platform": "Windows",
            "data_root": str(config.data_root()),
            "log_file": str(config.log_file()),
            "python": "3.13",
            "powershell": "5.1",
            "baseline_exists": config.baseline_file().exists(),
            "evidence_cache_entries": 0,
            "triage_count": 0,
        }

    def inventory(self, evidence: bool = True, refresh: bool = False, hours: int = 168):
        record = analysis.build_record(
            {
                "name": "FakeSvc",
                "display_name": "Fake Service",
                "description": "",
                "state": "Running",
                "start_mode": "Auto",
                "start_name": "LocalSystem",
                "service_type": "Own Process",
                "process_id": 1,
                "command_line": '"C:\\Windows\\System32\\fake.exe"',
            },
            {"exists": True, "signature": "Valid", "signer": "CN=Microsoft", "company": "Microsoft", "sha256": "B" * 64},
            [],
            {},
        )
        return {
            "collected_at": analysis.iso_now(),
            "evidence": evidence,
            "event_window_hours": hours,
            "events_truncated": False,
            "event_count": 0,
            "services": [record],
            "stats": {"total": 1, "running": 1, "stopped": 0, "auto": 1, "unsigned": 0,
                      "missing_binary": 0, "user_writable": 0, "unquoted": 0, "unknown_path": 0,
                      "categories": [{"name": record["category"], "count": 1}]},
        }

    def service_detail(self, name: str, hours: int = 168):
        if name.casefold() != "fakesvc":
            raise KeyError(name)
        record = self.inventory()["services"][0]
        return {
            "service": record,
            "assessment": analysis.assess(record),
            "events": [],
            "event_total": 0,
            "triage": None,
            "state_words": {},
        }

    def assessments(self, hours: int = 168, refresh: bool = False):
        record = self.inventory()["services"][0]
        return {
            "collected_at": analysis.iso_now(),
            "hours": hours,
            "event_count": 0,
            "events_truncated": False,
            "findings": [analysis.assess(record)],
            "notable": 0,
            "counts": {"Informational": 1},
            "scored_services": 1,
        }

    def timeline(self, hours: int = 168, name: str = "", bucket: str = "day", refresh: bool = False):
        return {
            "hours": hours,
            "name": name,
            "bucket": bucket,
            "events": [],
            "truncated": False,
            "summary": analysis.summarize_timeline([], bucket),
            "state_words": {},
        }


@pytest.fixture
def client(data_dir):
    from sentinel.server import create_app

    app = create_app(FakeCollector())
    app.config.update(TESTING=True)
    return app.test_client(), app


def test_index_page_renders(client):
    http, _app = client
    response = http.get("/")
    assert response.status_code == 200
    assert b"ServiceSentinel" in response.data


def test_status_endpoint(client):
    http, _app = client
    payload = http.get("/api/status").get_json()
    assert payload["hostname"] == "TESTHOST"
    assert payload["ok"] is True


def test_inventory_endpoint(client):
    http, _app = client
    payload = http.get("/api/inventory").get_json()
    assert payload["services"][0]["name"] == "FakeSvc"
    assert payload["stats"]["total"] == 1


def test_post_requires_token(client):
    http, _app = client
    response = http.post("/api/triage", json={"service": "FakeSvc", "decision": "Monitor"})
    assert response.status_code == 403


def test_post_with_token_records_triage(client):
    http, app = client
    response = http.post(
        "/api/triage",
        json={"service": "FakeSvc", "decision": "Monitor", "analyst": "Tester", "notes": "looks fine"},
        headers={"X-Sentinel-Token": app.extensions["token"]},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["record"]["decision"] == "Monitor"
    assert payload["record"]["sha256"] == "B" * 64


def test_baseline_requires_typed_confirmation(client):
    http, app = client
    response = http.post(
        "/api/baseline",
        json={"confirm": "yes"},
        headers={"X-Sentinel-Token": app.extensions["token"]},
    )
    assert response.status_code == 400


def test_baseline_create_then_compare(client):
    http, app = client
    headers = {"X-Sentinel-Token": app.extensions["token"]}
    created = http.post("/api/baseline", json={"confirm": "BASELINE"}, headers=headers)
    assert created.status_code == 200
    assert created.get_json()["services"] == 1
    compared = http.get("/api/baseline").get_json()
    assert compared["exists"] is True
    assert compared["changes"] == []


def test_export_endpoint(client):
    http, app = client
    response = http.post(
        "/api/export",
        json={"report": "inventory", "format": "Csv"},
        headers={"X-Sentinel-Token": app.extensions["token"]},
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["rows"] == 1
    assert payload["url"].startswith("/api/download/")


def test_management_requires_exact_confirmation(client):
    http, app = client
    response = http.post(
        "/api/manage",
        json={"service": "FakeSvc", "action": "stop", "confirm": "fakesvc"},
        headers={"X-Sentinel-Token": app.extensions["token"]},
    )
    assert response.status_code == 400
    assert "Confirmation" in response.get_json()["error"]


def test_management_refuses_core_service(client):
    http, app = client
    response = http.post(
        "/api/manage",
        json={"service": "rpcss", "action": "delete", "confirm": "rpcss"},
        headers={"X-Sentinel-Token": app.extensions["token"]},
    )
    assert response.status_code == 400
    assert "core Windows service" in response.get_json()["error"]


# --------------------------------------------------------------------------- #
# Production hardening
# --------------------------------------------------------------------------- #
def test_csv_export_neutralises_formula_injection(data_dir):
    result = exports.export(
        "inventory",
        [{"name": "=cmd|' /C calc'!A0", "notes": ["@SUM(1+1)"], "display_name": "-2"}],
        "Csv",
    )
    content = (data_dir / result["file"]).read_text(encoding="utf-8-sig")
    assert "'=cmd" in content
    assert "'@SUM" in content
    # A plain negative number must not be mangled.
    assert "-2" in content and "'-2" not in content


def test_state_word_file_ignores_metadata_keys(data_dir):
    storage.write_json(config.state_words_file(), {"_learned_at": "2026-01-01", "running": "Running"})
    assert Collector().state_words() == {"running": "Running"}


def test_state_word_legacy_flat_format_still_reads(data_dir):
    storage.write_json(config.state_words_file(), {"stopped": "Stopped", "_learned_at": "x"})
    assert Collector().state_words() == {"stopped": "Stopped"}


class StubCollector(Collector):
    """Collector with PowerShell replaced by deterministic canned data."""

    def _run(self, mode, payload=None, timeout=240):
        if mode == "services":
            return {
                "items": [
                    {
                        "name": "StubSvc",
                        "display_name": "Stub Service",
                        "description": "",
                        "state": "Running",
                        "start_mode": "Auto",
                        "start_name": "LocalSystem",
                        "service_type": "Own Process",
                        "process_id": 1,
                        "command_line": '"C:\\Windows\\System32\\stub.exe"',
                    }
                ]
            }
        if mode == "events":
            hours = int((payload or {}).get("hours", 24))
            count = 1 if hours <= 24 else 3
            return {
                "items": [
                    {
                        "id": 7036,
                        "time": "2026-01-01T10:00:00+00:00",
                        "record_id": index,
                        "values": ["Stub Service", "running"],
                    }
                    for index in range(count)
                ],
                "truncated": False,
            }
        if mode in {"evidence", "inspect"}:
            return {"items": []}
        return {}


def test_inventory_cache_distinguishes_event_window(data_dir):
    collector = StubCollector()
    short = collector.inventory(evidence=False, hours=24)
    long = collector.inventory(evidence=False, hours=168)
    assert short["event_count"] == 1
    assert long["event_count"] == 3
    assert long["event_window_hours"] == 168
    assert long["services"][0]["run_count"] == 3


def test_assess_accepts_prebuilt_index():
    interpreted = analysis.interpret_events(
        [{"id": 7034, "time": "2026-01-01T10:00:00+00:00", "values": ["TestSvc"]}],
        {},
    )
    index = analysis.event_index(interpreted)
    result = analysis.assess(make_record(), interpreted=interpreted, index=index)
    assert result["reliability_score"] == 10


def test_event_index_matches_both_service_names():
    interpreted = analysis.interpret_events(
        [{"id": 7045, "time": "2026-01-01T10:00:00+00:00", "values": ["Test Service", "C:\\x.exe", "own", "auto", "SYSTEM"]}],
        {},
    )
    index = analysis.event_index(interpreted)
    found = analysis.events_for(make_record(), interpreted, index)
    assert len(found) == 1
    assert found[0]["activity"] == "Created"


@pytest.fixture
def auth_client(data_dir):
    from sentinel.server import create_app

    previous = config.auth_password()
    config.set_auth_password("hunter2")
    app = create_app(FakeCollector(), prune_on_start=False)
    app.config.update(TESTING=True)
    try:
        yield app.test_client(), app
    finally:
        config.set_auth_password(previous)


def test_auth_blocks_api_without_session(auth_client):
    http, _app = auth_client
    assert http.get("/api/inventory").status_code == 401


def test_auth_redirects_pages_to_login(auth_client):
    http, _app = auth_client
    response = http.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_health_stays_public(auth_client):
    http, _app = auth_client
    response = http.get("/api/health")
    assert response.status_code in {200, 503}
    assert response.get_json()["status"] in {"ok", "degraded"}


def test_login_rejects_wrong_password(auth_client):
    http, _app = auth_client
    response = http.post("/login", data={"password": "wrong"})
    assert response.status_code == 401


def test_login_grantss_access(auth_client):
    http, _app = auth_client
    response = http.post("/login", data={"password": "hunter2"})
    assert response.status_code == 302
    assert http.get("/api/status").status_code == 200


def test_login_is_rate_limited(auth_client):
    http, _app = auth_client
    for _ in range(8):
        http.post("/login", data={"password": "wrong"})
    assert http.post("/login", data={"password": "hunter2"}).status_code == 429


def test_security_headers_are_present(client):
    http, _app = client
    response = http.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


class FakeManageCollector:
    """Minimal collector for management tests."""

    def __init__(self, admin: bool = True, delete_works: bool = True):
        self.admin = admin
        self.delete_works = delete_works
        self._present = True

    def status(self, refresh: bool = False):
        return {"admin": self.admin, "hostname": "HOST"}

    def raw_services(self, refresh: bool = False):
        if not self._present:
            return []
        return [
            {
                "name": "FakeSvc",
                "display_name": "Fake Service",
                "state": "Running",
                "start_mode": "Auto",
                "start_name": "LocalSystem",
                "service_type": "Own Process",
                "command_line": '"C:\\Windows\\System32\\fake.exe"',
                "process_id": 1,
            }
        ]

    def evidence(self, paths_list):
        return {}

    def invalidate(self):
        return None

    def run_action(self, payload, timeout=240):
        action = payload.get("action")
        if action == "contain":
            return {
                "ok": False,
                "steps": [
                    {"step": "stop", "ok": True, "message": "Service stopped."},
                    {"step": "disable", "ok": False, "message": "Access denied."},
                ],
            }
        if action == "restore":
            return {"ok": True, "steps": [{"step": "startup", "ok": True, "message": "restored"}]}
        if action == "delete":
            if self.delete_works:
                self._present = False
            return {"ok": True, "steps": [{"step": "delete", "ok": True, "message": "sc.exe exit 0"}]}
        return {"ok": True, "steps": [{"step": action, "ok": True, "message": "ok"}]}


def test_management_requires_elevation(data_dir):
    from sentinel.management import ManagementError as MgmtError

    collector = FakeManageCollector(admin=False)
    with pytest.raises(MgmtError, match="elevated"):
        from sentinel import management

        management.perform(collector, "FakeSvc", "stop", "FakeSvc")


def test_partial_containment_is_rolled_back(data_dir):
    from sentinel import management

    collector = FakeManageCollector()
    result = management.perform(collector, "FakeSvc", "contain", "FakeSvc")
    assert result["ok"] is False
    assert result["rolled_back"] is True
    rollback = [step for step in result["steps"] if step["step"] == "rollback"][0]
    assert rollback["ok"] is True
    assert result["backup"]["document"]["start_mode"] == "Auto"


def test_delete_is_verified(data_dir):
    from sentinel import management

    result = management.perform(FakeManageCollector(), "FakeSvc", "delete", "FakeSvc")
    assert result["ok"] is True
    assert any(step["step"] == "verify" and step["ok"] for step in result["steps"])


def test_stale_registration_is_reported_as_failure(data_dir):
    from sentinel import management

    result = management.perform(FakeManageCollector(delete_works=False), "FakeSvc", "delete", "FakeSvc")
    assert result["ok"] is False
    assert any(step["step"] == "verify" and not step["ok"] for step in result["steps"])


def test_prune_removes_expired_files_and_keeps_evidence_of_record(data_dir):
    old = data_dir / "inventory_20200101_000000.csv"
    old.write_text("x", encoding="utf-8")
    recent = data_dir / "assessment_20990101_000000.csv"
    recent.write_text("x", encoding="utf-8")
    current_baseline = data_dir / "baseline-latest.json"
    current_baseline.write_text("{}", encoding="utf-8")
    decisions = data_dir / "triage_decisions.jsonl"
    decisions.write_text("", encoding="utf-8")

    result = maintenance.prune(retention_days=30)

    assert not old.exists()
    assert recent.exists()
    assert current_baseline.exists()
    assert decisions.exists()
    assert result["removed_files"] == 1


def test_prune_caps_export_count(data_dir):
    for index in range(5):
        (data_dir / f"inventory_2025010{index + 1}_000000.csv").write_text("x", encoding="utf-8")
    maintenance.prune(retention_days=3650, max_exports=2)
    remaining = sorted(path.name for path in data_dir.glob("inventory_*.csv"))
    assert len(remaining) == 2
    assert remaining == ["inventory_20250104_000000.csv", "inventory_20250105_000000.csv"]
