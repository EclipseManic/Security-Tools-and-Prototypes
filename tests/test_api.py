"""API contract tests: health, facets, CSRF, and secret handling."""

from __future__ import annotations

import config
from fastapi.testclient import TestClient

from api.app import create_app

CSRF = {"X-Requested-With": "SOC-Trainer"}
SECRET = "sk-or-v1-test-secret-that-must-not-leak"


def make_client(tmp_path) -> TestClient:
    return TestClient(create_app(str(tmp_path / "test.db")))


def test_health_reports_scenario_count(tmp_path):
    with make_client(tmp_path) as client:
        response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["scenarios"] == 133


def test_library_facets_cover_every_difficulty_and_domain(tmp_path):
    with make_client(tmp_path) as client:
        response = client.get("/api/v1/scenarios", params={"limit": 1})
    assert response.status_code == 200
    facets = response.json()["facets"]
    assert set(facets["difficulties"]) == {
        "Easy",
        "Medium",
        "Hard",
        "Expert",
        "Critical",
    }
    assert sum(facets["difficulties"].values()) == 133
    assert list(facets["domains"])[0] == "Endpoint"
    assert sum(facets["domains"].values()) == 133


def test_library_starts_with_endpoint_scenarios(tmp_path):
    with make_client(tmp_path) as client:
        response = client.get("/api/v1/scenarios", params={"limit": 12})
    items = response.json()["items"]
    assert items[0]["category"] == "Endpoint"
    assert all(item["category"] == "Endpoint" for item in items)


def test_mutating_request_requires_csrf_header(tmp_path):
    with make_client(tmp_path) as client:
        response = client.post(
            "/api/v1/session",
            json={"name": "Analyst", "role": "analyst", "domains": []},
        )
    assert response.status_code == 403
    assert response.json()["code"] == "csrf_required"


def test_session_round_trip(tmp_path):
    with make_client(tmp_path) as client:
        created = client.post(
            "/api/v1/session",
            headers=CSRF,
            json={"name": "Analyst", "role": "analyst", "domains": []},
        )
        assert created.status_code == 201
        assert created.json()["user"]["name"] == "Analyst"

        me = client.get("/api/v1/me")
        assert me.status_code == 200
        assert me.json()["user"]["role"] == "analyst"

        anonymous = TestClient(create_app(str(tmp_path / "test.db")))
        assert anonymous.get("/api/v1/me").status_code == 401


def test_settings_never_return_the_api_key(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OPENROUTER_API_KEY", SECRET)
    with make_client(tmp_path) as client:
        response = client.get("/api/v1/settings")
    assert response.status_code == 200
    assert response.json()["api_key_configured"] is True
    assert SECRET not in response.text
    assert "api_key" not in {key for key in response.json() if key != "api_key_configured"}
