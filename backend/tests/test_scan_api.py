from __future__ import annotations

import os

import pytest
from httpx import AsyncClient, ASGITransport

from app.core.database import init_db
from app.main import app


@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_create_and_list_scans(client):
    response = await client.post(
        "/api/v1/scans",
        json={"path": os.path.expanduser("~"), "scan_type": "full"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["path"] is not None
    assert data["status"] == "pending"

    list_resp = await client.get("/api/v1/scans")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1
