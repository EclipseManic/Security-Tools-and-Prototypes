from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import async_session_factory, init_db
from app.main import app
from app.models.file import FileRecord


@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()


@pytest.mark.asyncio
async def test_distributions_account_for_every_file():
    async with async_session_factory() as db:
        db.add_all(
            [
                FileRecord(path="/tmp/fip-stats-a.txt", name="a.txt", extension=".txt", size=1),
                FileRecord(path="/tmp/fip-stats-b.bin", name="b.bin", extension=".bin", size=1),
            ]
        )
        await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        summary = (await client.get("/api/v1/stats/summary")).json()
        response = await client.get("/api/v1/stats/distributions")

    assert response.status_code == 200
    body = response.json()
    total = summary["total_files"]

    # Both series must cover the same files, and no file may silently vanish
    # because it had no analyzer result.
    assert sum(item["value"] for item in body["file_types"]) == total
    assert sum(item["value"] for item in body["categories"]) == total
    assert body["file_types"] == body["categories"]
    assert any(item["name"] == "Uncategorized" and item["value"] >= 2 for item in body["categories"])
