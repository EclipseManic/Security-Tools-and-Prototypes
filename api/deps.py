"""Per-request dependencies."""

from __future__ import annotations

from typing import Iterator

from fastapi import Depends, Request

from api.auth import get_current_user
from core.run_service import RunService
from core.session_db import SessionDB


def get_db(request: Request) -> Iterator[SessionDB]:
    """One short-lived SQLite connection per request (WAL + busy timeout)."""
    db = SessionDB(request.app.state.db_path)
    try:
        yield db
    finally:
        db.close()


def get_service(db: SessionDB = Depends(get_db)) -> RunService:
    return RunService(db)


def current_user(name: str = Depends(get_current_user)) -> str:
    return name
