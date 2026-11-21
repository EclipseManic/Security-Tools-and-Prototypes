"""
Signed-cookie auth for local single-user mode.

There is no password: the cookie only carries the chosen profile name and is
signed with a local secret. The secret lives in `.session_secret` (gitignored)
or `SOC_SESSION_SECRET`, so restarts keep sessions valid on the same machine.
"""

from __future__ import annotations

import os
import secrets
from typing import Optional

from fastapi import Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from api.errors import ApiError
from config import BASE_DIR

SESSION_COOKIE = "soc_session"
SESSION_MAX_AGE = 30 * 24 * 60 * 60  # 30 days
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "SOC-Trainer"


def _load_secret() -> str:
    env = (os.getenv("SOC_SESSION_SECRET") or "").strip()
    if env:
        return env

    path = BASE_DIR / ".session_secret"
    try:
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        value = secrets.token_urlsafe(48)
        path.write_text(value, encoding="utf-8")
        return value
    except OSError:
        # Read-only install: still work, but sessions end at process restart.
        return secrets.token_urlsafe(48)


_SECRET = _load_secret()
_SERIALIZER = URLSafeTimedSerializer(_SECRET, salt="soc-trainer-session")


def sign_session(name: str) -> str:
    return _SERIALIZER.dumps({"name": name})


def verify_session(token: str) -> Optional[str]:
    try:
        payload = _SERIALIZER.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(payload, dict):
        return None
    name = str(payload.get("name") or "").strip()
    return name or None


def set_session_cookie(response: Response, name: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        sign_session(name),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=(os.getenv("SOC_COOKIE_SECURE", "0") == "1"),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def get_current_user(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE)
    name = verify_session(token) if token else None
    if not name:
        raise ApiError(401, "unauthenticated", "Create a local session first.")
    return name
