"""Consistent JSON error envelope for the API."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    """Expected API failure with an explicit status and stable code."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail


def envelope(code: str, message: str, detail: Any = None) -> dict[str, Any]:
    return {"code": code, "message": message, "detail": detail}
