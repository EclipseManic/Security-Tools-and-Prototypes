"""Shared test configuration.

The application reads its database URL at import time, so point it at a
temporary file before any app module is imported. Tests must never touch the
developer's real ``backend/data/fip.db``.
"""

from __future__ import annotations

import os
import shutil
import tempfile

_TEST_DIR = tempfile.mkdtemp(prefix="fip-tests-")

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DIR}/fip-test.db"
os.environ["AI_PROVIDER"] = "none"
os.environ["WATCH_ENABLED"] = "false"
os.environ["LOG_LEVEL"] = "WARNING"
for _key in (
    "GEMINI_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "BAZAARLINK_API_KEY",
):
    os.environ.pop(_key, None)


def pytest_sessionfinish(session, exitstatus):  # noqa: ANN001
    shutil.rmtree(_TEST_DIR, ignore_errors=True)
