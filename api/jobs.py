"""
In-process background evaluation jobs.

Free-tier AI evaluation takes 25-40 s, so `/runs/{id}/finish` returns 202 and
the SPA polls `/runs/{id}/evaluation`. Jobs are intentionally process-local:
this is a single-user local app, and a DB row is the durable source of truth
after the job finishes.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from core.run_service import RunService
from core.session_db import SessionDB

_MAX_WORKERS = 2
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="evaluation")
_lock = threading.Lock()
_jobs: dict[int, "EvaluationJob"] = {}


def _stamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class EvaluationJob:
    run_id: int
    status: str = "queued"  # queued | running | done | failed
    queued_at: str = field(default_factory=_stamp)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    result: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "queued_at": self.queued_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "result": self.result,
        }


def _run_job(job: EvaluationJob, db_path: str, user_name: str) -> None:
    with _lock:
        job.status = "running"
        job.started_at = _stamp()

    db = SessionDB(db_path)
    try:
        result = RunService(db).finish(job.run_id, user_name=user_name)
        with _lock:
            job.status = "done"
            job.result = result
            job.finished_at = _stamp()
    except Exception as exc:  # noqa: BLE001 - surfaced to the polling client
        with _lock:
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = _stamp()
    finally:
        db.close()


def submit(run_id: int, db_path: str, user_name: str) -> EvaluationJob:
    """Queue evaluation, or return the existing job for this run."""
    with _lock:
        existing = _jobs.get(run_id)
        if existing and existing.status in ("queued", "running", "done"):
            return existing
        job = EvaluationJob(run_id=run_id)
        _jobs[run_id] = job

    _executor.submit(_run_job, job, db_path, user_name)
    return job


def get(run_id: int) -> Optional[EvaluationJob]:
    with _lock:
        return _jobs.get(run_id)


def shutdown() -> None:
    _executor.shutdown(wait=False, cancel_futures=True)
