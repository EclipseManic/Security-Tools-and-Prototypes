from __future__ import annotations

from typing import Optional

from sqlalchemy import ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import BaseModel


class ScanInsight(BaseModel):
    __tablename__ = "scan_insights"

    scan_job_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    insight_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    content: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="ai")
