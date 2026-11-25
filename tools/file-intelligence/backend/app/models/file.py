from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class FileRecord(BaseModel):
    __tablename__ = "files"

    path: Mapped[str] = mapped_column(String(4096), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    extension: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mime_type: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    magic_bytes: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    accessed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    owner: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    permissions: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_hidden: Mapped[bool] = mapped_column(Boolean, default=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)
    is_readonly: Mapped[bool] = mapped_column(Boolean, default=False)
    is_symlink: Mapped[bool] = mapped_column(Boolean, default=False)
    volume: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    md5: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    entropy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    duplicate_group_id: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    scan_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("scan_jobs.id"), nullable=True, index=True
    )

    first_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    content = relationship(
        "FileContent", back_populates="file", uselist=False, cascade="all, delete-orphan"
    )
    category = relationship(
        "FileCategory", back_populates="file", uselist=False, cascade="all, delete-orphan"
    )
    sensitivity = relationship(
        "FileSensitivity",
        back_populates="file",
        uselist=False,
        cascade="all, delete-orphan",
    )
    sensitive_findings = relationship(
        "SensitiveFinding", back_populates="file", cascade="all, delete-orphan"
    )
    entities = relationship(
        "EntityExtraction", back_populates="file", cascade="all, delete-orphan"
    )
    technical_artifacts = relationship(
        "TechnicalArtifact", back_populates="file", cascade="all, delete-orphan"
    )
    analyses = relationship(
        "FileAnalysis", back_populates="file", cascade="all, delete-orphan"
    )
    timeline_events = relationship(
        "FileTimeline", back_populates="file", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_files_sha256_duplicate", "sha256", "duplicate_group_id"),
        Index("idx_files_path_extension", "path", "extension"),
    )


class FileContent(BaseModel):
    __tablename__ = "file_contents"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    extracted_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ocr_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detailed_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="content")


class FileCategory(BaseModel):
    __tablename__ = "file_categories"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    category: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    subcategory: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="category")


class FileSensitivity(BaseModel):
    __tablename__ = "file_sensitivities"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    sensitivity_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="Public"
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="sensitivity")


class SensitiveFinding(BaseModel):
    __tablename__ = "sensitive_findings"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    severity: Mapped[str] = mapped_column(String(16), default="medium")

    file = relationship("FileRecord", back_populates="sensitive_findings")

    __table_args__ = (
        Index("idx_finding_file_type", "file_id", "finding_type"),
    )


class EntityExtraction(BaseModel):
    __tablename__ = "entity_extractions"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_value: Mapped[str] = mapped_column(String(1024), nullable=False)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="entities")

    __table_args__ = (
        Index("idx_entity_file_type_value", "file_id", "entity_type", "entity_value"),
    )


class TechnicalArtifact(BaseModel):
    __tablename__ = "technical_artifacts"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="technical_artifacts")

    __table_args__ = (
        Index("idx_artifact_file_type_value", "file_id", "artifact_type", "value"),
    )


class FileAnalysis(BaseModel):
    __tablename__ = "file_analyses"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    analyzer_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="analyses")

    __table_args__ = (
        Index("idx_analysis_file_type", "file_id", "analyzer_type"),
    )


class FileTimeline(BaseModel):
    __tablename__ = "file_timeline"

    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    old_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    new_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    file = relationship("FileRecord", back_populates="timeline_events")

    __table_args__ = (
        Index("idx_timeline_file_time", "file_id", "event_time"),
    )


class ScanJob(BaseModel):
    __tablename__ = "scan_jobs"

    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    total_files: Mapped[int] = mapped_column(Integer, default=0)
    scanned_files: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class WatchFolder(BaseModel):
    __tablename__ = "watch_folders"

    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    recursive: Mapped[bool] = mapped_column(Boolean, default=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Setting(BaseModel):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(
        String(256), nullable=False, unique=True, index=True
    )
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
