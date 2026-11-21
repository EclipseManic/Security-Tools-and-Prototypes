from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class FileRecordResponse(BaseModel):
    id: int
    path: str
    name: str
    extension: Optional[str] = None
    size: int = 0
    mime_type: Optional[str] = None
    magic_bytes: Optional[str] = None
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    accessed_at: Optional[datetime] = None
    owner: Optional[str] = None
    permissions: Optional[str] = None
    is_hidden: bool = False
    is_system: bool = False
    is_readonly: bool = False
    is_symlink: bool = False
    volume: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    entropy: Optional[float] = None
    duplicate_group_id: Optional[str] = None
    first_scanned_at: Optional[datetime] = None
    last_scanned_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class FileDetailResponse(FileRecordResponse):
    content: Optional["FileContentResponse"] = None
    category: Optional["FileCategoryResponse"] = None
    sensitivity: Optional["FileSensitivityResponse"] = None
    sensitive_findings: list["SensitiveFindingResponse"] = []
    entities: list["EntityExtractionResponse"] = []
    technical_artifacts: list["TechnicalArtifactResponse"] = []
    analyses: list["FileAnalysisResponse"] = []
    timeline_events: list["FileTimelineResponse"] = []


class FileContentResponse(BaseModel):
    extracted_text: Optional[str] = None
    ocr_text: Optional[str] = None
    raw_metadata: Optional[dict] = None
    summary: Optional[str] = None
    detailed_summary: Optional[str] = None

    model_config = {"from_attributes": True}


class FileCategoryResponse(BaseModel):
    category: str
    subcategory: Optional[str] = None
    confidence: float = 0.0
    explanation: Optional[str] = None

    model_config = {"from_attributes": True}


class FileSensitivityResponse(BaseModel):
    sensitivity_level: str = "Public"
    risk_score: float = 0.0
    explanation: Optional[str] = None

    model_config = {"from_attributes": True}


class SensitiveFindingResponse(BaseModel):
    finding_type: str
    value: Optional[str] = None
    context: Optional[str] = None
    count: int = 1
    severity: str = "medium"

    model_config = {"from_attributes": True}


class EntityExtractionResponse(BaseModel):
    entity_type: str
    entity_value: str
    context: Optional[str] = None

    model_config = {"from_attributes": True}


class TechnicalArtifactResponse(BaseModel):
    artifact_type: str
    value: str
    context: Optional[str] = None

    model_config = {"from_attributes": True}


class FileAnalysisResponse(BaseModel):
    analyzer_type: str
    status: str = "pending"
    result: Optional[dict] = None
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}


class FileTimelineResponse(BaseModel):
    event_type: str
    event_time: datetime
    old_value: Optional[str] = None
    new_value: Optional[str] = None

    model_config = {"from_attributes": True}


class ScanJobCreate(BaseModel):
    path: str
    scan_type: str = "full"


class ScanJobResponse(BaseModel):
    id: int
    scan_type: str
    path: str
    status: str = "pending"
    progress: float = 0.0
    total_files: int = 0
    scanned_files: int = 0
    error_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class SearchQuery(BaseModel):
    q: Optional[str] = None
    extensions: Optional[list[str]] = None
    mime_types: Optional[list[str]] = None
    categories: Optional[list[str]] = None
    sensitivity_levels: Optional[list[str]] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    owner: Optional[str] = None
    is_hidden: Optional[bool] = None
    is_duplicate: Optional[bool] = None
    has_passwords: Optional[bool] = None
    has_api_keys: Optional[bool] = None
    has_sql: Optional[bool] = None
    sort_by: str = "name"
    sort_order: str = "asc"
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


class SearchResponse(BaseModel):
    items: list[FileRecordResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class DashboardSummary(BaseModel):
    total_files: int = 0
    total_storage: int = 0
    sensitive_files: int = 0
    duplicate_files: int = 0
    executable_files: int = 0
    document_files: int = 0
    archive_files: int = 0
    source_code_files: int = 0
    image_files: int = 0
    media_files: int = 0
    recently_modified: int = 0
    scan_count: int = 0
