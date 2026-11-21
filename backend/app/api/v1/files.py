from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.file import FileRecord, FileSensitivity
from app.schemas.file import FileDetailResponse, FileRecordResponse

router = APIRouter(prefix="/files", tags=["files"])

DOC_EXTS = [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".rtf", ".odt"]
EXE_EXTS = [".exe", ".dll", ".msi", ".scr", ".bat", ".cmd"]
ARCHIVE_EXTS = [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"]
CODE_EXTS = [
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".cs",
    ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".sh", ".ps1",
]
IMAGE_EXTS = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg"]
MEDIA_EXTS = [".mp3", ".wav", ".flac", ".mp4", ".avi", ".mkv", ".mov", ".wmv"]


def _apply_category_filter(query, category: str):
    seven_days = datetime.now(timezone.utc) - timedelta(days=7)
    if category == "documents":
        return query.where(FileRecord.extension.in_(DOC_EXTS))
    elif category == "executables":
        return query.where(FileRecord.extension.in_(EXE_EXTS))
    elif category == "archives":
        return query.where(FileRecord.extension.in_(ARCHIVE_EXTS))
    elif category == "source_code":
        return query.where(FileRecord.extension.in_(CODE_EXTS))
    elif category == "images":
        return query.where(FileRecord.extension.in_(IMAGE_EXTS))
    elif category == "media":
        return query.where(FileRecord.extension.in_(MEDIA_EXTS))
    elif category == "sensitive":
        from sqlalchemy import exists
        return query.where(
            exists(
                select(FileSensitivity.file_id).where(
                    FileSensitivity.file_id == FileRecord.id,
                    FileSensitivity.sensitivity_level.in_(
                        ["Confidential", "Highly Confidential", "Critical"]
                    ),
                )
            )
        )
    elif category == "duplicates":
        return query.where(FileRecord.duplicate_group_id.isnot(None))
    elif category == "recently_modified":
        return query.where(FileRecord.modified_at >= seven_days)
    return query


@router.get("")
async def list_files(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    sort_by: str = Query(default="name"),
    sort_order: str = Query(default="asc"),
    extension: str | None = Query(default=None),
    category: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    query = select(FileRecord)

    if extension:
        query = query.where(FileRecord.extension == extension)

    if category:
        query = _apply_category_filter(query, category)

    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    sort_col = getattr(FileRecord, sort_by, FileRecord.name)
    if sort_order == "desc":
        sort_col = sort_col.desc()
    query = query.order_by(sort_col)

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    files = result.scalars().all()

    return {
        "items": [FileRecordResponse.model_validate(f) for f in files],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/{file_id}", response_model=FileDetailResponse)
async def get_file(file_id: int, db: AsyncSession = Depends(get_db)):
    query = (
        select(FileRecord)
        .where(FileRecord.id == file_id)
        .options(
            selectinload(FileRecord.content),
            selectinload(FileRecord.category),
            selectinload(FileRecord.sensitivity),
            selectinload(FileRecord.sensitive_findings),
            selectinload(FileRecord.entities),
            selectinload(FileRecord.technical_artifacts),
            selectinload(FileRecord.analyses),
            selectinload(FileRecord.timeline_events),
        )
    )
    result = await db.execute(query)
    file_record = result.scalar_one_or_none()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    return file_record
