from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.file import FileRecord, FileContent, FileCategory, FileSensitivity
from app.schemas.file import FileRecordResponse, SearchResponse

router = APIRouter(prefix="/search", tags=["search"])


@router.get("", response_model=SearchResponse)
async def search_files(
    q: str | None = Query(default=None),
    extension: str | None = Query(default=None),
    category: str | None = Query(default=None),
    sensitivity: str | None = Query(default=None),
    min_size: int | None = Query(default=None),
    max_size: int | None = Query(default=None),
    is_duplicate: bool | None = Query(default=None),
    has_content: bool | None = Query(default=None),
    sort_by: str = Query(default="name"),
    sort_order: str = Query(default="asc"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(FileRecord).distinct()

    if q:
        like_pattern = f"%{q}%"
        query = query.join(
            FileContent,
            FileRecord.id == FileContent.file_id,
            isouter=True,
        ).where(
            or_(
                FileRecord.name.ilike(like_pattern),
                FileRecord.path.ilike(like_pattern),
                FileContent.extracted_text.ilike(like_pattern),
                FileContent.summary.ilike(like_pattern),
            )
        )

    if extension:
        query = query.where(FileRecord.extension == extension)

    if category:
        query = query.join(
            FileCategory,
            FileRecord.id == FileCategory.file_id,
        ).where(FileCategory.category == category)

    if sensitivity:
        query = query.join(
            FileSensitivity,
            FileRecord.id == FileSensitivity.file_id,
        ).where(FileSensitivity.sensitivity_level == sensitivity)

    if min_size is not None:
        query = query.where(FileRecord.size >= min_size)

    if max_size is not None:
        query = query.where(FileRecord.size <= max_size)

    if is_duplicate is not None:
        if is_duplicate:
            query = query.where(FileRecord.duplicate_group_id.isnot(None))
        else:
            query = query.where(FileRecord.duplicate_group_id.is_(None))

    if has_content is not None:
        if has_content:
            query = query.join(
                FileContent,
                FileRecord.id == FileContent.file_id,
            ).where(FileContent.extracted_text.isnot(None))
        else:
            query = query.outerjoin(
                FileContent,
                FileRecord.id == FileContent.file_id,
            ).where(FileContent.extracted_text.is_(None))

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

    return SearchResponse(
        items=[FileRecordResponse.model_validate(f) for f in files],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )
