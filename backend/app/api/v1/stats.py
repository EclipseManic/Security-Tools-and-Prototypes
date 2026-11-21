from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.file import FileCategory, FileRecord, FileSensitivity, ScanJob

router = APIRouter(prefix="/stats", tags=["stats"])

DOC_EXTS = [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".rtf", ".odt"]
EXE_EXTS = [".exe", ".dll", ".msi", ".scr", ".bat", ".cmd"]
ARCHIVE_EXTS = [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"]
CODE_EXTS = [
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".cs",
    ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".sh", ".ps1",
]
IMAGE_EXTS = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".svg"]
MEDIA_EXTS = [".mp3", ".wav", ".flac", ".mp4", ".avi", ".mkv", ".mov", ".wmv"]


async def _scalar(db, stmt):
    try:
        val = await db.scalar(stmt)
        return int(val) if val is not None else 0
    except Exception:
        return 0


@router.get("/summary")
async def get_summary(db: AsyncSession = Depends(get_db)):
    F = FileRecord
    seven_days = datetime.now(timezone.utc) - timedelta(days=7)

    total_files = await _scalar(db, select(func.count(F.id)))
    total_storage = await _scalar(db, select(func.coalesce(func.sum(F.size), 0)))
    dupes = await _scalar(db, select(func.count(F.id)).where(F.duplicate_group_id.isnot(None)))
    docs = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(DOC_EXTS)))
    exes = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(EXE_EXTS)))
    archives = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(ARCHIVE_EXTS)))
    code_files = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(CODE_EXTS)))
    images = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(IMAGE_EXTS)))
    media_files = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(MEDIA_EXTS)))
    recent = await _scalar(db, select(func.count(F.id)).where(F.modified_at >= seven_days))
    sensitive = await _scalar(db, select(func.count(FileSensitivity.file_id)).where(
        FileSensitivity.sensitivity_level.in_(["Confidential", "Highly Confidential", "Critical"])))
    scans = await _scalar(db, select(func.count(ScanJob.id)))
    latest_scan_id = None
    latest_scan_path = None
    try:
        row = (await db.execute(
            select(ScanJob.id, ScanJob.path).order_by(ScanJob.id.desc()).limit(1)
        )).first()
        if row:
            latest_scan_id = row[0]
            latest_scan_path = row[1]
    except Exception:
        pass

    return {
        "total_files": total_files,
        "total_storage": total_storage,
        "duplicate_files": dupes,
        "document_files": docs,
        "executable_files": exes,
        "archive_files": archives,
        "source_code_files": code_files,
        "image_files": images,
        "media_files": media_files,
        "recently_modified": recent,
        "sensitive_files": sensitive,
        "scan_count": scans,
        "latest_scan_id": latest_scan_id,
        "latest_scan_path": latest_scan_path,
    }


@router.get("/distributions")
async def get_distributions(db: AsyncSession = Depends(get_db)):
    async def _run():
        F = FileRecord
        Ft = FileCategory
        Fs = FileSensitivity

        cat_rows = (await db.execute(
            select(Ft.category, func.count(Ft.file_id).label("c"))
            .group_by(Ft.category).order_by(func.count(Ft.file_id).desc())
        )).all()
        categories = [{"name": r[0], "value": r[1]} for r in cat_rows]

        sens_rows = (await db.execute(
            select(Fs.sensitivity_level, func.count(Fs.file_id).label("c"))
            .group_by(Fs.sensitivity_level).order_by(func.count(Fs.file_id).desc())
        )).all()
        sensitivity = [{"name": r[0], "value": r[1]} for r in sens_rows]

        ext_rows = (await db.execute(
            select(F.extension, func.count(F.id).label("c"))
            .where(F.extension.isnot(None))
            .group_by(F.extension).order_by(func.count(F.id).desc())
            .limit(20)
        )).all()
        extensions = [{"name": r[0], "value": r[1]} for r in ext_rows]

        docs = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(DOC_EXTS)))
        exes = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(EXE_EXTS)))
        code = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(CODE_EXTS)))
        images = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(IMAGE_EXTS)))
        media = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(MEDIA_EXTS)))
        archives = await _scalar(db, select(func.count(F.id)).where(F.extension.in_(ARCHIVE_EXTS)))

        return categories, sensitivity, extensions, [
            {"name": "Documents", "value": docs},
            {"name": "Executables", "value": exes},
            {"name": "Source Code", "value": code},
            {"name": "Images", "value": images},
            {"name": "Media", "value": media},
            {"name": "Archives", "value": archives},
        ]

    try:
        categories, sensitivity, extensions, ft = await _run()
    except Exception:
        return {"categories": [], "sensitivity": [], "extensions": [], "file_types": []}

    return {"categories": categories, "sensitivity": sensitivity, "extensions": extensions, "file_types": ft}
