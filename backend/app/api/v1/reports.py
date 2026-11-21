from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.report.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
async def list_reports(db: AsyncSession = Depends(get_db)):
    service = ReportService(db)
    reports = await service.get_available_reports()
    return {"items": reports, "total": len(reports)}


@router.get("/{report_type}")
async def download_report(
    report_type: str,
    fmt: str = Query("json", description="Output format"),
    db: AsyncSession = Depends(get_db),
):
    service = ReportService(db)
    try:
        content, media_type, filename = await service.generate_report(report_type, fmt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
