from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, async_session_factory
from app.core.logging import get_logger
from app.models.insight import ScanInsight
from app.schemas.file import ScanJobCreate, ScanJobResponse
from app.services.scanner.scan_service import ScanService

logger = get_logger(__name__)
router = APIRouter(prefix="/scans", tags=["scans"])


async def _run_scan_background(scan_id: int):
    try:
        async with async_session_factory() as db:
            service = ScanService(db)
            await service.start_scan(scan_id)
    except Exception as e:
        logger.error("Background scan %d failed: %s", scan_id, e)


@router.post("", response_model=ScanJobResponse)
async def create_scan(body: ScanJobCreate, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    job = await service.create_scan_job(path=body.path, scan_type=body.scan_type)
    return job


@router.get("")
async def list_scans(db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    jobs = await service.list_scan_jobs()
    return {"items": [ScanJobResponse.model_validate(j) for j in jobs], "total": len(jobs)}


@router.get("/{scan_id}", response_model=ScanJobResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    progress = await service.get_scan_progress(scan_id)
    if not progress:
        raise HTTPException(status_code=404, detail="Scan not found")
    return progress


@router.get("/{scan_id}/insights")
async def get_scan_insights(scan_id: int, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select

    result = await db.execute(
        select(ScanInsight).where(ScanInsight.scan_job_id == scan_id).order_by(ScanInsight.insight_type)
    )
    insights = result.scalars().all()
    grouped: dict[str, dict] = {}
    for ins in insights:
        if ins.insight_type not in grouped:
            grouped[ins.insight_type] = {"type": ins.insight_type, "content": ins.content, "created_at": str(ins.created_at) if ins.created_at else None}
    if not grouped:
        return {"insights": [], "has_ai_data": False}
    return {"insights": list(grouped.values()), "has_ai_data": True}


@router.post("/{scan_id}/start")
async def start_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    from app.models.file import ScanJob

    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    asyncio.create_task(_run_scan_background(scan_id))
    return {"status": "started"}


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    paused = await service.pause_scan(scan_id)
    if not paused:
        raise HTTPException(status_code=404, detail="Active scan not found")
    return {"status": "paused"}


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    resumed = await service.resume_scan(scan_id)
    if not resumed:
        raise HTTPException(status_code=404, detail="Paused scan not found")
    return {"status": "resumed"}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    cancelled = await service.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Active scan not found")
    return {"status": "cancelled"}


@router.delete("/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    service = ScanService(db)
    deleted = await service.delete_scan_job(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted"}
