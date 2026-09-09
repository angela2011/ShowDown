import json
import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from shared.models import Domain, Scan, ScanStatus
from app.schemas import ScanOut
from app.config import settings

router = APIRouter(prefix="/scans", tags=["scans"])
redis_client = redis.from_url(settings.redis_url)


@router.post("/{domain_id}", response_model=ScanOut)
async def trigger_scan(domain_id: str, db: AsyncSession = Depends(get_db)):
    domain = await db.get(Domain, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    if not domain.verified:
        raise HTTPException(status_code=403, detail="Domain not verified. Call /verify first.")

    scan = Scan(domain_id=domain.id, status=ScanStatus.queued)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # hand off to the worker pool
    job = {"scan_id": str(scan.id), "domain": domain.name}
    await redis_client.rpush(settings.scan_queue_name, json.dumps(job))

    return scan


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/domain/{domain_id}", response_model=list[ScanOut])
async def list_scans_for_domain(domain_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.domain_id == domain_id).order_by(Scan.created_at.desc()))
    return result.scalars().all()
