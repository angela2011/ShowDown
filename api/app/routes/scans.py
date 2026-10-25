from app.auth import current_user, owned_domain
from uuid import UUID
import json
from shared.targets import ownership_matches
from shared.time_utils import database_utc
import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from shared.models import Domain, Scan, ScanStatus
from app.schemas import ScanOut
from app.config import settings

router = APIRouter(prefix="/scans", tags=["scans"])
redis_client = redis.from_url(settings.redis_url, socket_connect_timeout=5, socket_timeout=10)


@router.post("/{domain_id}", response_model=ScanOut)
async def trigger_scan(domain_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    domain = await owned_domain(db, domain_id, user)
    if not domain.verified:
        raise HTTPException(status_code=403, detail="Domain not verified. Call /verify first.")

    try:
        authorized = await ownership_matches(domain.name, domain.verification_token)
    except Exception:
        raise HTTPException(status_code=503, detail="Ownership DNS lookup unavailable; no scan queued")
    if not authorized:
        domain.verified = False
        await db.commit()
        raise HTTPException(status_code=403, detail="Ownership TXT record no longer matches")
    scan = Scan(domain_id=domain.id, status=ScanStatus.queued)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # hand off to the worker pool
    job = {"scan_id": str(scan.id), "domain": domain.name}
    try:
        await redis_client.rpush(settings.scan_queue_name, json.dumps(job))
    except Exception:
        # The committed queued row is the durable outbox; worker recovery picks it up.
        pass

    return scan


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    scan = (await db.execute(select(Scan).join(Domain, Scan.domain_id == Domain.id).where(Scan.id == scan_id, Domain.owner_id == user.id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/domain/{domain_id}", response_model=list[ScanOut])
async def list_scans_for_domain(domain_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    await owned_domain(db, domain_id, user)
    result = await db.execute(select(Scan).where(Scan.domain_id == domain_id).order_by(Scan.created_at.desc()))
    return result.scalars().all()
