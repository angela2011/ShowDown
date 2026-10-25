"""Owner-authorized recurring scans; no anonymous scheduler HTTP endpoint."""
from datetime import timedelta, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select
from app.auth import current_user
from app.database import get_db
from shared.models import Domain, ScanSchedule
from shared.time_utils import database_utc

router = APIRouter(prefix='/schedules', tags=['schedules'])

class ScheduleInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    interval_minutes: int = Field(ge=60, le=43200, strict=True)
    enabled: bool = False

def output(schedule):
    return {name: (value.replace(tzinfo=timezone.utc) if name.endswith('_at') and value else value)
            for name in ('domain_id', 'interval_minutes', 'enabled', 'next_run_at',
                         'last_checked_at', 'last_outcome', 'last_scan_id')
            for value in [getattr(schedule, name)]}

async def domain_for_user(db, domain_id, user):
    domain = (await db.execute(select(Domain).where(Domain.id == domain_id,
        Domain.owner_id == user.id).with_for_update())).scalar_one_or_none()
    if domain is None:
        raise HTTPException(404, 'Domain not found')
    return domain

@router.get('/{domain_id}')
async def get_schedule(domain_id: UUID, db=Depends(get_db), user=Depends(current_user)):
    await domain_for_user(db, domain_id, user)
    schedule = await db.get(ScanSchedule, domain_id)
    if not schedule or schedule.owner_id != user.id:
        raise HTTPException(404, 'Schedule not found')
    return output(schedule)

@router.put('/{domain_id}')
async def set_schedule(domain_id: UUID, body: ScheduleInput, db=Depends(get_db), user=Depends(current_user)):
    domain = await domain_for_user(db, domain_id, user)
    if body.enabled and not domain.verified:
        raise HTTPException(403, 'Verify domain ownership before enabling scheduled scans')
    schedule = await db.get(ScanSchedule, domain_id)
    if schedule is None:
        schedule = ScanSchedule(domain_id=domain.id, owner_id=user.id)
        db.add(schedule)
    schedule.owner_id = user.id
    schedule.interval_minutes = body.interval_minutes
    schedule.enabled = body.enabled
    schedule.next_run_at = database_utc() + timedelta(minutes=body.interval_minutes)
    schedule.last_outcome = 'configured'
    await db.commit()
    return output(schedule)
