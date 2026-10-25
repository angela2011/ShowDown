"""Owner-scoped decoy control plane; no scan mutation or cloud management calls."""
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, func
from app.auth import current_user
from app.database import get_db
from shared.models import User, DecoySensor, DecoyEvent, DecoyBlock, DecoyAudit
from shared.time_utils import database_utc
from shared.honeypot import confidence, protected_ip

router = APIRouter(prefix='/honeypots', tags=['honeypots'])
log = logging.getLogger('showdown.decoy')
log.setLevel(logging.INFO)
if not log.handlers:
    log.addHandler(logging.StreamHandler())
log.propagate = False


def response_enabled():
    return os.getenv('HONEYPOT_RESPONSE_ENABLED', 'false').lower() == 'true'


def protected_networks():
    values = [s.strip() for s in os.getenv('HONEYPOT_PROTECTED_CIDRS', '').split(',') if s.strip()]
    try:
        for cidr in values:
            ipaddress.ip_network(cidr)
    except ValueError:
        raise HTTPException(503, 'Invalid protected networks; responses disabled')
    return values


def stamp(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value else None


def output(row):
    data = {c.name: getattr(row, c.name) for c in row.__table__.columns if c.name != 'token_hash'}
    return {k: stamp(v) if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v for k, v in data.items()}


def audit(db, sensor, actor, action, details):
    db.add(DecoyAudit(sensor_id=sensor.id, actor=str(actor), action=action, details=details))
    db.info.setdefault('decoy_audit_log', []).append({'component': 'honeypot', 'sensor_id': str(sensor.id),
        'actor': str(actor), 'action': action, 'details': details})


async def save(db):
    await db.commit()
    for record in db.info.pop('decoy_audit_log', []):
        log.info(json.dumps(record))


async def owned(db, identifier, user):
    sensor = (await db.execute(select(DecoySensor).where(DecoySensor.id == identifier, DecoySensor.owner_id == user.id).with_for_update())).scalar_one_or_none()
    if not sensor:
        raise HTTPException(404, 'Sensor not found')
    return sensor


async def sensor_auth(authorization: str = Header(default=''), db=Depends(get_db)):
    token = authorization.removeprefix('Bearer ')
    if not authorization.startswith('Bearer ') or len(token) != 43:
        raise HTTPException(401, 'Invalid sensor credential')
    digest = hashlib.sha256(token.encode()).hexdigest()
    sensor = (await db.execute(select(DecoySensor).join(User, User.id == DecoySensor.owner_id).where(
        DecoySensor.token_hash == digest, DecoySensor.enabled.is_(True), User.active.is_(True)).with_for_update())).scalar_one_or_none()
    if not sensor:
        raise HTTPException(401, 'Invalid sensor credential')
    return sensor


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class SensorCreate(Strict):
    name: str = Field(min_length=1, max_length=80)


class Policy(Strict):
    mode: Literal['disabled', 'manual', 'auto']


class Details(Strict):
    bytes_received: int = Field(ge=0, le=4096)
    payload_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    signals: list[Literal['credential_probe', 'path_traversal', 'shell_pattern']] = Field(default_factory=list, max_length=3)
    method: Literal['GET', 'POST', 'HEAD', 'OTHER', 'NONE'] = 'NONE'
    path_category: Literal['sensitive', 'other', 'none'] = 'none'
    outcome: Literal['observed', 'timeout', 'blocked', 'read_error'] = 'observed'
    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)


class EventIn(Strict):
    id: uuid.UUID
    observed_at: datetime
    source_ip: str
    source_verified: bool = False
    protocol: Literal['http', 'tcp']
    details: Details

    @field_validator('source_ip')
    @classmethod
    def ip(cls, value):
        return str(ipaddress.ip_address(value))

    @field_validator('observed_at')
    @classmethod
    def timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError('Timezone offset required')
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
        if value > database_utc() + timedelta(minutes=5):
            raise ValueError('Future timestamp')
        return value


class Decision(Strict):
    source_ip: str

    @field_validator('source_ip')
    @classmethod
    def ip(cls, value):
        return str(ipaddress.ip_address(value))


class BlockIn(Strict):
    event_id: uuid.UUID
    confirm_ip: str
    ttl_seconds: int = Field(default=300, ge=60, le=3600)
    reason: str = Field(min_length=10, max_length=240)


async def expire(db, sensor):
    rows = (await db.execute(select(DecoyBlock).where(DecoyBlock.sensor_id == sensor.id, DecoyBlock.status == 'active', DecoyBlock.expires_at <= database_utc()).with_for_update())).scalars().all()
    for row in rows:
        row.status = 'expired'
        audit(db, sensor, 'system', 'block_expired', {'block_id': str(row.id), 'expired_at': stamp(row.expires_at)})


async def add_block(db, sensor, event, actor, ttl, reason, request_ip=None):
    networks = protected_networks()
    why = None
    if not response_enabled() or sensor.response_mode == 'disabled':
        why = 'Responses disabled'
    elif not networks:
        why = 'Configure protected admin/health-check networks before enabling responses'
    elif not event.source_verified:
        why = 'Source IP attribution is not verified'
    elif protected_ip(event.source_ip, networks):
        why = 'Protected or non-public IP'
    elif event.source_ip == request_ip:
        why = 'Cannot block the requesting operator'
    elif event.confidence < 70:
        why = 'Confidence below manual response threshold (70)'
    elif event.observed_at < database_utc() - timedelta(minutes=10):
        why = 'Evidence is too old'
    if why:
        audit(db, sensor, actor, 'block_refused', {'event_id': str(event.id), 'reason': why})
        return None, why
    await expire(db, sensor)
    existing = (await db.execute(select(DecoyBlock).where(DecoyBlock.sensor_id == sensor.id, DecoyBlock.source_ip == event.source_ip, DecoyBlock.status == 'active', DecoyBlock.expires_at > database_utc()))).scalar_one_or_none()
    if existing:
        return existing, None
    count = await db.scalar(select(func.count()).select_from(DecoyBlock).where(DecoyBlock.sensor_id == sensor.id, DecoyBlock.status == 'active', DecoyBlock.expires_at > database_utc()))
    if count >= 100:
        audit(db, sensor, actor, 'block_refused', {'reason': '100 active blocks limit reached'})
        return None, '100 active blocks limit reached'
    block = DecoyBlock(id=uuid.uuid4(), sensor_id=sensor.id, source_ip=event.source_ip, event_id=event.id,
                       expires_at=database_utc()+timedelta(seconds=ttl), reason=reason)
    db.add(block)
    audit(db, sensor, actor, 'block_created', {'block_id': str(block.id), 'source_ip': event.source_ip,
          'expires_at': stamp(block.expires_at), 'scope': 'decoy-only'})
    return block, None


@router.post('/sensors', status_code=201)
async def create(payload: SensorCreate, db=Depends(get_db), user=Depends(current_user)):
    if await db.scalar(select(func.count()).select_from(DecoySensor).where(DecoySensor.owner_id == user.id)) >= 20:
        raise HTTPException(409, 'Sensor limit reached')
    token = secrets.token_urlsafe(32)
    sensor = DecoySensor(id=uuid.uuid4(), owner_id=user.id, name=payload.name,
                        token_hash=hashlib.sha256(token.encode()).hexdigest(), response_mode='disabled')
    db.add(sensor)
    await db.flush()
    audit(db, sensor, user.id, 'sensor_created', {})
    await save(db)
    return {**output(sensor), 'sensor_token': token}


@router.get('/sensors')
async def sensors(db=Depends(get_db), user=Depends(current_user)):
    return [output(s) for s in (await db.execute(select(DecoySensor).where(DecoySensor.owner_id == user.id))).scalars()]


@router.post('/sensors/{sensor_id}/policy')
async def policy(sensor_id: uuid.UUID, payload: Policy, db=Depends(get_db), user=Depends(current_user)):
    sensor = await owned(db, sensor_id, user)
    if payload.mode != 'disabled' and (not response_enabled() or not protected_networks()):
        audit(db, sensor, user.id, 'policy_refused', {'mode': payload.mode})
        await save(db)
        raise HTTPException(409, 'Response flag and protected networks must be configured by operator')
    sensor.response_mode = payload.mode
    audit(db, sensor, user.id, 'policy_changed', {'mode': payload.mode})
    await save(db)
    return output(sensor)


@router.post('/sensors/{sensor_id}/revoke')
async def revoke(sensor_id: uuid.UUID, db=Depends(get_db), user=Depends(current_user)):
    sensor = await owned(db, sensor_id, user)
    sensor.enabled = False
    audit(db, sensor, user.id, 'sensor_revoked', {})
    await save(db)
    return {'enabled': False}


@router.post('/ingest')
async def ingest(payload: EventIn, db=Depends(get_db), sensor=Depends(sensor_auth)):
    existing = await db.get(DecoyEvent, payload.id)
    if existing:
        if existing.sensor_id != sensor.id:
            raise HTTPException(409, 'Event ID conflict')
        return output(existing)
    now = database_utc()
    # PostgreSQL sensor row lock serializes ingestion and response decisions.
    count = await db.scalar(select(func.count()).select_from(DecoyEvent).where(DecoyEvent.sensor_id == sensor.id, DecoyEvent.received_at >= now-timedelta(minutes=1)))
    if count >= 120:
        raise HTTPException(429, 'Sensor ingestion limit reached', headers={'Retry-After': '60'})
    recent = await db.scalar(select(func.count()).select_from(DecoyEvent).where(DecoyEvent.sensor_id == sensor.id, DecoyEvent.source_ip == payload.source_ip, DecoyEvent.observed_at >= now-timedelta(minutes=10)))
    details = payload.details.model_dump()
    score, severity, reasons = confidence(details, recent+1 if payload.observed_at >= now-timedelta(minutes=10) else 0)
    event = DecoyEvent(**payload.model_dump(exclude={'details'}), sensor_id=sensor.id, details=details,
                       confidence=score, severity=severity, reasons=reasons)
    db.add(event)
    await db.flush()
    audit(db, sensor, 'sensor', 'detection', {'event_id': str(event.id), 'confidence': score, 'severity': severity})
    if details['outcome'] == 'blocked':
        audit(db, sensor, 'sensor', 'block_enforcement_reported', {'event_id': str(event.id), 'source_ip': event.source_ip})
    if sensor.response_mode == 'auto' and response_enabled() and score >= 90 and recent >= 2 and payload.observed_at >= now-timedelta(minutes=2):
        await add_block(db, sensor, event, 'automatic', 300, 'Automatic high-confidence decoy response')
    await save(db)
    return output(event)


@router.post('/decision')
async def decision(payload: Decision, db=Depends(get_db), sensor=Depends(sensor_auth)):
    await expire(db, sensor)
    block = (await db.execute(select(DecoyBlock).where(DecoyBlock.sensor_id == sensor.id, DecoyBlock.source_ip == payload.source_ip, DecoyBlock.status == 'active', DecoyBlock.expires_at > database_utc()))).scalar_one_or_none()
    networks = protected_networks()
    blocked = bool(response_enabled() and sensor.response_mode != 'disabled' and networks and not protected_ip(payload.source_ip, networks) and block)
    if blocked:
        audit(db, sensor, 'sensor', 'block_decision', {'block_id': str(block.id), 'source_ip': payload.source_ip})
    await save(db)
    return {'blocked': blocked, 'expires_at': stamp(block.expires_at) if blocked else None, 'scope': 'decoy-only'}


@router.post('/sensors/{sensor_id}/blocks', status_code=201)
async def block(sensor_id: uuid.UUID, payload: BlockIn, request: Request, db=Depends(get_db), user=Depends(current_user)):
    sensor = await owned(db, sensor_id, user)
    event = await db.get(DecoyEvent, payload.event_id)
    if not event or event.sensor_id != sensor.id:
        raise HTTPException(404, 'Event not found')
    if payload.confirm_ip != event.source_ip:
        audit(db, sensor, user.id, 'block_refused', {'reason': 'IP confirmation mismatch'})
        await save(db)
        raise HTTPException(409, 'Confirm the exact observed IP')
    result, error = await add_block(db, sensor, event, user.id, payload.ttl_seconds, payload.reason,
                                    request.client.host if request.client else None)
    await save(db)
    if error:
        raise HTTPException(409, error)
    return output(result)


@router.post('/sensors/{sensor_id}/blocks/{block_id}/unblock')
async def unblock(sensor_id: uuid.UUID, block_id: uuid.UUID, db=Depends(get_db), user=Depends(current_user)):
    sensor = await owned(db, sensor_id, user)
    block = await db.get(DecoyBlock, block_id)
    if not block or block.sensor_id != sensor.id:
        raise HTTPException(404, 'Block not found')
    if block.status == 'active':
        block.status = 'revoked'
        block.revoked_at = database_utc()
        audit(db, sensor, user.id, 'block_revoked', {'block_id': str(block.id)})
    await save(db)
    return output(block)


@router.get('/sensors/{sensor_id}/{kind}')
async def history(sensor_id: uuid.UUID, kind: Literal['events', 'blocks', 'audit'],
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000),
                  db=Depends(get_db), user=Depends(current_user)):
    sensor = await owned(db, sensor_id, user)
    await expire(db, sensor)
    await save(db)
    model = {'events': DecoyEvent, 'blocks': DecoyBlock, 'audit': DecoyAudit}[kind]
    order = model.received_at if kind == 'events' else model.created_at
    rows = list((await db.execute(select(model).where(model.sensor_id == sensor.id).order_by(order.desc(), model.id.desc()).offset(offset).limit(limit+1))).scalars())
    return {'items': [output(row) for row in rows[:limit]], 'next_offset': offset+limit if len(rows) > limit else None}
