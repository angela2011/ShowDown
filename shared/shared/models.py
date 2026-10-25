import uuid
from datetime import datetime
from shared.time_utils import database_utc

from sqlalchemy import String, Boolean, DateTime, ForeignKey, JSON, Enum, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class AuthThrottle(Base):
    __tablename__ = "auth_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    # NULL only for quarantined legacy domains; new registrations require an owner.
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    verification_token: Mapped[str] = mapped_column(String)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc)


class ScanSchedule(Base):
    __tablename__ = 'scan_schedules'
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('domains.id'), primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'))
    interval_minutes: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    next_run_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_outcome: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("domains.id"))
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # raw pipeline output, one blob per stage for easy inspection/debugging
    subdomains: Mapped[list[str] | dict | None] = mapped_column(JSON, nullable=True)
    open_ports: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    socket_findings: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tls_findings: Mapped[list[dict] | dict | None] = mapped_column(JSON, nullable=True)
    diff: Mapped[dict | None] = mapped_column(JSON, nullable=True)


# Decoys are independent of scans; all their records inherit sensor ownership.
class DecoySensor(Base):
    __tablename__ = 'decoy_sensors'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'), index=True)
    name: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    response_mode: Mapped[str] = mapped_column(String(12), default='disabled')
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc)


class DecoyEvent(Base):
    __tablename__ = 'decoy_events'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    sensor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('decoy_sensors.id'), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_verified: Mapped[bool] = mapped_column(Boolean)
    protocol: Mapped[str] = mapped_column(String(12))
    details: Mapped[dict] = mapped_column(JSON)
    confidence: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(12))
    reasons: Mapped[list] = mapped_column(JSON)


class DecoyBlock(Base):
    __tablename__ = 'decoy_blocks'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('decoy_sensors.id'), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('decoy_events.id'))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(12), default='active')
    reason: Mapped[str] = mapped_column(String(240))


class DecoyAudit(Base):
    __tablename__ = 'decoy_audit'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('decoy_sensors.id'), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=database_utc, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(40))
    details: Mapped[dict] = mapped_column(JSON)
