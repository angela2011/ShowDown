import uuid
from datetime import datetime, timezone
from pydantic import BaseModel, field_validator


class DomainCreate(BaseModel):
    name: str

    @field_validator('name')
    @classmethod
    def valid_name(cls, value):
        from shared.targets import normalize_domain
        return normalize_domain(value)


class DomainOut(BaseModel):
    id: uuid.UUID
    name: str
    verified: bool
    verification_token: str

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: uuid.UUID
    domain_id: uuid.UUID
    status: str
    created_at: datetime
    completed_at: datetime | None
    subdomains: list[str] | dict | None
    open_ports: dict | None
    socket_findings: dict | None
    tls_findings: list[dict] | dict | None
    diff: dict | None

    class Config:
        from_attributes = True

    @field_validator("created_at", "completed_at")
    @classmethod
    def timestamps_are_utc(cls, value):
        # Existing TIMESTAMP WITHOUT TIME ZONE rows have always represented UTC.
        # Attach UTC on output; do not rewrite or reinterpret stored wall times.
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
