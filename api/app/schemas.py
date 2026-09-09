import uuid
from datetime import datetime
from pydantic import BaseModel


class DomainCreate(BaseModel):
    name: str


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
    subdomains: dict | None
    open_ports: dict | None
    socket_findings: dict | None
    tls_findings: dict | None
    diff: dict | None

    class Config:
        from_attributes = True
