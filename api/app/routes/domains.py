import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from shared.models import Domain
from app.schemas import DomainCreate, DomainOut

router = APIRouter(prefix="/domains", tags=["domains"])


@router.post("/", response_model=DomainOut)
async def register_domain(payload: DomainCreate, db: AsyncSession = Depends(get_db)):
    """Register a domain for monitoring. Not yet scannable until verified."""
    token = f"asm-verify={secrets.token_hex(16)}"
    domain = Domain(name=payload.name, verification_token=token, verified=False)
    db.add(domain)
    await db.commit()
    await db.refresh(domain)
    return domain


@router.get("/", response_model=list[DomainOut])
async def list_domains(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Domain))
    return result.scalars().all()


@router.get("/{domain_id}", response_model=DomainOut)
async def get_domain(domain_id: str, db: AsyncSession = Depends(get_db)):
    domain = await db.get(Domain, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return domain
