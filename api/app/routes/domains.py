from app.auth import current_user, owned_domain
from uuid import UUID
import secrets
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.database import get_db
from shared.models import Domain
from app.schemas import DomainCreate, DomainOut

router = APIRouter(prefix="/domains", tags=["domains"])


@router.post("/", response_model=DomainOut)
async def register_domain(payload: DomainCreate, db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    """Register a domain for monitoring. Not yet scannable until verified."""
    token = f"asm-verify={secrets.token_hex(16)}"
    domain = Domain(name=payload.name, verification_token=token, verified=False, owner_id=user.id)
    db.add(domain)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Domain already registered")
    await db.refresh(domain)
    return domain


@router.get("/", response_model=list[DomainOut])
async def list_domains(db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    result = await db.execute(select(Domain).where(Domain.owner_id == user.id))
    return result.scalars().all()


@router.get("/{domain_id}", response_model=DomainOut)
async def get_domain(domain_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    domain = await owned_domain(db, domain_id, user)
    return domain
