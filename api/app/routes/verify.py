from app.auth import current_user, owned_domain
from uuid import UUID
from shared.targets import ownership_matches
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from shared.models import Domain
from app.schemas import DomainOut

router = APIRouter(prefix="/verify", tags=["verify"])


@router.post("/{domain_id}", response_model=DomainOut)
async def verify_domain(domain_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    """
    Checks for a TXT record on the domain matching the stored verification
    token, e.g.:  _asm-verify.example.com  TXT  "asm-verify=<token>"
    Scans are only allowed against domains where this has succeeded.
    """
    domain = await owned_domain(db, domain_id, user)

    query_name = f"_asm-verify.{domain.name}"
    try:
        found = await ownership_matches(domain.name, domain.verification_token)
    except Exception:
        raise HTTPException(status_code=503, detail="DNS verification temporarily unavailable; retry later")

    if not found:
        domain.verified = False
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail=f"TXT record not found or mismatched. Add: {query_name} TXT \"{domain.verification_token}\"",
        )

    domain.verified = True
    await db.commit()
    await db.refresh(domain)
    return domain
