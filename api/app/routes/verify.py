import dns.resolver
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from shared.models import Domain
from app.schemas import DomainOut

router = APIRouter(prefix="/verify", tags=["verify"])


@router.post("/{domain_id}", response_model=DomainOut)
async def verify_domain(domain_id: str, db: AsyncSession = Depends(get_db)):
    """
    Checks for a TXT record on the domain matching the stored verification
    token, e.g.:  _asm-verify.example.com  TXT  "asm-verify=<token>"
    Scans are only allowed against domains where this has succeeded.
    """
    domain = await db.get(Domain, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    query_name = f"_asm-verify.{domain.name}"
    try:
        answers = dns.resolver.resolve(query_name, "TXT")
        found = any(domain.verification_token in str(r) for r in answers)
    except Exception:
        found = False

    if not found:
        raise HTTPException(
            status_code=400,
            detail=f"TXT record not found or mismatched. Add: {query_name} TXT \"{domain.verification_token}\"",
        )

    domain.verified = True
    await db.commit()
    await db.refresh(domain)
    return domain
