"""Explicit operator-only assignment of a single unowned legacy domain."""
import argparse
import asyncio
import secrets
import uuid
from sqlalchemy import select
from app.database import SessionLocal, engine
from shared.models import Domain, User, Scan, ScanStatus

async def assign(db, domain_id, user_id):
    domain = (await db.execute(select(Domain).where(Domain.id == domain_id).with_for_update())).scalar_one_or_none()
    user = await db.get(User, user_id)
    if not domain or domain.owner_id is not None or not user or not user.active:
        raise ValueError('Requires an unassigned domain and an active existing user')
    pending = (await db.execute(select(Scan.id).where(Scan.domain_id == domain_id, Scan.status.in_([ScanStatus.queued, ScanStatus.running])).limit(1))).first()
    if pending:
        raise ValueError('Resolve queued/running scans before assigning this domain')
    domain.owner_id = user.id
    domain.verified = False
    domain.verification_token = 'asm-verify=' + secrets.token_hex(16)
    await db.commit()

async def main(args):
    try:
        async with SessionLocal() as db:
            await assign(db, args.domain_id, args.user_id)
        print('Assigned domain and its history; fresh DNS verification required.')
    finally:
        await engine.dispose()

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain-id', required=True, type=uuid.UUID)
    parser.add_argument('--user-id', required=True, type=uuid.UUID)
    asyncio.run(main(parser.parse_args()))
