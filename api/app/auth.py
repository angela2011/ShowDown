"""Authentication and centralized owner checks. Never accept owner IDs from clients."""
import asyncio
import hashlib
import re
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, delete
from shared.models import User, AuthSession, Domain, AuthThrottle
from shared.time_utils import database_utc
from app.database import get_db

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
# Work on unknown usernames too, to reduce username-dependent login timing.
DUMMY_HASH = password_hasher.hash('unused-random-dummy-password')
bearer = HTTPBearer(auto_error=False)
_hash_slots = asyncio.Semaphore(2)

async def hash_password(password):
    async with _hash_slots:
        return await asyncio.to_thread(password_hasher.hash, password)

async def password_matches(encoded, password):
    def check():
        try:
            return password_hasher.verify(encoded, password)
        except (VerificationError, InvalidHashError):
            return False
    async with _hash_slots:
        return await asyncio.to_thread(check)

def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

def unauthorized():
    return HTTPException(status_code=401, detail='Invalid or expired authentication', headers={'WWW-Authenticate':'Bearer'})

async def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db=Depends(get_db)):
    if credentials is None or not re.fullmatch(r'[A-Za-z0-9_-]{43}', credentials.credentials):
        raise unauthorized()
    result = await db.execute(select(User).join(AuthSession, AuthSession.user_id == User.id).where(
        AuthSession.token_hash == token_digest(credentials.credentials),
        AuthSession.expires_at > database_utc(), User.active.is_(True)))
    user = result.scalar_one_or_none()
    if user is None:
        raise unauthorized()
    return user

async def owned_domain(db, domain_id, user):
    domain = (await db.execute(select(Domain).where(Domain.id == domain_id, Domain.owner_id == user.id))).scalar_one_or_none()
    if domain is None:
        raise HTTPException(status_code=404, detail='Domain not found')
    return domain

async def throttle(db, request: Request, action: str, username: str):
    # Use the ASGI peer address, not untrusted client-supplied forwarding headers.
    # A trusted reverse proxy must configure address forwarding correctly.
    peer = request.client.host if request.client else 'unknown'
    window = 3600 if action == 'register' else 900
    now = database_utc()
    epoch = int(now.replace(tzinfo=timezone.utc).timestamp())
    bucket = epoch // window
    expiry = datetime.fromtimestamp((bucket + 1) * window, timezone.utc).replace(tzinfo=None)
    quotas = [(f'{action}:peer:{peer}', 10 if action == 'register' else 60)]
    if action == 'login':
        quotas.append((f'login:user:{username}', 10))
    dialect = db.get_bind().dialect.name
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == 'sqlite':
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise RuntimeError('Unsupported authentication database')
    exceeded = False
    for scope, limit in quotas:
        key = token_digest(f'{scope}:{bucket}')
        statement = insert(AuthThrottle).values(key=key, count=1, expires_at=expiry)
        statement = statement.on_conflict_do_update(index_elements=['key'], set_={'count':AuthThrottle.count + 1}).returning(AuthThrottle.count)
        count = (await db.execute(statement)).scalar_one()
        exceeded |= count > limit
    await db.execute(delete(AuthThrottle).where(AuthThrottle.expires_at <= now))
    await db.commit()
    if exceeded:
        raise HTTPException(status_code=429, detail='Too many authentication attempts; try later',
                            headers={'Retry-After':str(max(1, (bucket + 1) * window - epoch))})
