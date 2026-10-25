import re
import secrets
from datetime import timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from app.database import get_db
from app.config import settings
from app.auth import (current_user, bearer, hash_password, password_matches,
                      password_hasher, token_digest, throttle, DUMMY_HASH)
from shared.models import User, AuthSession
from shared.time_utils import database_utc

router = APIRouter(prefix='/auth', tags=['auth'])

class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr = Field(min_length=6, max_length=128)

    @field_validator('username')
    @classmethod
    def normalize_username(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}', value):
            raise ValueError('Use 3–64 letters, digits, dots, underscores or hyphens')
        return value

@router.post('/register', status_code=201)
async def register(payload: Credentials, request: Request, response: Response, db=Depends(get_db)):
    response.headers['Cache-Control'] = 'no-store'
    await throttle(db, request, 'register', payload.username)
    encoded = await hash_password(payload.password.get_secret_value())
    user = User(username=payload.username, password_hash=encoded)
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail='Username unavailable')
    await db.refresh(user)
    return {'id':str(user.id), 'username':user.username}

@router.post('/login')
async def login(payload: Credentials, request: Request, response: Response, db=Depends(get_db)):
    response.headers['Cache-Control'] = 'no-store'
    await throttle(db, request, 'login', payload.username)
    user = (await db.execute(select(User).where(User.username == payload.username))).scalar_one_or_none()
    valid = await password_matches(user.password_hash if user else DUMMY_HASH, payload.password.get_secret_value())
    if not valid or user is None or not user.active:
        raise HTTPException(status_code=401, detail='Invalid username or password', headers={'WWW-Authenticate':'Bearer'})
    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = await hash_password(payload.password.get_secret_value())
    token = secrets.token_urlsafe(32)
    now = database_utc()
    expires = now + timedelta(hours=settings.auth_session_hours)
    await db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
    db.add(AuthSession(token_hash=token_digest(token), user_id=user.id, expires_at=expires))
    await db.commit()
    return {'access_token':token, 'token_type':'bearer', 'expires_at':expires.replace(tzinfo=timezone.utc).isoformat()}

@router.get('/me')
async def me(user=Depends(current_user)):
    return {'id':str(user.id), 'username':user.username}

@router.post('/logout', status_code=204)
async def logout(user=Depends(current_user), credentials=Depends(bearer), db=Depends(get_db)):
    await db.execute(delete(AuthSession).where(AuthSession.token_hash == token_digest(credentials.credentials), AuthSession.user_id == user.id))
    await db.commit()
    return Response(status_code=204, headers={'Cache-Control':'no-store'})
