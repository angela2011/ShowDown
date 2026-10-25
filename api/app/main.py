from fastapi import FastAPI
from app.routes import domains, verify, scans, auth, honeypots, schedules
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from shared.auth_migration import require_auth_schema
from app.database import engine
from shared.models import Base

app = FastAPI(title="AttackSurface Monitor API")

app.include_router(auth.router)
app.include_router(honeypots.router)
app.include_router(domains.router)
app.include_router(verify.router)
app.include_router(scans.router)
app.include_router(schedules.router)


@app.on_event("startup")
async def on_startup():
    # Dev convenience: create tables if they don't exist. Swap for Alembic
    # migrations before this goes anywhere near production.
    async with engine.begin() as conn:
        await conn.run_sync(require_auth_schema)
        await conn.run_sync(Base.metadata.create_all)


@app.get("/")
async def root():
    return {"status": "ok", "service": "attacksurface-monitor-api"}


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Pydantic errors otherwise echo invalid submitted passwords in "input".
    return JSONResponse(status_code=422, content={'detail':[
        {key:error[key] for key in ('loc','msg','type')} for error in exc.errors()
    ]}, headers={'Cache-Control':'no-store'})

@app.middleware('http')
async def private_responses(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    return response
