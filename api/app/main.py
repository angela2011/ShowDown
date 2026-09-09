from fastapi import FastAPI
from app.routes import domains, verify, scans
from app.database import engine
from shared.models import Base

app = FastAPI(title="AttackSurface Monitor API")

app.include_router(domains.router)
app.include_router(verify.router)
app.include_router(scans.router)


@app.on_event("startup")
async def on_startup():
    # Dev convenience: create tables if they don't exist. Swap for Alembic
    # migrations before this goes anywhere near production.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/")
async def root():
    return {"status": "ok", "service": "attacksurface-monitor-api"}
