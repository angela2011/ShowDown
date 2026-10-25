"""Explicit additive migration; never assigns legacy domains or enables schedules."""
import asyncio
from app.database import engine
from shared.auth_migration import require_auth_schema
from shared.models import ScanSchedule

def migrate(connection):
    require_auth_schema(connection)
    ScanSchedule.__table__.create(connection, checkfirst=True)

async def main():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(migrate)
    finally:
        await engine.dispose()

if __name__ == '__main__':
    asyncio.run(main())
