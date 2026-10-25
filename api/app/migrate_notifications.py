"""Add only the notification outbox; does not alter historical scans."""
import asyncio
from app.database import engine
from shared.models import ScanNotification
from shared.auth_migration import require_auth_schema

def migrate(connection):
    require_auth_schema(connection)
    ScanNotification.__table__.create(connection, checkfirst=True)

async def main():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(migrate)
    finally:
        await engine.dispose()

if __name__ == '__main__':
    asyncio.run(main())
