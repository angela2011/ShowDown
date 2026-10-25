"""Operator-invoked migration; does not assign existing data to any user."""
import asyncio
from app.database import engine
from shared.auth_migration import migrate_auth

async def main():
    try:
        async with engine.begin() as connection:
            await connection.run_sync(migrate_auth)
        print('Authentication schema ready. Legacy domains remain unassigned.')
    finally:
        await engine.dispose()

if __name__ == '__main__':
    asyncio.run(main())
