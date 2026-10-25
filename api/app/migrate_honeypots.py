"""Operator-invoked additive table creation. Does not alter existing tables."""
import asyncio
from app.database import engine
from shared.models import DecoySensor, DecoyEvent, DecoyBlock, DecoyAudit


def migrate(connection):
    for model in (DecoySensor, DecoyEvent, DecoyBlock, DecoyAudit):
        model.__table__.create(connection, checkfirst=True)


async def main():
    try:
        async with engine.begin() as connection:
            await connection.run_sync(migrate)
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())
