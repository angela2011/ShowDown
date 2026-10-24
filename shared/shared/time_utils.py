"""UTC conventions for existing timezone-naive PostgreSQL timestamp columns."""
from datetime import datetime, timezone


def database_utc(value: datetime | None = None) -> datetime:
    value = value if value is not None else datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value  # Legacy timestamps already represent UTC.
    return value.astimezone(timezone.utc).replace(tzinfo=None)
