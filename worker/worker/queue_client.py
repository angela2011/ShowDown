import os
import json
import redis.asyncio as redis

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SCAN_QUEUE_NAME = os.environ.get("SCAN_QUEUE_NAME", "scan_jobs")

client = redis.from_url(REDIS_URL)


async def get_next_job(timeout: int = 5):
    """Blocking pop from the scan queue. Returns a dict job or None on timeout."""
    result = await client.blpop(SCAN_QUEUE_NAME, timeout=timeout)
    if result is None:
        return None
    _, raw = result
    return json.loads(raw)
