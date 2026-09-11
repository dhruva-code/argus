"""Redis connection and the queue/control channel constants shared with the
Go orchestrator (must match orchestrator/internal/queue)."""

from __future__ import annotations

import json
from typing import Any

import redis.asyncio as aioredis

from app.config import settings

KEY_QUEUED = "argus:jobs:queued"
KEY_PROCESSING = "argus:jobs:processing"
CHAN_EVENTS = "argus:events"
CHAN_CONTROL = "argus:control"

_client: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def enqueue_job(job_id: str, payload: dict[str, Any]) -> None:
    r = get_redis()
    async with r.pipeline(transaction=True) as pipe:
        pipe.set(f"argus:job:{job_id}", json.dumps(payload, default=str))
        pipe.rpush(KEY_QUEUED, job_id)
        await pipe.execute()


async def send_control(action: str, job_id: str | None = None) -> None:
    r = get_redis()
    msg: dict[str, Any] = {"action": action}
    if job_id:
        msg["job_id"] = job_id
    await r.publish(CHAN_CONTROL, json.dumps(msg))


async def purge_job_keys(job_id: str) -> None:
    """Remove a job's wire payload, heartbeat, checkpoint and queue entries."""
    r = get_redis()
    keys = [k async for k in r.scan_iter(match=f"argus:job:{job_id}*")]
    async with r.pipeline(transaction=False) as pipe:
        if keys:
            pipe.delete(*keys)
        pipe.lrem(KEY_QUEUED, 0, job_id)
        pipe.lrem(KEY_PROCESSING, 0, job_id)
        await pipe.execute()
