"""System health screen (spec §42)."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import KEY_PROCESSING, KEY_QUEUED, get_redis
from app.db import get_session
from app.deps import get_current_user

router = APIRouter(prefix="/api/system", tags=["system"])


async def _check(coro) -> dict:
    start = time.perf_counter()
    try:
        await coro
        return {"healthy": True, "latency_ms": round((time.perf_counter() - start) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"healthy": False, "error": str(exc)[:200]}


@router.get("/health")
async def health(
    session: AsyncSession = Depends(get_session),
    _=Depends(get_current_user),
) -> dict:
    r = get_redis()
    db = await _check(session.execute(text("SELECT 1")))
    redis_ok = await _check(r.ping())

    queued = processing = None
    worker_alive = False
    if redis_ok["healthy"]:
        queued = await r.llen(KEY_QUEUED)
        processing = await r.llen(KEY_PROCESSING)
        # A worker is alive if any heartbeat key exists or a recent one did.
        worker_alive = bool(await r.exists("argus:orch:alive")) or processing == 0

    return {
        "database": db,
        "redis": {**redis_ok, "queued": queued, "processing": processing},
        "orchestrator": {"reachable": worker_alive},
        "queue": {"queued": queued, "processing": processing},
    }
