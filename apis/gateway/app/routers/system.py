"""System health screen (spec §42)."""

from __future__ import annotations

import time

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import KEY_PROCESSING, KEY_QUEUED, get_redis
from app.db import get_session
from app.deps import Principal, get_principal

router = APIRouter(prefix="/api/system", tags=["system"])


async def _check(coro) -> dict:
    start = time.perf_counter()
    try:
        await coro
        return {"healthy": True, "latency_ms": round((time.perf_counter() - start) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"healthy": False, "error": str(exc)[:200]}


async def _ai_health(session: AsyncSession, org_id) -> dict:
    """Unlike the other checks here, this endpoint is polled every ~10s by
    the System Health screen — so this must never make a live, billed call
    to a hosted provider (Anthropic) on every poll. Ollama is different: a
    local server, and `/api/tags` is a cheap metadata call that never loads
    the model into memory, so it's safe and useful to check live every
    time (this is also the only way to catch an Ollama server that's
    crashed/OOM-killed between manual "Test connection" clicks — see
    docs/AI_ANALYSIS.md's note on local-model memory requirements)."""
    from app.services.ai import resolve_config

    cfg = await resolve_config(session, org_id)
    if not cfg.enabled:
        return {
            "healthy": True,
            "configured": False,
            "provider": cfg.provider,
            "detail": "AI analysis is disabled",
        }

    if cfg.provider == "ollama":
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{cfg.ollama_base_url.rstrip('/')}/api/tags")
            r.raise_for_status()
            names = {m.get("name", "") for m in r.json().get("models", [])}
            model_ok = cfg.model in names or any(n.split(":")[0] == cfg.model.split(":")[0] for n in names)
            return {
                "healthy": model_ok,
                "configured": True,
                "provider": "ollama",
                "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                "detail": f"model {cfg.model} available"
                if model_ok
                else f"model {cfg.model} not pulled on this server",
            }
        except httpx.HTTPError as exc:
            return {
                "healthy": False,
                "configured": True,
                "provider": "ollama",
                "detail": f"unreachable at {cfg.ollama_base_url}: {str(exc)[:150]}",
            }

    # Anthropic (or any future hosted provider): report the last *manual*
    # test result rather than re-spending API quota on every dashboard poll.
    from app.models import AiSettings

    row = await session.get(AiSettings, org_id)
    if row is None or row.last_test_status == "not_configured":
        return {
            "healthy": True,
            "configured": True,
            "provider": cfg.provider,
            "detail": "not yet tested — see Settings → AI & Analysis",
        }
    return {
        "healthy": row.last_test_status == "ok",
        "configured": True,
        "provider": cfg.provider,
        "detail": f"{row.last_test_detail} (as of last manual test, not live-checked here)",
    }


@router.get("/health")
async def health(
    session: AsyncSession = Depends(get_session),
    principal: Principal = Depends(get_principal),
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

    ai = await _ai_health(session, principal.org.id)

    return {
        "database": db,
        "redis": {**redis_ok, "queued": queued, "processing": processing},
        "orchestrator": {"reachable": worker_alive},
        "queue": {"queued": queued, "processing": processing},
        "ai": ai,
    }
