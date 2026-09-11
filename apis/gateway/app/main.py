"""Argus gateway API — application factory and lifespan."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text as sql_text
from starlette.requests import Request

from app import __version__
from app.config import settings
from app.core.redis import close_redis, get_redis
from app.db import create_all, engine
from app.routers import (
    assets,
    audit,
    auth,
    dashboard,
    inject,
    jobs,
    metrics,
    oast,
    orgs,
    profiles,
    projects,
    reports,
    system,
    tools,
)
from app.routers import (
    settings as settings_router,
)
from app.scope.engine import ScopePolicyError
from app.services.events import recover_orphaned_jobs, run_consumer
from app.services.notifications import run_notification_worker, run_telegram_pairing_poller
from app.services.scheduler import run_scheduler

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("argus.gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.env == "production" and settings.jwt_secret == "dev-insecure-change-me":  # noqa: S105
        raise RuntimeError("JWT_SECRET must be set in production")
    if settings.env == "production" and not settings.secret_encryption_key:
        raise RuntimeError("SECRET_ENCRYPTION_KEY must be set in production")

    # In development / tests we create tables directly; production uses Alembic
    # (see apis/gateway/entrypoint.sh).
    if settings.env != "production":
        await create_all()

    stop = asyncio.Event()
    try:
        await recover_orphaned_jobs()
    except Exception:  # noqa: BLE001
        log.warning("orphaned-job recovery skipped (redis unavailable)")
    consumer = asyncio.create_task(run_consumer(stop))
    scheduler = asyncio.create_task(run_scheduler(stop))
    notifier = asyncio.create_task(run_notification_worker(stop))
    telegram_poller = asyncio.create_task(run_telegram_pairing_poller(stop))

    log.info("gateway %s ready (env=%s)", __version__, settings.env)
    try:
        yield
    finally:
        stop.set()
        for task in (consumer, scheduler, notifier, telegram_poller):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:  # noqa: BLE001
                log.debug("background task shutdown raised", exc_info=True)
        await close_redis()
        await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Argus Platform API",
        version=__version__,
        description="Attack Surface Management & authorized bug-bounty reconnaissance platform.",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.middleware("http")(metrics.instrument)

    @app.exception_handler(ScopePolicyError)
    async def _scope_err(_: Request, exc: ScopePolicyError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.get("/api/health", tags=["meta"])
    async def health() -> dict[str, str]:
        """Process liveness only — confirms the ASGI app is up and serving."""
        return {"status": "ok", "version": __version__}

    @app.get("/api/version", tags=["meta"])
    async def version() -> dict[str, str]:
        return {"version": __version__, "env": settings.env}

    @app.get("/api/ready", tags=["meta"])
    async def ready() -> JSONResponse:
        """Confirms the app can actually do work: database, Redis, and the
        configuration production requires are all in place. Unauthenticated
        (matches standard readiness-probe convention) but reveals only
        booleans — never connection strings or other configuration detail."""
        checks: dict[str, bool] = {}
        try:
            async with engine.connect() as conn:
                await conn.execute(sql_text("SELECT 1"))
            checks["database"] = True
        except Exception:  # noqa: BLE001
            checks["database"] = False
        try:
            await get_redis().ping()
            checks["redis"] = True
        except Exception:  # noqa: BLE001
            checks["redis"] = False
        checks["configuration"] = bool(settings.jwt_secret) and settings.jwt_secret != "dev-insecure-change-me"  # noqa: S105
        ok = all(checks.values()) if settings.env == "production" else checks["database"] and checks["redis"]
        return JSONResponse(status_code=200 if ok else 503, content={"ready": ok, "checks": checks})

    for r in (auth, orgs, projects, assets, profiles, jobs, tools, dashboard, audit, reports,
              metrics, inject, oast, system, settings_router):
        app.include_router(r.router)
    app.include_router(inject.internal_router)

    # optional OpenTelemetry auto-instrumentation
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(app)
            log.info("OpenTelemetry instrumentation enabled")
        except Exception:  # noqa: BLE001
            log.warning("OpenTelemetry requested but instrumentation failed", exc_info=True)

    return app


app = create_app()
