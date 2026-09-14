"""Consume orchestrator events from Redis, persist them, and fan out to SSE
subscribers.

Runs as a background task started in app.main.lifespan. One consumer per
gateway process; all processes share the same Redis pub/sub so every SSE client
on any process sees every event.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.redis import CHAN_EVENTS, get_redis
from app.db import SessionLocal
from app.models import JobEvent, JobStatus, ScanJob

log = logging.getLogger("argus.events")

_TERMINAL = {
    JobStatus.completed,
    JobStatus.failed,
    JobStatus.cancelled,
    JobStatus.partially_completed,
}


class EventHub:
    """In-process fan-out. Each SSE request registers a queue keyed by job id."""

    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, job_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs[job_id].add(q)
        return q

    def unsubscribe(self, job_id: str, q: asyncio.Queue) -> None:
        self._subs[job_id].discard(q)
        if not self._subs[job_id]:
            self._subs.pop(job_id, None)

    def publish(self, job_id: str, event: dict) -> None:
        for q in list(self._subs.get(job_id, ())):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(event)


hub = EventHub()


def _strip_nul_bytes(value):
    """Recursively drop embedded NUL (0x00) bytes from strings.

    Postgres text/varchar/json columns cannot store a NUL byte at all — it's
    a hard Postgres limitation, not something that can be escaped — and
    asyncpg raises DataError on any INSERT/UPDATE that carries one. Event
    payloads from the orchestrator can legitimately contain one (e.g.
    null-byte-truncation probe values used by the injection-testing engine),
    so scrub every event at the ingestion boundary before any of its fields
    ever reach a query, regardless of which upsert path consumes them.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_nul_bytes(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul_bytes(v) for v in value]
    return value


async def _apply_event(raw: dict) -> None:
    job_id = raw.get("job_id")
    if not job_id:
        return
    try:
        jid = uuid.UUID(job_id)
    except ValueError:
        return

    async with SessionLocal() as session:
        job = await session.get(ScanJob, jid)
        if job is None:
            return

        etype = raw.get("type", "log")

        # High-frequency recon events: the row is the artifact, so don't also
        # write a job_event for every one (asset events keep a slim log line).
        _quiet = {"asset_edge", "vhost", "endpoint", "repository", "port", "finding", "injection_point"}
        if etype not in _quiet:
            ev_data = raw.get("data") or {}
            if etype in ("asset", "secret"):
                # keep the log row lean (the row itself carries the detail)
                ev_data = {}
            session.add(
                JobEvent(
                    job_id=jid,
                    type=etype,
                    level=raw.get("level", "INFO"),
                    message=raw.get("message", ""),
                    data=ev_data,
                )
            )

        if etype in (
            "asset",
            "asset_edge",
            "vhost",
            "endpoint",
            "secret",
            "repository",
            "port",
            "finding",
            "injection_point",
        ):
            from app.services.assets import (
                upsert_asset,
                upsert_edge,
                upsert_endpoint,
                upsert_repository,
                upsert_secret,
                upsert_vhost,
            )
            from app.services.findings import upsert_finding, upsert_port
            from app.services.injection import upsert_injection_point

            data = raw.get("data") or {}
            fn = {
                "asset": upsert_asset,
                "asset_edge": upsert_edge,
                "vhost": upsert_vhost,
                "endpoint": upsert_endpoint,
                "secret": upsert_secret,
                "repository": upsert_repository,
                "port": upsert_port,
                "finding": upsert_finding,
                "injection_point": upsert_injection_point,
            }[etype]
            try:
                await fn(
                    session,
                    org_id=job.org_id,
                    project_id=job.project_id,
                    scan_id=job.id,
                    data=data,
                )
                if etype in (
                    "asset",
                    "vhost",
                    "endpoint",
                    "secret",
                    "repository",
                    "port",
                    "finding",
                    "injection_point",
                ):
                    job.result_count = (job.result_count or 0) + 1
            except Exception:  # noqa: BLE001
                log.exception(
                    "%s upsert failed: %s",
                    etype,
                    data.get("value")
                    or data.get("normalized_url")
                    or data.get("fingerprint")
                    or data.get("param_name"),
                )
                # A DB-level failure (e.g. a DataError) leaves this session's
                # transaction aborted; Postgres refuses every further
                # statement on it, including the error_count bump below and
                # the session.commit() at the end of this function — so the
                # error would silently fail to record too, and the whole
                # event (job_events row included) would be lost when the
                # exception propagates out of _apply_event. Roll back first
                # so the job row can be reloaded on a clean transaction and
                # the increment actually persists.
                await session.rollback()
                job = await session.get(ScanJob, jid)
                if job is None:
                    return
                job.error_count = (job.error_count or 0) + 1

        if etype == "result":
            job.result_count = (job.result_count or 0) + 1
            if job.type == "tool.health":
                from app.models import ToolIntegration, ToolVersion
                from app.routers.tools import apply_health_result

                data = raw.get("data") or {}
                await apply_health_result(session, job.org_id, data)
                if data.get("tool") and data.get("installed_version"):
                    tool = await session.scalar(
                        select(ToolIntegration).where(
                            ToolIntegration.org_id == job.org_id,
                            ToolIntegration.name == data["tool"],
                        )
                    )
                    if tool is not None:
                        tool.last_checked_at = datetime.now(UTC)
                        session.add(
                            ToolVersion(
                                tool_id=tool.id,
                                version=data["installed_version"],
                                health=data.get("state", "unknown"),
                                detail=data.get("detail", ""),
                            )
                        )
        elif etype == "error":
            job.error_count = (job.error_count or 0) + 1

        if etype == "status" and raw.get("status"):
            try:
                new = JobStatus(raw["status"])
            except ValueError:
                new = None
            if new is not None:
                job.status = new
                if new == JobStatus.running and job.started_at is None:
                    job.started_at = datetime.now(UTC)
                    if isinstance(raw.get("message"), str) and "worker" in raw["message"]:
                        job.worker = raw["message"].split()[1]
                if new in _TERMINAL:
                    job.finished_at = datetime.now(UTC)
        if etype == "error":
            job.error = raw.get("message")

        checkpoint_phase = None
        msg = raw.get("message", "")
        if (
            etype == "log"
            and job.type == "recon.scan"
            and isinstance(msg, str)
            and msg.startswith("checkpoint: ")
        ):
            checkpoint_phase = msg.removeprefix("checkpoint: ")
        org_id, project_id = job.org_id, job.project_id

        await session.commit()

        # fire notifications when a recon scan finishes
        if etype == "status" and job.status in _TERMINAL and job.type == "recon.scan":
            try:
                await _on_scan_finished(session, job)
            except Exception:  # noqa: BLE001
                log.exception("post-scan notification failed")

    # Opt-in per-phase AI strategy note (Settings -> AI & Analysis ->
    # "analyze every phase"). Fired as a background task, not awaited here,
    # so a slow/unreachable AI provider (a local Ollama model in particular
    # can take tens of seconds) never stalls the event-consumer loop other
    # jobs' events are also flowing through.
    if checkpoint_phase is not None:
        asyncio.create_task(_run_phase_analysis(jid, org_id, project_id, checkpoint_phase))

    # Secret values are shown to authorized operators (masking defeats
    # validation). `raw_for_vault` was a duplicate of `value` kept only as the
    # encrypt-at-rest side channel — drop just that key.
    if raw.get("type") == "secret" and isinstance(raw.get("data"), dict):
        raw["data"].pop("raw_for_vault", None)
    hub.publish(job_id, raw)


async def _run_phase_analysis(
    job_id: uuid.UUID, org_id: uuid.UUID, project_id: uuid.UUID, phase: str
) -> None:
    """Builds a lightweight summary of a just-finished phase from its own
    job event log (the same data a human watching the live log would see),
    asks the configured AI for a short strategy note, and — if one comes
    back — appends it as its own job event (type="ai_insight") so it shows
    up inline in the job's timeline without any new UI surface. Errors are
    logged, never raised — this is a bonus insight, not part of the scan."""
    try:
        async with SessionLocal() as session:
            from app.models import Project
            from app.services.ai import analyse_phase

            project = await session.get(Project, project_id)
            if project is None:
                return

            recent = (
                (
                    await session.execute(
                        select(JobEvent)
                        .where(JobEvent.job_id == job_id, JobEvent.type != "ai_insight")
                        .order_by(JobEvent.at.desc())
                        .limit(60)
                    )
                )
                .scalars()
                .all()
            )
            counts: dict[str, int] = defaultdict(int)
            samples: list[str] = []
            for e in recent:
                counts[e.type] += 1
                if e.type == "log" and e.message.startswith("checkpoint:"):
                    continue
                if len(samples) < 12 and e.message:
                    samples.append(e.message[:200])

            note = await analyse_phase(
                session, org_id, project.name, phase, {"counts": dict(counts), "samples": samples}
            )
            if not note:
                return

            session.add(
                JobEvent(
                    job_id=job_id,
                    type="ai_insight",
                    level="INFO",
                    message=note,
                    data={"phase": phase},
                )
            )
            await session.commit()
        hub.publish(
            str(job_id),
            {
                "job_id": str(job_id),
                "type": "ai_insight",
                "level": "INFO",
                "message": note,
                "data": {"phase": phase},
            },
        )
    except Exception:  # noqa: BLE001
        log.exception("per-phase AI analysis task failed for job %s phase %s", job_id, phase)


async def _on_scan_finished(session, job) -> None:
    from app.models import Project
    from app.services.monitoring import exposure_delta
    from app.services.notify import notify_scan_complete

    project = await session.get(Project, job.project_id)
    if project is None or not (project.notification_policy or {}):
        return
    delta = await exposure_delta(session, job.project_id)
    await notify_scan_complete(session, project, job, delta)


async def run_consumer(stop: asyncio.Event) -> None:
    r = get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(CHAN_EVENTS)
    log.info("event consumer subscribed to %s", CHAN_EVENTS)
    try:
        while not stop.is_set():
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg is None:
                continue
            try:
                raw = json.loads(msg["data"])
            except (ValueError, TypeError):
                continue
            raw = _strip_nul_bytes(raw)
            try:
                await _apply_event(raw)
            except Exception:  # noqa: BLE001
                log.exception("failed to apply event")
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(CHAN_EVENTS)
            await pubsub.aclose()
        log.info("event consumer stopped")


async def recover_orphaned_jobs() -> None:
    """On startup, fail any job stuck 'running' with no live worker heartbeat."""
    r = get_redis()
    async with SessionLocal() as session:
        rows = (
            (
                await session.execute(
                    select(ScanJob).where(ScanJob.status.in_([JobStatus.running, JobStatus.paused]))
                )
            )
            .scalars()
            .all()
        )
        for job in rows:
            if not await r.exists(f"argus:job:{job.id}:hb"):
                job.status = JobStatus.failed
                job.error = "worker lost (no heartbeat on startup recovery)"
                job.finished_at = datetime.now(UTC)
        await session.commit()
