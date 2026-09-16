"""Scheduled continuous monitoring (M6).

A single in-process loop wakes every 60 s, and for each project with a
`schedule_cron` whose next fire time has passed since the last scheduled scan,
enqueues a `recon.scan` (marked `params.scheduled = true`). Notifications for the
result are fired by the event consumer when the scan finishes.

Only one gateway replica should run this — set `ARGUS_SCHEDULER=off` on the
others (or run it as a dedicated worker).
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime

from croniter import croniter
from sqlalchemy import delete as sa_delete
from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditLog, JobEvent, JobStatus, Organization, Project, ScanJob
from app.services import scans

log = logging.getLogger("argus.scheduler")

_TICK = 60
_RETENTION_EVERY = 3600  # run the retention sweep at most hourly


def enabled() -> bool:
    return os.getenv("ARGUS_SCHEDULER", "on").lower() not in ("off", "0", "false")


async def _due_projects(session) -> list[Project]:
    rows = (
        (
            await session.execute(
                select(Project).where(Project.schedule_cron.is_not(None), Project.is_archived.is_(False))
            )
        )
        .scalars()
        .all()
    )
    due: list[Project] = []
    now = datetime.now(UTC)
    for p in rows:
        if not p.schedule_cron or not croniter.is_valid(p.schedule_cron):
            continue
        last = await session.scalar(
            select(ScanJob.created_at)
            .where(ScanJob.project_id == p.id, ScanJob.type == "recon.scan")
            .order_by(ScanJob.created_at.desc())
            .limit(1)
        )
        base = last or (now - _one_interval(p.schedule_cron, now))
        if base.tzinfo is None:
            base = base.replace(tzinfo=UTC)
        nxt = croniter(p.schedule_cron, base).get_next(datetime)
        if nxt <= now:
            due.append(p)
    return due


def _one_interval(expr: str, now: datetime):
    it = croniter(expr, now)
    a = it.get_next(datetime)
    b = it.get_next(datetime)
    return b - a


async def _run_once() -> None:
    async with SessionLocal() as session:
        due = await _due_projects(session)
        for project in due:
            # skip if a scan is already active for this project
            active = await session.scalar(
                select(ScanJob.id)
                .where(
                    ScanJob.project_id == project.id,
                    ScanJob.status.in_([JobStatus.queued, JobStatus.running]),
                )
                .limit(1)
            )
            if active:
                continue
            try:
                # profile_key=None → plan_recon_scan falls back to the project's
                # default profile
                params, rate_limits = await scans.plan_recon_scan(session, project, profile_key=None)
            except scans.ReconPlanError as exc:
                log.info("scheduled scan for %s skipped: %s", project.name, exc)
                continue
            params["scheduled"] = True
            job = await scans.create_scan_job(
                session,
                project=project,
                job_type="recon.scan",
                params=params,
                rate_limits=rate_limits,
                created_by=None,
            )
            await session.commit()
            await scans.enqueue(session, job)
            log.info("enqueued scheduled scan %s for project %s", job.id, project.name)


async def run_retention_sweep() -> dict[str, int]:
    """Delete data older than each org's retention window."""
    from datetime import timedelta

    removed = {"job_events": 0, "scan_jobs": 0, "audit_logs": 0}
    async with SessionLocal() as session:
        orgs = (await session.execute(select(Organization))).scalars().all()
        for org in orgs:
            raw_cut = datetime.now(UTC) - timedelta(days=max(1, org.retention_raw_days))
            audit_cut = datetime.now(UTC) - timedelta(days=max(1, org.retention_audit_days))

            old_jobs = (
                (
                    await session.execute(
                        select(ScanJob.id).where(
                            ScanJob.org_id == org.id,
                            ScanJob.finished_at.is_not(None),
                            ScanJob.finished_at < raw_cut,
                        )
                    )
                )
                .scalars()
                .all()
            )
            if old_jobs:
                r = await session.execute(sa_delete(JobEvent).where(JobEvent.job_id.in_(old_jobs)))
                removed["job_events"] += r.rowcount or 0
                r = await session.execute(sa_delete(ScanJob).where(ScanJob.id.in_(old_jobs)))
                removed["scan_jobs"] += r.rowcount or 0

            r = await session.execute(
                sa_delete(AuditLog).where(AuditLog.org_id == org.id, AuditLog.at < audit_cut)
            )
            removed["audit_logs"] += r.rowcount or 0
        await session.commit()
    if any(removed.values()):
        log.info("retention sweep removed %s", removed)
    return removed


async def run_scheduler(stop: asyncio.Event) -> None:
    if not enabled():
        log.info("scheduler disabled (ARGUS_SCHEDULER=off)")
        return
    log.info("continuous-monitoring scheduler started")
    last_retention = 0.0
    while not stop.is_set():
        try:
            await _run_once()
        except Exception:  # noqa: BLE001
            log.exception("scheduler tick failed")
        loop_now = asyncio.get_event_loop().time()
        if loop_now - last_retention > _RETENTION_EVERY:
            last_retention = loop_now
            try:
                await run_retention_sweep()
            except Exception:  # noqa: BLE001
                log.exception("retention sweep failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=_TICK)
        except TimeoutError:
            pass
