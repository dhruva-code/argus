"""Scan jobs: create, list, inspect, control, and stream events."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from app.core import audit
from app.db import get_session
from app.deps import Principal, client_ip, get_principal, require_permission
from app.models import JobEvent, JobStatus, Project, ScanJob
from app.schemas import (
    JobCreate,
    JobEventOut,
    JobOut,
    ScanDeleteRequest,
    ScanDeleteResult,
)
from app.services import scans
from app.services.events import hub

router = APIRouter(prefix="/api", tags=["jobs"])

_ACTIVE_TYPES = scans.ACTIVE_JOB_TYPES


async def _project(session: AsyncSession, principal: Principal, pid: uuid.UUID) -> Project:
    p = await session.get(Project, pid)
    if p is None or p.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return p


async def _job(session: AsyncSession, principal: Principal, jid: uuid.UUID) -> ScanJob:
    j = await session.get(ScanJob, jid)
    if j is None or j.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    return j


@router.post(
    "/projects/{project_id}/jobs",
    response_model=JobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_job(
    project_id: uuid.UUID,
    body: JobCreate,
    request: Request,
    principal: Principal = Depends(require_permission("scan.execute")),
    session: AsyncSession = Depends(get_session),
) -> JobOut:
    project = await _project(session, principal, project_id)
    if body.type in _ACTIVE_TYPES and not body.authorization_ack:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "authorization_ack is required for job types that interact with target infrastructure",
        )

    if body.type == "recon.scan":
        try:
            params, rate_limits = await scans.plan_recon_scan(
                session,
                project,
                profile_key=body.params.get("profile_key"),
                extra_phases=body.params.get("phases"),
                bruteforce=body.params.get("bruteforce", True),
                vuln_level=body.params.get("vuln_level"),
                injection_ack=body.params.get("injection_ack", False),
                ssrf_ack=body.params.get("ssrf_ack", False),
                auth_profile_id=body.params.get("auth_profile_id"),
            )
        except scans.ReconPlanError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    else:
        params, rate_limits = body.params, scans.DEFAULT_RATE_LIMITS

    job = ScanJob(
        org_id=principal.org.id,
        project_id=project_id,
        type=body.type,
        status=JobStatus.queued,
        params=params,
        rate_limits=rate_limits,
        created_by=principal.user.id,
    )
    session.add(job)
    await session.flush()
    await audit.record(
        session,
        action="scan.create",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="scan_job",
        object_id=job.id,
        after={"type": body.type, "params": params},
    )
    await session.commit()
    await session.refresh(job)
    await scans.enqueue(session, job)
    return JobOut.model_validate(job)


@router.get("/projects/{project_id}/jobs", response_model=list[JobOut])
async def list_project_jobs(
    project_id: uuid.UUID,
    limit: int = 50,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[JobOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)
    rows = (
        (
            await session.execute(
                select(ScanJob)
                .where(ScanJob.project_id == project_id)
                .order_by(ScanJob.created_at.desc())
                .limit(min(limit, 200))
            )
        )
        .scalars()
        .all()
    )
    return [JobOut.model_validate(r) for r in rows]


@router.get("/jobs", response_model=list[JobOut])
async def list_jobs(
    status_filter: JobStatus | None = None,
    limit: int = 50,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[JobOut]:
    principal.require("project.read")
    q = select(ScanJob).where(ScanJob.org_id == principal.org.id)
    if status_filter:
        q = q.where(ScanJob.status == status_filter)
    rows = (
        (await session.execute(q.order_by(ScanJob.created_at.desc()).limit(min(limit, 200)))).scalars().all()
    )
    return [JobOut.model_validate(r) for r in rows]


@router.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> JobOut:
    principal.require("project.read")
    return JobOut.model_validate(await _job(session, principal, job_id))


@router.get("/jobs/{job_id}/events", response_model=list[JobEventOut])
async def job_events(
    job_id: uuid.UUID,
    after: datetime | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[JobEventOut]:
    principal.require("project.read")
    await _job(session, principal, job_id)
    q = select(JobEvent).where(JobEvent.job_id == job_id)
    if after:
        q = q.where(JobEvent.at > after)
    rows = (await session.execute(q.order_by(JobEvent.at).limit(2000))).scalars().all()
    return [JobEventOut.model_validate(r) for r in rows]


@router.get("/jobs/{job_id}/stream")
async def stream_job(
    job_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> EventSourceResponse:
    principal.require("project.read")
    job = await _job(session, principal, job_id)
    q = hub.subscribe(str(job_id))
    initial_status = job.status.value

    async def gen():
        yield {"event": "status", "data": json.dumps({"status": initial_status})}
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15)
                    yield {"event": ev.get("type", "log"), "data": json.dumps(ev)}
                except TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            hub.unsubscribe(str(job_id), q)

    return EventSourceResponse(gen())


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
async def cancel_job(
    job_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_permission("scan.cancel")),
    session: AsyncSession = Depends(get_session),
) -> JobOut:
    job = await _job(session, principal, job_id)
    if job.status in {JobStatus.completed, JobStatus.failed, JobStatus.cancelled}:
        raise HTTPException(status.HTTP_409_CONFLICT, f"job is already {job.status.value}")
    if job.status == JobStatus.queued:
        job.status = JobStatus.cancelled
        job.finished_at = datetime.now(UTC)
        # A queued job hasn't been claimed by any orchestrator worker yet, so
        # there's no one listening for the "stop" control message published
        # below — without this, the job's id stays sitting in the Redis
        # queue (argus:jobs:queued) and its full wire payload stays cached,
        # and a worker will eventually BLMOVE-claim and actually *run* it
        # despite the DB already showing it cancelled, tying up a worker for
        # the whole scan and blocking every real job queued behind it.
        await scans.purge_job_keys(str(job_id))
    await scans.request_cancel(str(job_id))
    await audit.record(
        session,
        action="scan.cancel",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="scan_job",
        object_id=job.id,
    )
    await session.commit()
    await session.refresh(job)
    return JobOut.model_validate(job)


@router.post("/projects/{project_id}/scans/delete", response_model=ScanDeleteResult)
async def delete_project_scans(
    project_id: uuid.UUID,
    body: ScanDeleteRequest,
    request: Request,
    principal: Principal = Depends(require_permission("scan.cancel")),
    session: AsyncSession = Depends(get_session),
) -> ScanDeleteResult:
    """Delete one or more finished scans (and their event logs). `purge_data`
    also removes the inventory rows each scan first discovered. Running or
    queued scans are skipped — cancel them first."""
    await _project(session, principal, project_id)
    if body.purge_data:
        principal.require("project.write")

    rows = (
        (
            await session.execute(
                select(ScanJob).where(
                    ScanJob.project_id == project_id,
                    ScanJob.id.in_(body.job_ids),
                    ScanJob.org_id == principal.org.id,
                )
            )
        )
        .scalars()
        .all()
    )
    deletable, skipped = [], []
    for j in rows:
        if j.status.value in scans.TERMINAL_STATUSES:
            deletable.append(j)
        else:
            skipped.append(str(j.id))
    for missing in set(map(str, body.job_ids)) - {str(j.id) for j in rows}:
        skipped.append(missing)
    deletable_ids = [str(j.id) for j in deletable]

    result = {"deleted": 0, "purged": {}}
    if deletable:
        result = await scans.delete_scans(
            session, org_id=principal.org.id, jobs=deletable, purge_data=body.purge_data
        )
        await audit.record(
            session,
            action="scan.delete",
            actor_email=principal.user.email,
            user_id=principal.user.id,
            org_id=principal.org.id,
            ip=client_ip(request),
            object_type="project",
            object_id=project_id,
            after={
                "job_ids": deletable_ids,
                "purge_data": body.purge_data,
                "purged": result["purged"],
            },
            reason=body.reason,
        )
        await session.commit()

    return ScanDeleteResult(deleted=result["deleted"], purged=result["purged"], skipped=skipped)


@router.delete("/jobs/{job_id}", response_model=ScanDeleteResult)
async def delete_job(
    job_id: uuid.UUID,
    request: Request,
    purge_data: bool = False,
    principal: Principal = Depends(require_permission("scan.cancel")),
    session: AsyncSession = Depends(get_session),
) -> ScanDeleteResult:
    job = await _job(session, principal, job_id)
    if purge_data:
        principal.require("project.write")
    if job.status.value not in scans.TERMINAL_STATUSES:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"job is {job.status.value} — cancel it before deleting",
        )
    result = await scans.delete_scans(session, org_id=principal.org.id, jobs=[job], purge_data=purge_data)
    await audit.record(
        session,
        action="scan.delete",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="scan_job",
        object_id=job_id,
        after={"purge_data": purge_data, "purged": result["purged"]},
    )
    await session.commit()
    return ScanDeleteResult(deleted=result["deleted"], purged=result["purged"])


@router.post("/jobs/emergency-stop", status_code=status.HTTP_202_ACCEPTED)
async def emergency_stop(
    request: Request,
    principal: Principal = Depends(require_permission("scan.cancel")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    await scans.emergency_stop_all()
    await audit.record(
        session,
        action="scan.emergency_stop_all",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        reason="operator triggered STOP ALL",
    )
    await session.commit()
    return {"status": "stop signal broadcast to all workers"}


@router.post("/jobs/emergency-stop/clear", status_code=status.HTTP_202_ACCEPTED)
async def clear_emergency_stop(
    principal: Principal = Depends(require_permission("scan.cancel")),
) -> dict[str, str]:
    await scans.clear_emergency_stop()
    return {"status": "workers accepting jobs again"}
