"""Prometheus metrics + advanced analytics (M7)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import Principal, get_principal
from app.models import (
    Asset,
    Finding,
    FindingStatus,
    JobStatus,
    Port,
    Project,
    ScanJob,
    Secret,
)

router = APIRouter(prefix="/api", tags=["metrics"])

# ── request instrumentation ──────────────────────────────────────────────
REQUESTS = Counter("argus_http_requests_total", "HTTP requests", ["method", "path", "status"])
LATENCY = Histogram("argus_http_request_seconds", "HTTP request latency", ["method", "path"])

# ── surface gauges (refreshed on scrape) ─────────────────────────────────
G_PROJECTS = Gauge("argus_projects", "Projects")
G_ACTIVE_JOBS = Gauge("argus_scan_jobs_active", "Queued or running scan jobs")
G_ASSETS = Gauge("argus_assets", "Assets", ["status"])
G_FINDINGS = Gauge("argus_findings", "Findings", ["severity", "status"])
G_SECRETS = Gauge("argus_secrets_open", "Unverified secret candidates")
G_PORTS = Gauge("argus_open_ports", "Open ports")


async def instrument(request: Request, call_next):
    import time

    path = request.scope.get("route").path if request.scope.get("route") else request.url.path
    start = time.perf_counter()
    response = await call_next(request)
    LATENCY.labels(request.method, path).observe(time.perf_counter() - start)
    REQUESTS.labels(request.method, path, response.status_code).inc()
    return response


@router.get("/metrics")
async def metrics(session: AsyncSession = Depends(get_session)) -> PlainTextResponse:
    G_PROJECTS.set(await session.scalar(select(func.count(Project.id))) or 0)
    G_ACTIVE_JOBS.set(
        await session.scalar(
            select(func.count(ScanJob.id)).where(ScanJob.status.in_([JobStatus.queued, JobStatus.running]))
        )
        or 0
    )
    for st in ("alive", "resolved", "dead", "unknown"):
        G_ASSETS.labels(st).set(
            await session.scalar(select(func.count(Asset.id)).where(Asset.status == st)) or 0
        )
    rows = (
        await session.execute(
            select(Finding.severity, Finding.status, func.count(Finding.id)).group_by(
                Finding.severity, Finding.status
            )
        )
    ).all()
    seen = set()
    for sev, stt, n in rows:
        G_FINDINGS.labels(sev.value, stt.value).set(n)
        seen.add((sev.value, stt.value))
    G_SECRETS.set(await session.scalar(select(func.count(Secret.id))) or 0)
    G_PORTS.set(await session.scalar(select(func.count(Port.id))) or 0)
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── advanced analytics ───────────────────────────────────────────────────


@router.get("/projects/{project_id}/analytics")
async def project_analytics(
    project_id: uuid.UUID,
    days: int = 30,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict:
    principal.require("project.read")
    project = await session.get(Project, project_id)
    if project is None or project.org_id != principal.org.id:
        from fastapi import HTTPException, status

        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    since = datetime.now(UTC) - timedelta(days=days)

    findings = (
        (await session.execute(select(Finding).where(Finding.project_id == project_id))).scalars().all()
    )
    # mean time-to-triage for findings that left the auto states
    triaged = [
        max(0.0, (f.updated_at - f.first_seen).total_seconds() / 3600)
        for f in findings
        if f.status in (FindingStatus.confirmed, FindingStatus.false_positive, FindingStatus.fixed)
        and f.updated_at
        and f.first_seen
    ]

    # scan cadence + duration
    scans = (
        (
            await session.execute(
                select(ScanJob)
                .where(
                    ScanJob.project_id == project_id,
                    ScanJob.type == "recon.scan",
                    ScanJob.created_at >= since,
                )
                .order_by(ScanJob.created_at)
            )
        )
        .scalars()
        .all()
    )
    durations = [
        (s.finished_at - s.started_at).total_seconds() / 60 for s in scans if s.started_at and s.finished_at
    ]

    top_templates: dict[str, int] = {}
    top_hosts: dict[str, int] = {}
    for f in findings:
        if f.status == FindingStatus.false_positive:
            continue
        top_templates[f.template_id] = top_templates.get(f.template_id, 0) + 1
        if f.host:
            top_hosts[f.host] = top_hosts.get(f.host, 0) + 1

    fp_rate = (
        sum(1 for f in findings if f.status == FindingStatus.false_positive) / len(findings)
        if findings
        else 0.0
    )

    return {
        "window_days": days,
        "findings_total": len(findings),
        "false_positive_rate": round(fp_rate, 3),
        "mean_hours_to_triage": round(sum(triaged) / len(triaged), 1) if triaged else None,
        "scans_in_window": len(scans),
        "mean_scan_minutes": round(sum(durations) / len(durations), 1) if durations else None,
        "riskiest_hosts": sorted(top_hosts.items(), key=lambda kv: -kv[1])[:10],
        "noisiest_templates": sorted(top_templates.items(), key=lambda kv: -kv[1])[:10],
        "verification_mix": {
            v: sum(1 for f in findings if f.verification == v) for v in {f.verification for f in findings}
        },
    }
