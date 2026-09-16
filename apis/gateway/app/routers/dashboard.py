"""Executive dashboard aggregates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import Principal, get_principal
from app.models import (
    Asset,
    AssetStatus,
    Endpoint,
    Finding,
    FindingSeverity,
    FindingStatus,
    JobStatus,
    Port,
    Project,
    ScanJob,
    ScopeRule,
    Secret,
    SecretStatus,
    Sensitivity,
    ToolHealth,
    ToolIntegration,
)
from app.schemas import DashboardStats, JobOut

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _exposure_score(tools_missing: int, active_jobs: int, scope_rules: int) -> int:
    """Placeholder 0-100 exposure score for M1.

    Rises with unhealthy tooling and running active work, falls when scope is
    tightly defined. Later milestones replace this with the finding-driven
    Attack Surface Priority Score (spec §50).
    """
    score = 30 + tools_missing * 8 + active_jobs * 5
    score -= min(scope_rules, 10) * 2
    return max(0, min(100, score))


@router.get("", response_model=DashboardStats)
async def dashboard(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> DashboardStats:
    principal.require("project.read")
    org_id = principal.org.id
    now = datetime.now(UTC)

    projects = await session.scalar(
        select(func.count(Project.id)).where(Project.org_id == org_id, Project.is_archived.is_(False))
    )
    scope_rules = await session.scalar(
        select(func.count(ScopeRule.id))
        .select_from(ScopeRule)
        .join(Project, Project.id == ScopeRule.project_id)
        .where(Project.org_id == org_id)
    )

    status_rows = (
        await session.execute(
            select(ScanJob.status, func.count(ScanJob.id))
            .where(ScanJob.org_id == org_id)
            .group_by(ScanJob.status)
        )
    ).all()
    breakdown = {s.value: 0 for s in JobStatus}
    for st, count in status_rows:
        breakdown[st.value] = count
    active_jobs = breakdown["queued"] + breakdown["running"] + breakdown["paused"]

    jobs_24h = await session.scalar(
        select(func.count(ScanJob.id)).where(
            ScanJob.org_id == org_id, ScanJob.created_at >= now - timedelta(hours=24)
        )
    )

    tool_rows = (
        await session.execute(
            select(ToolIntegration.health, func.count(ToolIntegration.id))
            .where(ToolIntegration.org_id == org_id)
            .group_by(ToolIntegration.health)
        )
    ).all()
    th = dict.fromkeys(ToolHealth, 0)
    for h, count in tool_rows:
        th[h] = count

    # 14-day job history
    since = now - timedelta(days=13)
    hist_rows = (
        await session.execute(
            select(func.date(ScanJob.created_at), func.count(ScanJob.id))
            .where(ScanJob.org_id == org_id, ScanJob.created_at >= since)
            .group_by(func.date(ScanJob.created_at))
        )
    ).all()
    hist = {str(d): c for d, c in hist_rows}
    jobs_over_time = [
        {
            "date": (since + timedelta(days=i)).date().isoformat(),
            "count": hist.get((since + timedelta(days=i)).date().isoformat(), 0),
        }
        for i in range(14)
    ]

    recent = (
        (
            await session.execute(
                select(ScanJob).where(ScanJob.org_id == org_id).order_by(ScanJob.created_at.desc()).limit(8)
            )
        )
        .scalars()
        .all()
    )

    assets_total = await session.scalar(select(func.count(Asset.id)).where(Asset.org_id == org_id))
    assets_alive = await session.scalar(
        select(func.count(Asset.id)).where(Asset.org_id == org_id, Asset.status == AssetStatus.alive)
    )
    assets_new = await session.scalar(
        select(func.count(Asset.id)).where(
            Asset.org_id == org_id, Asset.first_seen >= now - timedelta(hours=24)
        )
    )
    secrets_open = await session.scalar(
        select(func.count(Secret.id)).where(Secret.org_id == org_id, Secret.status == SecretStatus.unverified)
    )
    sensitive_paths = await session.scalar(
        select(func.count(Endpoint.id))
        .join(Project, Project.id == Endpoint.project_id)
        .where(
            Project.org_id == org_id,
            Endpoint.sensitivity.in_([Sensitivity.high, Sensitivity.critical]),
        )
    )
    open_ports = await session.scalar(select(func.count(Port.id)).where(Port.org_id == org_id))
    findings_open = await session.scalar(
        select(func.count(Finding.id)).where(
            Finding.org_id == org_id,
            Finding.status.in_([FindingStatus.open, FindingStatus.probable, FindingStatus.needs_review]),
        )
    )
    findings_critical = await session.scalar(
        select(func.count(Finding.id)).where(
            Finding.org_id == org_id,
            Finding.severity.in_([FindingSeverity.high, FindingSeverity.critical]),
            Finding.status != FindingStatus.false_positive,
        )
    )

    return DashboardStats(
        projects=projects or 0,
        active_jobs=active_jobs,
        jobs_last_24h=jobs_24h or 0,
        tools_ok=th[ToolHealth.ok],
        tools_degraded=th[ToolHealth.degraded],
        tools_missing=th[ToolHealth.missing] + th[ToolHealth.unknown],
        scope_rules=scope_rules or 0,
        assets=assets_total or 0,
        assets_alive=assets_alive or 0,
        assets_new_24h=assets_new or 0,
        secrets_open=secrets_open or 0,
        sensitive_paths=sensitive_paths or 0,
        open_ports=open_ports or 0,
        findings_open=findings_open or 0,
        findings_critical=findings_critical or 0,
        exposure_score=_exposure_score(
            th[ToolHealth.missing] + th[ToolHealth.unknown], active_jobs, scope_rules or 0
        ),
        job_status_breakdown=breakdown,
        jobs_over_time=jobs_over_time,
        recent_jobs=[JobOut.model_validate(j) for j in recent],
    )
