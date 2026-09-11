"""Tool Manager: catalog, configuration, and health-check trigger."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.crypto import encrypt
from app.db import get_session
from app.deps import Principal, client_ip, get_principal, require_permission
from app.models import Project, ScanJob, ToolHealth, ToolIntegration
from app.schemas import JobOut, ToolConfigIn, ToolOut
from app.tool_catalog import BY_NAME, CATALOG

router = APIRouter(prefix="/api/tools", tags=["tools"])


async def _ensure_rows(session: AsyncSession, org_id: uuid.UUID) -> dict[str, ToolIntegration]:
    existing = {
        t.name: t
        for t in (await session.execute(select(ToolIntegration).where(ToolIntegration.org_id == org_id)))
        .scalars()
        .all()
    }
    created = False
    for spec in CATALOG:
        if spec["name"] not in existing:
            row = ToolIntegration(
                org_id=org_id,
                name=spec["name"],
                display_name=spec["display_name"],
                capabilities=spec["capabilities"],
                safety_class=spec["safety_class"],
                needs_api_key=spec["needs_api_key"],
                min_version=spec["min_version"],
                tested_version=spec["tested_version"],
                health=ToolHealth.unknown,
            )
            session.add(row)
            existing[spec["name"]] = row
            created = True
    if created:
        await session.flush()
    return existing


def _to_out(row: ToolIntegration) -> ToolOut:
    out = ToolOut.model_validate(row)
    out.has_api_key = bool(row.api_key_encrypted)
    return out


@router.get("", response_model=list[ToolOut])
async def list_tools(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[ToolOut]:
    principal.require("project.read")
    rows = await _ensure_rows(session, principal.org.id)
    await session.commit()
    return [_to_out(rows[name]) for name in sorted(rows)]


@router.get("/{name}", response_model=ToolOut)
async def get_tool(
    name: str,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> ToolOut:
    principal.require("project.read")
    rows = await _ensure_rows(session, principal.org.id)
    await session.commit()
    if name not in rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown tool")
    return _to_out(rows[name])


@router.patch("/{name}", response_model=ToolOut)
async def configure_tool(
    name: str,
    body: ToolConfigIn,
    request: Request,
    principal: Principal = Depends(require_permission("tool.configure")),
    session: AsyncSession = Depends(get_session),
) -> ToolOut:
    rows = await _ensure_rows(session, principal.org.id)
    if name not in rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown tool")
    row = rows[name]
    changed: dict[str, object] = {}
    if body.enabled is not None:
        row.enabled = body.enabled
        changed["enabled"] = body.enabled
    if body.rate_limit_rps is not None:
        row.rate_limit_rps = body.rate_limit_rps
        changed["rate_limit_rps"] = body.rate_limit_rps
    if body.config is not None:
        row.config = body.config
        changed["config"] = "updated"
    if body.api_key is not None:
        row.api_key_encrypted = encrypt(body.api_key) if body.api_key else None
        changed["api_key"] = "set" if body.api_key else "cleared"

    await audit.record(
        session,
        action="tool.configure",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="tool_integration",
        object_id=row.id,
        after=changed,
    )
    await session.commit()
    await session.refresh(row)
    return _to_out(row)


@router.post("/health-check", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
async def run_health_check(
    request: Request,
    principal: Principal = Depends(require_permission("tool.configure")),
    session: AsyncSession = Depends(get_session),
) -> JobOut:
    """Queue a job that probes every tool binary for presence + version."""
    from app.services import scans

    await _ensure_rows(session, principal.org.id)  # so results have a row to update
    project = await session.scalar(select(Project).where(Project.org_id == principal.org.id).limit(1))
    if project is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "create a project first — health-check jobs are attached to one",
        )
    job = ScanJob(
        org_id=principal.org.id,
        project_id=project.id,
        type="tool.health",
        params={"tools": [t["name"] for t in CATALOG]},
        rate_limits=scans.DEFAULT_RATE_LIMITS,
        created_by=principal.user.id,
    )
    session.add(job)
    await session.flush()
    await audit.record(
        session,
        action="tool.health_check",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="scan_job",
        object_id=job.id,
    )
    await session.commit()
    await session.refresh(job)
    await scans.enqueue(session, job)
    return JobOut.model_validate(job)


# Consumed by the events service when a tool.health result event arrives.
async def apply_health_result(session: AsyncSession, org_id: uuid.UUID, data: dict) -> None:
    name = data.get("tool")
    if not name or name not in BY_NAME:
        return
    row = await session.scalar(
        select(ToolIntegration).where(ToolIntegration.org_id == org_id, ToolIntegration.name == name)
    )
    if row is None:
        return
    state = data.get("state", "unknown")
    try:
        row.health = ToolHealth(state)
    except ValueError:
        row.health = ToolHealth.unknown
    row.installed_version = data.get("installed_version", "") or ""
    row.health_detail = data.get("detail", "") or ""
