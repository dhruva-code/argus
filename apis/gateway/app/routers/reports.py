"""Assessment reports + the exposure-delta / monitoring endpoint (M6)."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.db import get_session
from app.deps import Principal, client_ip, get_principal, require_permission
from app.models import Project
from app.services.monitoring import exposure_delta
from app.services.reports import FORMATS, render_report

router = APIRouter(prefix="/api", tags=["reports"])


async def _project(session: AsyncSession, principal: Principal, pid: uuid.UUID) -> Project:
    p = await session.get(Project, pid)
    if p is None or p.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return p


@router.get("/projects/{project_id}/report")
async def project_report(
    project_id: uuid.UUID,
    request: Request,
    fmt: str = Query(default="md", alias="format"),
    download: bool = False,
    principal: Principal = Depends(require_permission("report.generate")),
    session: AsyncSession = Depends(get_session),
) -> Response:
    project = await _project(session, principal, project_id)
    if fmt not in FORMATS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"format must be one of: {', '.join(FORMATS)}"
        )
    body, media, filename = await render_report(session, project, fmt)
    await audit.record(
        session,
        action="report.generate",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project_id,
        after={"format": fmt},
    )
    await session.commit()
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(content=body, media_type=media, headers=headers)


@router.get("/projects/{project_id}/exposure-delta")
async def project_exposure_delta(
    project_id: uuid.UUID,
    since: datetime | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict:
    principal.require("project.read")
    await _project(session, principal, project_id)
    return await exposure_delta(session, project_id, since=since)


@router.post("/projects/{project_id}/ai-summary")
async def project_ai_summary(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Read-only AI-assisted analysis of the current findings — executive
    summary, related-finding clusters, remediation order. Uses an LLM when
    `ARGUS_AI_API_KEY` is set, otherwise a deterministic heuristic."""
    principal.require("finding.read")
    project = await _project(session, principal, project_id)
    from sqlalchemy import select

    from app.models import Finding
    from app.services.ai import analyse, available

    findings = (
        (await session.execute(select(Finding).where(Finding.project_id == project_id)))
        .scalars()
        .all()
    )
    result = await analyse(project, findings)
    result["llm_available"] = available()
    return result
