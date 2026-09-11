"""Out-of-band interaction collector for SSRF / RFI verification (§7, §10).

Tokens are self-describing: the first 32 hex characters are the target
project's UUID (hex, no dashes), so a hit can be logged without a prior
"register" round-trip. This is a UUID, not a secret — only ever seen by our
own collector and whatever egress-monitoring the target operator runs.

`GET/POST /api/oast/{token}` is intentionally unauthenticated: it is hit by
the *target* application, not by an Argus user, and must respond regardless of
whether the token turns out to be valid (a 404 here would itself be a signal
to an attacker fingerprinting the collector).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import Principal, get_principal, require_internal
from app.models import OASTEvent, Project

router = APIRouter(tags=["oast"])

_TOKEN_RE = re.compile(r"^[0-9a-f]{48}$")


def _project_id_from_token(token: str) -> uuid.UUID | None:
    if not _TOKEN_RE.match(token):
        return None
    try:
        return uuid.UUID(token[:32])
    except ValueError:
        return None


@router.api_route("/api/oast/{token}", methods=["GET", "POST", "PUT"])
async def oast_hit(
    token: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> PlainTextResponse:
    pid = _project_id_from_token(token)
    if pid is not None:
        project = await session.get(Project, pid)
        if project is not None:
            headers = {k: v for k, v in request.headers.items() if k.lower() in ("user-agent", "host", "x-forwarded-for")}
            summary = f"{request.method} {request.url.path} {headers}"[:2000]
            session.add(
                OASTEvent(
                    org_id=project.org_id,
                    project_id=project.id,
                    token=token,
                    protocol="http",
                    remote_addr=(request.client.host if request.client else ""),
                    request_summary=summary,
                )
            )
            await session.commit()
    # Always a bland, generic response — never confirm/deny token validity.
    return PlainTextResponse("ok")


@router.get("/api/internal/oast/status/{token}")
async def oast_status_internal(
    token: str,
    _: None = Depends(require_internal),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Polled by the orchestrator while a SSRF/RFI test is in flight."""
    row = await session.scalar(
        select(OASTEvent).where(OASTEvent.token == token).order_by(OASTEvent.received_at.desc())
    )
    if row is None:
        return {"hit": False}
    return {
        "hit": True,
        "received_at": row.received_at.isoformat(),
        "remote_addr": row.remote_addr,
        "summary": row.request_summary,
    }


@router.get("/api/projects/{project_id}/oast-events")
async def list_oast_events(
    project_id: uuid.UUID,
    hours: int = 24,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    principal.require("finding.read")
    project = await session.get(Project, project_id)
    if project is None or project.org_id != principal.org.id:
        from fastapi import HTTPException, status

        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = (
        (
            await session.execute(
                select(OASTEvent)
                .where(OASTEvent.project_id == project_id, OASTEvent.received_at >= since)
                .order_by(OASTEvent.received_at.desc())
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": str(r.id),
            "token": r.token,
            "protocol": r.protocol,
            "remote_addr": r.remote_addr,
            "summary": r.request_summary,
            "received_at": r.received_at.isoformat(),
        }
        for r in rows
    ]
