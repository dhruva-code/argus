"""Read-only audit log (spec §29 — immutable from the normal UI)."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import Principal, require_permission
from app.models import AuditLog
from app.schemas import AuditOut

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditOut])
async def list_audit(
    action: str | None = None,
    object_type: str | None = None,
    since: datetime | None = None,
    limit: int = Query(default=100, le=500),
    principal: Principal = Depends(require_permission("audit.read")),
    session: AsyncSession = Depends(get_session),
) -> list[AuditOut]:
    q = select(AuditLog).where(AuditLog.org_id == principal.org.id)
    if action:
        q = q.where(AuditLog.action == action)
    if object_type:
        q = q.where(AuditLog.object_type == object_type)
    if since:
        q = q.where(AuditLog.at >= since)
    rows = (await session.execute(q.order_by(AuditLog.at.desc()).limit(limit))).scalars().all()
    return [AuditOut.model_validate(r) for r in rows]
