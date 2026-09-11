"""Append-only audit trail helper.

Audit rows are never updated or deleted through the API (spec §29). The only
retention path is the scheduled retention job (later milestone), which deletes
rows older than the org's ``retention_audit_days``.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog


async def record(
    session: AsyncSession,
    *,
    action: str,
    actor_email: str = "",
    user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    ip: str = "",
    object_type: str = "",
    object_id: str = "",
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    reason: str = "",
) -> None:
    session.add(
        AuditLog(
            action=action,
            actor_email=actor_email,
            user_id=user_id,
            org_id=org_id,
            ip=ip,
            object_type=object_type,
            object_id=str(object_id),
            before=before,
            after=after,
            reason=reason,
        )
    )
    # Caller commits with the rest of the unit of work.
