"""Injection Testing Engine persistence (§1-17 of the platform enhancement
spec): `injection_points` upserts (the row behind the Injection Point
Explorer), the overview aggregation for the dashboard, and Authentication
Profile secret handling.

Auth Profile secrets are Fernet/Vault encrypted at rest (`app.core.crypto`)
and are only ever decrypted for the just-in-time internal fetch the
orchestrator makes per scan — never returned by any user-facing endpoint,
never logged.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Endpoint, InjectionPoint


def _now() -> datetime:
    return datetime.now(UTC)


async def upsert_injection_point(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    data: dict[str, Any],
) -> None:
    method = str(data.get("method", "GET")).upper()[:10]
    url = str(data.get("url", "")).strip()
    param_name = str(data.get("param_name", "")).strip()
    location = str(data.get("location", "query"))[:20]
    if not url or not param_name:
        return

    row = await session.scalar(
        select(InjectionPoint).where(
            InjectionPoint.project_id == project_id,
            InjectionPoint.method == method,
            InjectionPoint.url == url,
            InjectionPoint.param_name == param_name,
            InjectionPoint.location == location,
        )
    )
    is_new = row is None
    if is_new:
        row = InjectionPoint(
            org_id=org_id,
            project_id=project_id,
            method=method,
            url=url[:2000],
            param_name=param_name[:200],
            location=location,
            first_seen=_now(),
            first_seen_scan=scan_id,
        )
        session.add(row)
        host = str(data.get("host", ""))[:300]
        ep = await session.scalar(
            select(Endpoint).where(
                Endpoint.project_id == project_id,
                Endpoint.method == method,
                Endpoint.host == host,
            )
        )
        if ep is not None:
            row.endpoint_id = ep.id

    row.last_seen = _now()
    row.host = str(data.get("host", ""))[:300] or row.host
    row.param_type = str(data.get("param_type", "unknown"))[:20]
    row.context = str(data.get("context", ""))[:20]
    tech = data.get("technology") or []
    if isinstance(tech, list) and tech:
        row.technology = ", ".join(str(t) for t in tech)[:300]
    row.auth_state = str(data.get("auth_state", "unauthenticated"))[:40]
    row.candidate_classes = [str(c) for c in (data.get("candidate_classes") or [])]
    row.tested_classes = [str(c) for c in (data.get("tested_classes") or [])]
    row.best_result = str(data.get("best_result", "untested"))[:20]
    row.confidence = int(data.get("confidence") or 0)
    row.last_tested = _now()


async def injection_overview(session: AsyncSession, project_id: uuid.UUID) -> dict[str, Any]:
    """Dashboard cards + per-class coverage (§13, §51 "Testing Coverage" —
    never claims 100% unless the numbers actually show it)."""
    total = await session.scalar(
        select(func.count()).select_from(InjectionPoint).where(InjectionPoint.project_id == project_id)
    )
    tested = await session.scalar(
        select(func.count())
        .select_from(InjectionPoint)
        .where(InjectionPoint.project_id == project_id, InjectionPoint.best_result != "untested")
    )
    by_result = dict(
        (
            await session.execute(
                select(InjectionPoint.best_result, func.count())
                .where(InjectionPoint.project_id == project_id)
                .group_by(InjectionPoint.best_result)
            )
        ).all()
    )
    rows = (
        await session.execute(
            select(InjectionPoint.candidate_classes, InjectionPoint.tested_classes).where(
                InjectionPoint.project_id == project_id
            )
        )
    ).all()
    candidate_counts: dict[str, int] = {}
    tested_counts: dict[str, int] = {}
    for candidates, tested_classes in rows:
        for c in candidates or []:
            candidate_counts[c] = candidate_counts.get(c, 0) + 1
        for c in tested_classes or []:
            tested_counts[c] = tested_counts.get(c, 0) + 1
    coverage = {
        cls: {
            "candidates": candidate_counts.get(cls, 0),
            "tested": tested_counts.get(cls, 0),
            "coverage_pct": round(100 * tested_counts.get(cls, 0) / candidate_counts[cls], 1)
            if candidate_counts.get(cls)
            else 0.0,
        }
        for cls in candidate_counts
    }
    total = total or 0
    tested = tested or 0
    return {
        "total_points": total,
        "tested_points": tested,
        "untested_points": total - tested,
        "coverage_pct": round(100 * tested / total, 1) if total else 0.0,
        "by_result": by_result,
        "by_class": coverage,
    }
