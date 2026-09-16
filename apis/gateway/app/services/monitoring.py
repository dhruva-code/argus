"""Continuous-monitoring / exposure-delta engine (M6).

Compares the current attack surface against a point in time (by default the
finish of the previous recon scan) and reports what appeared, what changed and
what went away.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, Finding, Port, ScanJob, Secret


async def _last_two_recon_scans(
    session: AsyncSession, project_id: uuid.UUID
) -> tuple[ScanJob | None, ScanJob | None]:
    rows = (
        (
            await session.execute(
                select(ScanJob)
                .where(
                    ScanJob.project_id == project_id,
                    ScanJob.type == "recon.scan",
                    ScanJob.finished_at.is_not(None),
                )
                .order_by(ScanJob.finished_at.desc())
                .limit(2)
            )
        )
        .scalars()
        .all()
    )
    current = rows[0] if rows else None
    previous = rows[1] if len(rows) > 1 else None
    return current, previous


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _asset_row(a: Asset) -> dict[str, Any]:
    return {
        "type": a.type.value if hasattr(a.type, "value") else str(a.type),
        "value": a.value,
        "status": a.status.value if hasattr(a.status, "value") else str(a.status),
    }


async def exposure_delta(
    session: AsyncSession,
    project_id: uuid.UUID,
    *,
    since: datetime | None = None,
) -> dict[str, Any]:
    current, previous = await _last_two_recon_scans(session, project_id)
    baseline = _aware(since or (previous.finished_at if previous else None))

    def _new(row) -> bool:
        return bool(row.first_seen) and _aware(row.first_seen) >= baseline

    def _gone(row) -> bool:
        return bool(row.last_seen) and _aware(row.last_seen) < baseline

    result: dict[str, Any] = {
        "baseline": baseline.isoformat() if baseline else None,
        "current_scan": str(current.id) if current else None,
        "previous_scan": str(previous.id) if previous else None,
        "has_baseline": baseline is not None,
        "new": {},
        "resolved": {},
        "counts": {},
    }
    if baseline is None:
        return result

    async def rows(model, extra=None):
        stmt = select(model).where(model.project_id == project_id)
        if extra is not None:
            stmt = stmt.where(extra)
        return (await session.execute(stmt)).scalars().all()

    # assets
    assets = await rows(Asset)
    new_assets = [a for a in assets if _new(a)]
    gone_assets = [a for a in assets if _gone(a)]
    result["new"]["assets"] = [_asset_row(a) for a in new_assets][:200]
    result["resolved"]["assets"] = [_asset_row(a) for a in gone_assets][:200]

    # findings
    fnds = await rows(Finding)
    new_f = [f for f in fnds if _new(f)]
    gone_f = [f for f in fnds if _gone(f)]
    result["new"]["findings"] = [
        {
            "severity": f.severity.value,
            "name": f.name or f.template_id,
            "host": f.host,
            "status": f.status.value,
        }
        for f in sorted(new_f, key=lambda f: f.confidence, reverse=True)
    ][:200]
    result["resolved"]["findings"] = [
        {"severity": f.severity.value, "name": f.name or f.template_id, "host": f.host} for f in gone_f
    ][:200]

    # ports & secrets (counts + samples)
    ports = await rows(Port)
    secrets = await rows(Secret)
    new_ports = [p for p in ports if _new(p)]
    new_secrets = [s for s in secrets if _new(s)]
    result["new"]["ports"] = [{"ip": p.ip, "port": p.port, "service": p.service} for p in new_ports][:200]
    result["new"]["secrets"] = [{"type": s.detector_type, "location": s.location} for s in new_secrets][:200]

    result["counts"] = {
        "new_assets": len(new_assets),
        "resolved_assets": len(gone_assets),
        "new_findings": len(new_f),
        "resolved_findings": len(gone_f),
        "new_ports": len(new_ports),
        "new_secrets": len(new_secrets),
    }
    return result
