"""Scan profiles (read + clone)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import Principal, get_principal, require_permission
from app.models import ScanProfile
from app.schemas import ScanProfileOut
from app.seed_profiles import ensure_builtin_profiles

router = APIRouter(prefix="/api/scan-profiles", tags=["scan-profiles"])


@router.get("", response_model=list[ScanProfileOut])
async def list_profiles(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[ScanProfileOut]:
    principal.require("project.read")
    await ensure_builtin_profiles(session, principal.org.id)
    await session.commit()
    rows = (
        (
            await session.execute(
                select(ScanProfile)
                .where((ScanProfile.org_id == principal.org.id) | (ScanProfile.org_id.is_(None)))
                .order_by(ScanProfile.is_builtin.desc(), ScanProfile.name)
            )
        )
        .scalars()
        .all()
    )
    return [ScanProfileOut.model_validate(r) for r in rows]


@router.post("/{profile_id}/clone", response_model=ScanProfileOut, status_code=201)
async def clone_profile(
    profile_id: uuid.UUID,
    name: str,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ScanProfileOut:
    src = await session.get(ScanProfile, profile_id)
    if src is None or (src.org_id not in (None, principal.org.id)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    clone = ScanProfile(
        org_id=principal.org.id,
        key=f"custom-{uuid.uuid4().hex[:8]}",
        name=name,
        description=f"Cloned from {src.name}",
        is_builtin=False,
        phases=dict(src.phases),
        rate_limits=dict(src.rate_limits),
        requires_active_ack=src.requires_active_ack,
    )
    session.add(clone)
    await session.commit()
    await session.refresh(clone)
    return ScanProfileOut.model_validate(clone)
