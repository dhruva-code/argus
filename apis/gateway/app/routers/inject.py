"""Injection Testing Engine surface (§1-17): the Injection Point Explorer,
per-project coverage overview, manual re-test trigger, and Authentication
Profile CRUD.

Auth Profile secrets are Fernet/Vault encrypted at rest and are never
returned by any endpoint here — `AuthProfileOut` has no secret field. The
orchestrator fetches the decrypted value just-in-time via the internal-token
guarded endpoint at the bottom of this module, and holds it only in memory.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.crypto import decrypt, encrypt
from app.db import get_session
from app.deps import Principal, client_ip, get_principal, require_internal, require_permission
from app.models import AuthProfile, InjectionPoint, Project
from app.schemas import (
    AuthProfileCreate,
    AuthProfileOut,
    InjectionOverviewOut,
    InjectionPointOut,
    JobOut,
)
from app.services import scans
from app.services.injection import injection_overview

router = APIRouter(prefix="/api/projects/{project_id}", tags=["injection"])


async def _project(session: AsyncSession, principal: Principal, pid: uuid.UUID) -> Project:
    p = await session.get(Project, pid)
    if p is None or p.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return p


# ── Injection Point Explorer ────────────────────────────────────────────────


@router.get("/injection/overview", response_model=InjectionOverviewOut)
async def get_injection_overview(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> InjectionOverviewOut:
    principal.require("finding.read")
    await _project(session, principal, project_id)
    data = await injection_overview(session, project_id)
    return InjectionOverviewOut(**data)


@router.get("/injection-points", response_model=list[InjectionPointOut])
async def list_injection_points(
    project_id: uuid.UUID,
    injection_class: str | None = None,
    best_result: str | None = None,
    host: str | None = None,
    limit: int = 200,
    offset: int = 0,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[InjectionPointOut]:
    principal.require("finding.read")
    await _project(session, principal, project_id)

    q = select(InjectionPoint).where(InjectionPoint.project_id == project_id)
    if best_result:
        q = q.where(InjectionPoint.best_result == best_result)
    if host:
        q = q.where(InjectionPoint.host == host)
    if injection_class:
        # candidate_classes is a JSON array column — filter in Python once
        # scoped by the cheaper indexed columns above (result sets here are
        # bounded by `limit`, so this stays inexpensive).
        pass
    rows = (
        (
            await session.execute(
                q.order_by(InjectionPoint.confidence.desc(), InjectionPoint.last_seen.desc())
                .offset(max(offset, 0))
                .limit(min(max(limit, 1), 1000))
            )
        )
        .scalars()
        .all()
    )
    if injection_class:
        rows = [r for r in rows if injection_class in (r.candidate_classes or [])]
    return [InjectionPointOut.model_validate(r) for r in rows]


@router.post("/injection-points/{point_id}/retest", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
async def retest_injection_point(
    project_id: uuid.UUID,
    point_id: uuid.UUID,
    request: Request,
    injection_ack: bool = True,
    principal: Principal = Depends(require_permission("scan.execute")),
    session: AsyncSession = Depends(get_session),
) -> JobOut:
    """Queues a scoped injection_testing re-test job for a single previously
    discovered parameter (§25 Test Replay — scope/rate-limit/auth are all
    re-validated by the orchestrator exactly as a full scan would)."""
    project = await _project(session, principal, project_id)
    point = await session.get(InjectionPoint, point_id)
    if point is None or point.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "injection point not found")
    if not injection_ack:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "injection_ack must be true to re-test — this sends a live payload to the target",
        )

    params = {
        "roots": [point.host] if point.host else [],
        "phases": ["injection_testing"],
        "brute_words": [],
        "profile_key": None,
        "vuln_level": "safe_verify",
        "ssrf_ack": False,
        "retest_injection_point_id": str(point.id),
        "retest_urls": [point.url],
    }
    job = await scans.create_scan_job(
        session,
        project=project,
        job_type="recon.scan",
        params=params,
        rate_limits=scans.DEFAULT_RATE_LIMITS,
        created_by=principal.user.id,
    )
    await audit.record(
        session,
        action="injection_point.retest",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="injection_point",
        object_id=point.id,
        after={"job_id": str(job.id)},
    )
    await session.commit()
    await session.refresh(job)
    await scans.enqueue(session, job)
    return JobOut.model_validate(job)


# ── Authentication Profiles (§17) ───────────────────────────────────────────


@router.get("/auth-profiles", response_model=list[AuthProfileOut])
async def list_auth_profiles(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[AuthProfileOut]:
    principal.require("project.read")
    await _project(session, principal, project_id)
    rows = (
        (
            await session.execute(
                select(AuthProfile).where(AuthProfile.project_id == project_id).order_by(AuthProfile.name)
            )
        )
        .scalars()
        .all()
    )
    return [AuthProfileOut.model_validate(r) for r in rows]


@router.post("/auth-profiles", response_model=AuthProfileOut, status_code=status.HTTP_201_CREATED)
async def create_auth_profile(
    project_id: uuid.UUID,
    body: AuthProfileCreate,
    request: Request,
    principal: Principal = Depends(require_permission("auth_profile.manage")),
    session: AsyncSession = Depends(get_session),
) -> AuthProfileOut:
    project = await _project(session, principal, project_id)
    row = AuthProfile(
        org_id=project.org_id,
        project_id=project.id,
        name=body.name,
        kind=body.kind,
        header_name=body.header_name[:120],
        cookie_name=body.cookie_name[:120],
        location=body.location,
        value_enc=encrypt(body.value),
        created_by=principal.user.id,
    )
    session.add(row)
    await session.flush()
    # Never write the plaintext value into the audit log — only the profile's
    # non-secret metadata.
    await audit.record(
        session,
        action="auth_profile.create",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="auth_profile",
        object_id=row.id,
        after={"name": row.name, "kind": row.kind, "location": row.location},
    )
    await session.commit()
    await session.refresh(row)
    return AuthProfileOut.model_validate(row)


@router.delete("/auth-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_auth_profile(
    project_id: uuid.UUID,
    profile_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_permission("auth_profile.manage")),
    session: AsyncSession = Depends(get_session),
) -> None:
    await _project(session, principal, project_id)
    row = await session.get(AuthProfile, profile_id)
    if row is None or row.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "auth profile not found")
    await audit.record(
        session,
        action="auth_profile.delete",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="auth_profile",
        object_id=row.id,
        after={"name": row.name},
    )
    await session.delete(row)
    await session.commit()


# ── Internal: just-in-time decrypted fetch for the orchestrator ────────────
#
# A separate top-level router (not nested under /projects/{project_id}) since
# the orchestrator only ever has the auth_profile_id, not the project id, at
# the point it needs this. Registered alongside `router` in app.main.

internal_router = APIRouter(prefix="/api/internal", tags=["injection-internal"])


@internal_router.get("/auth-profiles/{profile_id}")
async def get_auth_profile_internal(
    profile_id: uuid.UUID,
    _: None = Depends(require_internal),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Polled once per scan by the orchestrator. Never logs the decrypted
    value — see app.core.crypto and orchestrator/internal/engine/authprofile.go."""
    profile = await session.get(AuthProfile, profile_id)
    if profile is None or not profile.value_enc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "auth profile not found")
    try:
        plaintext = decrypt(profile.value_enc)
    except ValueError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc

    if profile.kind == "bearer":
        header_name, header_value = "Authorization", f"Bearer {plaintext}"
    elif profile.kind == "basic":
        header_name, header_value = "Authorization", f"Basic {plaintext}"
    elif profile.kind == "cookie" or profile.location == "cookie":
        header_name = "Cookie"
        cookie_name = profile.cookie_name or "session"
        header_value = f"{cookie_name}={plaintext}"
    else:  # api_key / oauth_session over a header, or a plain header override
        header_name = profile.header_name or "Authorization"
        header_value = plaintext

    return {"header_name": header_name, "header_value": header_value}
