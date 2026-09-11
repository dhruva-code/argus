"""Projects and their scope policies."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.db import get_session
from app.deps import Principal, client_ip, get_principal, require_permission
from app.models import Project, ScopeRule
from app.schemas import (
    ProjectDeletePreview,
    ProjectDeleteRequest,
    ProjectDeleteResult,
    ProjectIn,
    ProjectOut,
    ScopePolicyIn,
    ScopeRuleOut,
    ScopeTestRequest,
    ScopeTestResult,
)
from app.scope import Target, compile_policy
from app.scope.engine import ScopePolicyError
from app.services import projects as project_svc
from app.services.scope_policy import build_policy_dict

router = APIRouter(prefix="/api/projects", tags=["projects"])


async def _get_project(session: AsyncSession, principal: Principal, project_id: uuid.UUID) -> Project:
    project = await session.get(Project, project_id)
    if project is None or project.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return project


async def _to_out(session: AsyncSession, project: Project) -> ProjectOut:
    count = await session.scalar(select(func.count(ScopeRule.id)).where(ScopeRule.project_id == project.id))
    out = ProjectOut.model_validate(project)
    out.scope_rule_count = count or 0
    return out


@router.get("", response_model=list[ProjectOut])
async def list_projects(
    include_archived: bool = False,
    include_deleted: bool = False,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[ProjectOut]:
    principal.require("project.read")
    q = select(Project).where(Project.org_id == principal.org.id)
    if not include_archived:
        q = q.where(Project.is_archived.is_(False))
    if not include_deleted:
        q = q.where(Project.deleted_at.is_(None))
    projects = (await session.execute(q.order_by(Project.created_at.desc()))).scalars().all()
    return [await _to_out(session, p) for p in projects]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: ProjectIn,
    request: Request,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ProjectOut:
    project = Project(org_id=principal.org.id, **body.model_dump())
    session.add(project)
    await session.flush()
    await audit.record(
        session,
        action="project.create",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project.id,
        after=body.model_dump(mode="json"),
    )
    await session.commit()
    await session.refresh(project)
    return await _to_out(session, project)


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> ProjectOut:
    principal.require("project.read")
    project = await _get_project(session, principal, project_id)
    return await _to_out(session, project)


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectIn,
    request: Request,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ProjectOut:
    project = await _get_project(session, principal, project_id)
    before = {c.name: getattr(project, c.name) for c in project.__table__.columns}
    for k, v in body.model_dump().items():
        setattr(project, k, v)
    await audit.record(
        session,
        action="project.update",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project.id,
        before={"name": before["name"], "risk_profile": str(before["risk_profile"])},
        after=body.model_dump(mode="json"),
    )
    await session.commit()
    await session.refresh(project)
    return await _to_out(session, project)


@router.post("/{project_id}/archive", response_model=ProjectOut)
async def archive_project(
    project_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ProjectOut:
    project = await _get_project(session, principal, project_id)
    project.is_archived = True
    await audit.record(
        session,
        action="project.archive",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project.id,
    )
    await session.commit()
    await session.refresh(project)
    return await _to_out(session, project)


# ── Deletion (§18-19) ────────────────────────────────────────────────────
#
# Danger Zone: preview → soft delete (reversible) → permanent delete
# (irreversible, requires the project to already be soft-deleted, and admin
# rights). Every step is audit-logged and requires the caller to retype the
# project's exact name.


@router.get("/{project_id}/deletion-preview", response_model=ProjectDeletePreview)
async def get_deletion_preview(
    project_id: uuid.UUID,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ProjectDeletePreview:
    project = await _get_project(session, principal, project_id)
    counts = await project_svc.deletion_preview(session, project_id)
    return ProjectDeletePreview(project_name=project.name, counts=counts)


@router.post("/{project_id}/delete", response_model=ProjectOut)
async def delete_project(
    project_id: uuid.UUID,
    body: ProjectDeleteRequest,
    request: Request,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ProjectOut:
    """Soft delete — reversible via `/restore`. Stops any in-flight scan jobs
    and archives the project; the inventory is untouched."""
    project = await _get_project(session, principal, project_id)
    if body.confirm_name != project.name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "confirm_name does not match the project name")
    if project.deleted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "project is already deleted")

    stopped = await project_svc.soft_delete_project(session, project)
    await audit.record(
        session,
        action="project.delete.soft",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project.id,
        after={"name": project.name, "jobs_stopped": stopped},
    )
    await session.commit()
    await session.refresh(project)
    return await _to_out(session, project)


@router.post("/{project_id}/restore", response_model=ProjectOut)
async def restore_project(
    project_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_permission("project.write")),
    session: AsyncSession = Depends(get_session),
) -> ProjectOut:
    project = await session.get(Project, project_id)
    if project is None or project.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    if project.deleted_at is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "project is not deleted")
    await project_svc.restore_project(project)
    await audit.record(
        session,
        action="project.restore",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project.id,
    )
    await session.commit()
    await session.refresh(project)
    return await _to_out(session, project)


@router.post("/{project_id}/delete/permanent", response_model=ProjectDeleteResult)
async def delete_project_permanent(
    project_id: uuid.UUID,
    body: ProjectDeleteRequest,
    request: Request,
    principal: Principal = Depends(require_permission("settings.modify")),
    session: AsyncSession = Depends(get_session),
) -> ProjectDeleteResult:
    """Irreversible. Requires the project to already be soft-deleted (the UI's
    Danger Zone flow enforces this ordering) and org-admin rights. Every row
    with a project_id foreign key is ON DELETE CASCADE, so deleting the
    project row removes the entire inventory in one transaction — nothing is
    left orphaned in the database. Redis queue/checkpoint/heartbeat keys for
    the project's jobs are purged explicitly first."""
    project = await session.get(Project, project_id)
    if project is None or project.org_id != principal.org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    if body.confirm_name != project.name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "confirm_name does not match the project name")
    if project.deleted_at is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "project must be soft-deleted first — see POST /delete"
        )

    counts = await project_svc.permanent_delete_project(session, project)
    await audit.record(
        session,
        action="project.delete.permanent",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project_id,
        after={"name": body.confirm_name, "counts": counts},
    )
    await session.commit()
    return ProjectDeleteResult(deleted=True, permanent=True, counts=counts)


# ── Scope ──────────────────────────────────────────────────────────────────


@router.get("/{project_id}/scope", response_model=list[ScopeRuleOut])
async def get_scope(
    project_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[ScopeRuleOut]:
    principal.require("project.read")
    await _get_project(session, principal, project_id)
    rows = (
        (
            await session.execute(
                select(ScopeRule).where(ScopeRule.project_id == project_id).order_by(ScopeRule.position)
            )
        )
        .scalars()
        .all()
    )
    return [ScopeRuleOut.model_validate(r) for r in rows]


@router.put("/{project_id}/scope", response_model=list[ScopeRuleOut])
async def replace_scope(
    project_id: uuid.UUID,
    body: ScopePolicyIn,
    request: Request,
    principal: Principal = Depends(require_permission("scope.write")),
    session: AsyncSession = Depends(get_session),
) -> list[ScopeRuleOut]:
    await _get_project(session, principal, project_id)

    candidate = {
        "rules": [
            {
                "id": f"r{i}",
                "effect": r.effect.value,
                "type": r.matcher.value,
                "value": r.value,
                "ports": r.ports,
                "paths": r.paths,
            }
            for i, r in enumerate(body.rules)
        ]
    }
    try:
        compile_policy(candidate)
    except ScopePolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    old = await build_policy_dict(session, project_id)
    existing = (
        (await session.execute(select(ScopeRule).where(ScopeRule.project_id == project_id))).scalars().all()
    )
    for r in existing:
        await session.delete(r)
    await session.flush()
    for i, r in enumerate(body.rules):
        session.add(
            ScopeRule(
                project_id=project_id,
                position=i,
                effect=r.effect,
                matcher=r.matcher,
                value=r.value.strip(),
                ports=r.ports,
                paths=r.paths,
                note=r.note,
            )
        )
    await audit.record(
        session,
        action="scope.replace",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="project",
        object_id=project_id,
        before=old,
        after=candidate,
        reason=f"{len(body.rules)} rule(s)",
    )
    await session.commit()
    rows = (
        (
            await session.execute(
                select(ScopeRule).where(ScopeRule.project_id == project_id).order_by(ScopeRule.position)
            )
        )
        .scalars()
        .all()
    )
    return [ScopeRuleOut.model_validate(r) for r in rows]


@router.post("/{project_id}/scope/test", response_model=ScopeTestResult)
async def test_scope(
    project_id: uuid.UUID,
    body: ScopeTestRequest,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> ScopeTestResult:
    principal.require("project.read")
    await _get_project(session, principal, project_id)
    policy = await build_policy_dict(session, project_id)
    engine = compile_policy(policy)
    d = engine.evaluate(Target(host=body.host, ip=body.ip, port=body.port, path=body.path, asn=body.asn))
    return ScopeTestResult(allowed=d.allowed, rule_id=d.rule_id, reason=d.reason)
