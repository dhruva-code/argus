"""Organizations and membership management (minimal for M1)."""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit, security
from app.core.types import Email
from app.db import get_session
from app.deps import Principal, client_ip, get_current_user, get_principal, require_permission
from app.models import Membership, Organization, Role, User
from app.schemas import OrgSummary
from app.seed_profiles import ensure_builtin_profiles

router = APIRouter(prefix="/api/orgs", tags=["organizations"])


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)


class MemberInvite(BaseModel):
    email: Email
    password: str = Field(min_length=12, max_length=200)
    full_name: str = ""
    role: Role = Role.viewer


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: Email
    full_name: str
    role: Role


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "org"


@router.get("", response_model=list[OrgSummary])
async def my_orgs(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[OrgSummary]:
    rows = (
        await session.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.org_id)
            .where(Membership.user_id == user.id)
        )
    ).all()
    return [OrgSummary(id=o.id, name=o.name, slug=o.slug, role=m.role) for m, o in rows]


@router.post("", response_model=OrgSummary, status_code=status.HTTP_201_CREATED)
async def create_org(
    body: OrgCreate,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> OrgSummary:
    org = Organization(name=body.name, slug=f"{_slug(body.name)}-{uuid.uuid4().hex[:6]}")
    session.add(org)
    await session.flush()
    session.add(Membership(user_id=user.id, org_id=org.id, role=Role.org_admin))
    await ensure_builtin_profiles(session, org.id)
    await audit.record(
        session,
        action="org.create",
        actor_email=user.email,
        user_id=user.id,
        org_id=org.id,
        ip=client_ip(request),
        object_type="organization",
        object_id=org.id,
    )
    await session.commit()
    return OrgSummary(id=org.id, name=org.name, slug=org.slug, role=Role.org_admin)


@router.get("/members", response_model=list[MemberOut])
async def list_members(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[MemberOut]:
    principal.require("user.manage")
    rows = (
        await session.execute(
            select(Membership, User)
            .join(User, User.id == Membership.user_id)
            .where(Membership.org_id == principal.org.id)
        )
    ).all()
    return [MemberOut(user_id=u.id, email=u.email, full_name=u.full_name, role=m.role) for m, u in rows]


@router.post("/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def invite_member(
    body: MemberInvite,
    request: Request,
    principal: Principal = Depends(require_permission("user.manage")),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    if body.role == Role.super_admin and not principal.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only a superuser can grant super_admin")
    email = body.email.lower()
    user = await session.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            email=email,
            full_name=body.full_name,
            password_hash=security.hash_password(body.password),
            email_verified=True,  # an org admin invited this exact address directly
        )
        session.add(user)
        await session.flush()
    exists = await session.scalar(
        select(Membership).where(Membership.user_id == user.id, Membership.org_id == principal.org.id)
    )
    if exists:
        raise HTTPException(status.HTTP_409_CONFLICT, "already a member")
    session.add(Membership(user_id=user.id, org_id=principal.org.id, role=body.role))
    await audit.record(
        session,
        action="member.invite",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="user",
        object_id=user.id,
        after={"role": body.role.value},
    )
    await session.commit()
    return MemberOut(user_id=user.id, email=user.email, full_name=user.full_name, role=body.role)


@router.patch("/members/{user_id}", response_model=MemberOut)
async def change_role(
    user_id: uuid.UUID,
    role: Role,
    request: Request,
    principal: Principal = Depends(require_permission("user.manage")),
    session: AsyncSession = Depends(get_session),
) -> MemberOut:
    m = await session.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.org_id == principal.org.id)
    )
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not a member")
    before = m.role
    m.role = role
    u = await session.get(User, user_id)
    await audit.record(
        session,
        action="member.role_change",
        actor_email=principal.user.email,
        user_id=principal.user.id,
        org_id=principal.org.id,
        ip=client_ip(request),
        object_type="user",
        object_id=user_id,
        before={"role": before.value},
        after={"role": role.value},
    )
    await session.commit()
    return MemberOut(user_id=u.id, email=u.email, full_name=u.full_name, role=role)
