"""Organizations and membership (read-only membership listing — the
single-admin model has no user-creation/invite/role-assignment mechanism;
see app/bootstrap_admin.py for the one way an account gets created)."""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.types import Email
from app.db import get_session
from app.deps import Principal, client_ip, get_current_user, get_principal
from app.models import Membership, Organization, Role, User
from app.schemas import OrgSummary
from app.seed_profiles import ensure_builtin_profiles

router = APIRouter(prefix="/api/orgs", tags=["organizations"])


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)


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
    session.add(Membership(user_id=user.id, org_id=org.id, role=Role.super_admin))
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
    return OrgSummary(id=org.id, name=org.name, slug=org.slug, role=Role.super_admin)


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
