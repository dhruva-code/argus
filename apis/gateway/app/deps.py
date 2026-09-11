"""Shared FastAPI dependencies: authentication, org context, RBAC."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core import rbac, security
from app.db import get_session
from app.models import Membership, Organization, Role, User

_bearer = HTTPBearer(auto_error=False)


@dataclass
class Principal:
    user: User
    org: Organization
    role: Role
    permissions: set[str]

    @property
    def is_superuser(self) -> bool:
        return self.user.is_superuser

    def require(self, permission: str) -> None:
        if permission not in self.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing permission: {permission}",
            )


async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(get_session),
) -> User:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        payload = security.decode_token(creds.credentials, expected_kind="access")
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    user = await session.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
    return user


async def get_principal(
    request: Request,
    x_org_id: str | None = Header(default=None, alias="X-Org-Id"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> Principal:
    q = select(Membership).where(Membership.user_id == user.id)
    memberships = (await session.execute(q)).scalars().all()
    if not memberships:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "user has no organization membership")

    membership = None
    if x_org_id:
        try:
            want = uuid.UUID(x_org_id)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid X-Org-Id") from exc
        membership = next((m for m in memberships if m.org_id == want), None)
        if membership is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not a member of that organization")
    else:
        membership = memberships[0]

    org = await session.get(Organization, membership.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")

    perms = rbac.permissions_for(membership.role, is_superuser=user.is_superuser)
    return Principal(user=user, org=org, role=membership.role, permissions=perms)


def require_permission(permission: str):
    async def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        principal.require(permission)
        return principal

    return _dep


async def require_internal(
    x_internal_token: str | None = Header(default=None, alias="X-Internal-Token"),
) -> None:
    """Guards endpoints only the orchestrator may call."""
    if not settings.orch_internal_token or x_internal_token != settings.orch_internal_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "internal token required")


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""
