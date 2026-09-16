"""Authentication: login (+ MFA), refresh, logout, sessions, profile.

Single bootstrap-admin model — there is no registration, first-run setup
wizard, or forgot-password flow here. The one account is created by
`python -m app.bootstrap_admin` (run automatically by install.sh); see
docs/AUTHENTICATION.md. A logged-in user can still change their own
password via POST /change-password.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit, security
from app.core.ratelimit import clear_failed_attempts, is_locked_out, record_failed_attempt
from app.core.rbac import permissions_for
from app.db import get_session
from app.deps import Principal, client_ip, get_current_user, get_principal
from app.models import Membership, Organization, RefreshToken, User
from app.schemas import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    LoginRequest,
    MeResponse,
    MfaEnrollResponse,
    MfaVerifyRequest,
    OrgSummary,
    RefreshRequest,
    SessionOut,
    TokenPair,
    UpdateProfileRequest,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


async def _issue_pair(session: AsyncSession, user: User, *, ip: str = "", user_agent: str = "") -> TokenPair:
    access, exp = security.create_token(str(user.id), "access")
    jti = uuid.uuid4().hex
    refresh, r_exp = security.create_token(str(user.id), "refresh", jti=jti)
    session.add(
        RefreshToken(
            user_id=user.id,
            jti=jti,
            expires_at=r_exp,
            ip=ip[:64],
            user_agent=user_agent[:300],
            last_used_at=datetime.now(UTC),
        )
    )
    user.last_login_at = datetime.now(UTC)
    await session.commit()
    return TokenPair(access_token=access, refresh_token=refresh, expires_at=exp)


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenPair:
    ip = client_ip(request)
    locked, retry_after = await is_locked_out(ip)
    if locked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"too many failed login attempts — try again in {retry_after}s",
            headers={"Retry-After": str(retry_after)},
        )

    user = await session.scalar(select(User).where(User.email == body.email.lower()))
    # Constant-ish work whether or not the user exists.
    ok = user is not None and security.verify_password(body.password, user.password_hash)
    if not ok or not user.is_active:
        await record_failed_attempt(ip)
        await audit.record(
            session,
            action="auth.login_failed",
            actor_email=body.email.lower(),
            ip=ip,
            after={"reason": "invalid_credentials" if not ok else "inactive_account"},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if user.mfa_enabled:
        if not body.mfa_code:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mfa_code required")
        if not security.verify_mfa(user.mfa_secret or "", body.mfa_code):
            await record_failed_attempt(ip)
            await audit.record(
                session,
                action="auth.login_failed",
                actor_email=user.email,
                user_id=user.id,
                ip=ip,
                after={"reason": "invalid_mfa"},
            )
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid mfa code")
    await clear_failed_attempts(ip)
    await audit.record(session, action="auth.login", actor_email=user.email, user_id=user.id, ip=ip)
    return await _issue_pair(session, user, ip=ip, user_agent=request.headers.get("user-agent", ""))


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    body: RefreshRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenPair:
    try:
        payload = security.decode_token(body.refresh_token, expected_kind="refresh")
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    row = await session.scalar(select(RefreshToken).where(RefreshToken.jti == payload["jti"]))
    if row is None or row.revoked or security.ensure_aware(row.expires_at) < datetime.now(UTC):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "refresh token not valid")
    row.revoked = True  # rotate
    user = await session.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user inactive")
    return await _issue_pair(
        session, user, ip=client_ip(request), user_agent=request.headers.get("user-agent", "")
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, session: AsyncSession = Depends(get_session)) -> None:
    try:
        payload = security.decode_token(body.refresh_token, expected_kind="refresh")
    except ValueError:
        return
    row = await session.scalar(select(RefreshToken).where(RefreshToken.jti == payload["jti"]))
    if row:
        row.revoked = True
        await session.commit()


@router.get("/me", response_model=MeResponse)
async def me(
    user: User = Depends(get_current_user),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> MeResponse:
    rows = (
        await session.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.org_id)
            .where(Membership.user_id == user.id)
        )
    ).all()
    orgs = [OrgSummary(id=o.id, name=o.name, slug=o.slug, role=m.role) for m, o in rows]
    return MeResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_superuser=user.is_superuser,
        mfa_enabled=user.mfa_enabled,
        email_verified=user.email_verified,
        timezone=user.timezone,
        language=user.language,
        avatar_url=user.avatar_url,
        theme=user.theme,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        organizations=orgs,
        active_org=principal.org.id,
        role=principal.role,
        permissions=sorted(permissions_for(principal.role, is_superuser=user.is_superuser)),
    )


@router.patch("/me", response_model=MeResponse)
async def update_profile(
    body: UpdateProfileRequest,
    user: User = Depends(get_current_user),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> MeResponse:
    if body.full_name is not None:
        user.full_name = body.full_name[:200]
    if body.timezone is not None:
        user.timezone = body.timezone[:64]
    if body.language is not None:
        user.language = body.language[:16]
    if body.theme is not None:
        user.theme = body.theme
    await session.commit()
    return await me(user=user, principal=principal, session=session)


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> MfaEnrollResponse:
    secret = security.new_mfa_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    await session.commit()
    return MfaEnrollResponse(secret=secret, otpauth_uri=security.mfa_provisioning_uri(secret, user.email))


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_verify(
    body: MfaVerifyRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    if not user.mfa_secret or not security.verify_mfa(user.mfa_secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = True
    await session.commit()


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(
    body: MfaVerifyRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    if not user.mfa_enabled or not security.verify_mfa(user.mfa_secret or "", body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = False
    user.mfa_secret = None
    await session.commit()


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    if not security.verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is incorrect")
    user.password_hash = security.hash_password(body.new_password)
    await audit.record(
        session, action="user.password_change", actor_email=user.email, user_id=user.id, ip=client_ip(request)
    )
    await session.commit()


# ── Sessions (§18-19) ────────────────────────────────────────────────────


@router.get("/sessions", response_model=list[SessionOut])
async def list_sessions(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[SessionOut]:
    # The access token doesn't carry the refresh jti, so there's no reliable
    # way to mark "this one" as current from an access-token-authenticated
    # request — `current` is always false here; the frontend already knows
    # which session it holds locally. Lists every non-revoked, non-expired
    # session without guessing.
    current_jti = None
    rows = (
        (
            await session.execute(
                select(RefreshToken)
                .where(
                    RefreshToken.user_id == user.id,
                    RefreshToken.revoked.is_(False),
                    RefreshToken.expires_at > datetime.now(UTC),
                )
                .order_by(RefreshToken.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [
        SessionOut(
            id=r.id,
            ip=r.ip,
            user_agent=r.user_agent,
            created_at=r.created_at,
            last_used_at=r.last_used_at,
            expires_at=r.expires_at,
            current=(r.jti == current_jti),
        )
        for r in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    row = await session.get(RefreshToken, session_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    row.revoked = True
    await session.commit()


@router.post("/sessions/revoke-all", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_sessions(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> None:
    await session.execute(
        RefreshToken.__table__.update().where(RefreshToken.user_id == user.id).values(revoked=True)
    )
    await session.commit()


# ── Account export / deletion (§18) ─────────────────────────────────────


@router.get("/account/export")
async def export_account(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> dict:
    rows = (
        await session.execute(
            select(Membership, Organization)
            .join(Organization, Organization.id == Membership.org_id)
            .where(Membership.user_id == user.id)
        )
    ).all()
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "timezone": user.timezone,
        "language": user.language,
        "theme": user.theme,
        "email_verified": user.email_verified,
        "mfa_enabled": user.mfa_enabled,
        "created_at": user.created_at.isoformat(),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "organizations": [{"id": str(o.id), "name": o.name, "role": m.role.value} for m, o in rows],
    }


@router.post("/account/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    body: DeleteAccountRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    if not security.verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "password is incorrect")
    if body.confirm.strip().lower() != user.email.lower():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "type your account email exactly to confirm deletion"
        )

    rows = (await session.execute(select(Membership).where(Membership.user_id == user.id))).scalars().all()
    orgs_to_delete: list[uuid.UUID] = []
    for m in rows:
        other_members = await session.scalar(
            select(func.count(Membership.id)).where(
                Membership.org_id == m.org_id, Membership.user_id != user.id
            )
        )
        if not other_members:
            # This user is the org's only member at all — it's their solo
            # workspace; deleting the account takes it (and everything in
            # it — projects, findings, evidence, everything) with it, same
            # as §30's "no orphaned records" for project deletion. If other
            # members exist, the org is simply left to them (there is only
            # one role now, so any remaining member can manage it).
            orgs_to_delete.append(m.org_id)

    await audit.record(
        session,
        action="user.account_delete",
        actor_email=user.email,
        user_id=user.id,
        ip=client_ip(request),
        after={"deleted_solo_orgs": [str(o) for o in orgs_to_delete]},
    )
    for org_id in orgs_to_delete:
        org = await session.get(Organization, org_id)
        if org is not None:
            await session.delete(org)  # cascades every project/asset/finding/etc. that org owned
    await session.delete(user)  # memberships cascade
    await session.commit()
