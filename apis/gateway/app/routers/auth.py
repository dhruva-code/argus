"""Authentication: first-run setup, registration + email verification,
password reset, login (+ MFA), refresh, logout, sessions, profile."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core import audit, security
from app.core.email import EmailSendError, get_email_provider
from app.core.rbac import permissions_for
from app.db import get_session
from app.deps import Principal, client_ip, get_current_user, get_principal
from app.models import Membership, Organization, RefreshToken, Role, User
from app.schemas import (
    ChangeEmailRequest,
    ChangePasswordRequest,
    DeleteAccountRequest,
    LoginRequest,
    MeResponse,
    MfaEnrollResponse,
    MfaVerifyRequest,
    OrgSummary,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    RequestPasswordResetRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SessionOut,
    SetupRequest,
    TokenPair,
    UpdateProfileRequest,
    VerifyEmailRequest,
)
from app.seed_profiles import ensure_builtin_profiles

router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_VERIFY_TTL_HOURS = 48
PASSWORD_RESET_TTL_HOURS = 2


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _new_raw_token() -> str:
    return secrets.token_urlsafe(32)


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "org"


async def _users_exist(session: AsyncSession) -> bool:
    return (await session.scalar(select(func.count(User.id)))) > 0


async def _issue_pair(
    session: AsyncSession, user: User, *, ip: str = "", user_agent: str = ""
) -> TokenPair:
    access, exp = security.create_token(str(user.id), "access")
    jti = uuid.uuid4().hex
    refresh, r_exp = security.create_token(str(user.id), "refresh", jti=jti)
    session.add(
        RefreshToken(
            user_id=user.id, jti=jti, expires_at=r_exp, ip=ip[:64], user_agent=user_agent[:300],
            last_used_at=datetime.now(UTC),
        )
    )
    user.last_login_at = datetime.now(UTC)
    await session.commit()
    return TokenPair(access_token=access, refresh_token=refresh, expires_at=exp)


@router.get("/setup-required")
async def setup_required(session: AsyncSession = Depends(get_session)) -> dict[str, bool]:
    return {"setup_required": settings.allow_setup and not await _users_exist(session)}


@router.post("/setup", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
async def first_run_setup(
    body: SetupRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenPair:
    if not settings.allow_setup:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "setup is disabled")
    if await _users_exist(session):
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed")

    org = Organization(name=body.org_name, slug=_slugify(body.org_name))
    session.add(org)
    await session.flush()

    user = User(
        email=body.admin_email.lower(),
        full_name=body.admin_name,
        password_hash=security.hash_password(body.admin_password),
        is_superuser=True,
        email_verified=True,  # trusted first-run flow — no inbox to verify against yet
    )
    session.add(user)
    await session.flush()
    session.add(Membership(user_id=user.id, org_id=org.id, role=Role.org_admin))

    await ensure_builtin_profiles(session, org.id)
    await audit.record(
        session,
        action="setup.complete",
        actor_email=user.email,
        user_id=user.id,
        org_id=org.id,
        ip=client_ip(request),
        object_type="organization",
        object_id=org.id,
    )
    return await _issue_pair(session, user, ip=client_ip(request), user_agent=request.headers.get("user-agent", ""))


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenPair:
    user = await session.scalar(select(User).where(User.email == body.email.lower()))
    # Constant-ish work whether or not the user exists.
    ok = user is not None and security.verify_password(body.password, user.password_hash)
    if not ok or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not user.email_verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "email not verified — check your inbox or request a new verification email")
    if user.mfa_enabled:
        if not body.mfa_code:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "mfa_code required")
        if not security.verify_mfa(user.mfa_secret or "", body.mfa_code):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid mfa code")
    await audit.record(
        session, action="auth.login", actor_email=user.email, user_id=user.id, ip=client_ip(request)
    )
    return await _issue_pair(session, user, ip=client_ip(request), user_agent=request.headers.get("user-agent", ""))


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
    return await _issue_pair(session, user, ip=client_ip(request), user_agent=request.headers.get("user-agent", ""))


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


# ── Registration + email verification (§5-7) ────────────────────────────────
#
# Proton addresses (@proton.me, @protonmail.com) work exactly like any other
# address here — app.core.types.Email has no provider allowlist. This is
# email-address compatibility, not Proton-as-identity-provider; see
# docs/AUTHENTICATION.md for why the latter isn't offered.


_log = logging.getLogger("argus.auth")


async def _send_verification_email(user: User, raw_token: str) -> None:
    base = settings.cors_origin_list[0] if settings.cors_origin_list else "http://localhost:3000"
    link = f"{base}/verify-email?token={raw_token}"
    body = (
        f"Welcome to Argus.\n\nVerify your email address to activate your account:\n{link}\n\n"
        f"This link expires in {EMAIL_VERIFY_TTL_HOURS} hours. If you didn't request this, ignore this email."
    )
    try:
        get_email_provider().send(user.email, "Verify your Argus account", body)
    except EmailSendError as exc:
        _log.warning("verification email not sent to %s: %s", user.email, exc)


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> RegisterResponse:
    email = body.email.lower()
    existing = await session.scalar(select(User).where(User.email == email))
    if existing is not None:
        # Don't reveal whether the address is already registered.
        return RegisterResponse(message="If that address can be registered, a verification email was sent.", email=email)

    raw_token = _new_raw_token()
    user = User(
        email=email,
        full_name=body.full_name,
        password_hash=security.hash_password(body.password),
        email_verified=False,
        email_verify_token_hash=_hash_token(raw_token),
        email_verify_expires=datetime.now(UTC) + timedelta(hours=EMAIL_VERIFY_TTL_HOURS),
    )
    session.add(user)
    await session.flush()

    org_name = body.org_name.strip() or f"{email.split('@')[0]}'s workspace"
    org = Organization(name=org_name, slug=_slugify(org_name) + "-" + uuid.uuid4().hex[:6])
    session.add(org)
    await session.flush()
    session.add(Membership(user_id=user.id, org_id=org.id, role=Role.org_admin))
    await ensure_builtin_profiles(session, org.id)

    await audit.record(
        session, action="user.register", actor_email=email, user_id=user.id, org_id=org.id,
        ip=client_ip(request), object_type="user", object_id=user.id,
    )
    await session.commit()
    await _send_verification_email(user, raw_token)
    return RegisterResponse(message="Account created — check your email to verify it.", email=email)


@router.post("/verify-email", response_model=TokenPair)
async def verify_email(
    body: VerifyEmailRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenPair:
    token_hash = _hash_token(body.token)
    user = await session.scalar(select(User).where(User.email_verify_token_hash == token_hash))
    if user is None or not user.email_verify_expires or security.ensure_aware(user.email_verify_expires) < datetime.now(UTC):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired verification link")

    if user.pending_email:
        # This verification is for a change-email request, not first signup.
        user.email = user.pending_email
        user.pending_email = None
    user.email_verified = True
    user.email_verify_token_hash = None
    user.email_verify_expires = None
    await audit.record(
        session, action="user.email_verified", actor_email=user.email, user_id=user.id, ip=client_ip(request)
    )
    return await _issue_pair(session, user, ip=client_ip(request), user_agent=request.headers.get("user-agent", ""))


@router.post("/resend-verification", status_code=status.HTTP_204_NO_CONTENT)
async def resend_verification(
    body: ResendVerificationRequest, session: AsyncSession = Depends(get_session)
) -> None:
    user = await session.scalar(select(User).where(User.email == body.email.lower()))
    if user is None or user.email_verified:
        return  # don't reveal account existence/state
    raw_token = _new_raw_token()
    user.email_verify_token_hash = _hash_token(raw_token)
    user.email_verify_expires = datetime.now(UTC) + timedelta(hours=EMAIL_VERIFY_TTL_HOURS)
    await session.commit()
    await _send_verification_email(user, raw_token)


# ── Password reset ───────────────────────────────────────────────────────


@router.post("/request-password-reset", status_code=status.HTTP_204_NO_CONTENT)
async def request_password_reset(
    body: RequestPasswordResetRequest, session: AsyncSession = Depends(get_session)
) -> None:
    user = await session.scalar(select(User).where(User.email == body.email.lower()))
    if user is None:
        return  # don't reveal account existence
    raw_token = _new_raw_token()
    user.password_reset_token_hash = _hash_token(raw_token)
    user.password_reset_expires = datetime.now(UTC) + timedelta(hours=PASSWORD_RESET_TTL_HOURS)
    await session.commit()

    base = settings.cors_origin_list[0] if settings.cors_origin_list else "http://localhost:3000"
    link = f"{base}/reset-password?token={raw_token}"
    body_text = (
        f"A password reset was requested for your Argus account.\n\n{link}\n\n"
        f"This link expires in {PASSWORD_RESET_TTL_HOURS} hours. If you didn't request this, ignore this email — "
        "your password has not been changed."
    )
    try:
        get_email_provider().send(user.email, "Reset your Argus password", body_text)
    except EmailSendError:
        pass  # never leak provider errors to an unauthenticated caller


@router.post("/reset-password", response_model=TokenPair)
async def reset_password(
    body: ResetPasswordRequest, request: Request, session: AsyncSession = Depends(get_session)
) -> TokenPair:
    token_hash = _hash_token(body.token)
    user = await session.scalar(select(User).where(User.password_reset_token_hash == token_hash))
    if user is None or not user.password_reset_expires or security.ensure_aware(user.password_reset_expires) < datetime.now(UTC):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid or expired reset link")
    user.password_hash = security.hash_password(body.new_password)
    user.password_reset_token_hash = None
    user.password_reset_expires = None
    # Revoke every existing session — a password reset should log everything out.
    await session.execute(
        RefreshToken.__table__.update().where(RefreshToken.user_id == user.id).values(revoked=True)
    )
    await audit.record(
        session, action="user.password_reset", actor_email=user.email, user_id=user.id, ip=client_ip(request)
    )
    return await _issue_pair(session, user, ip=client_ip(request), user_agent=request.headers.get("user-agent", ""))


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


@router.post("/change-email", status_code=status.HTTP_204_NO_CONTENT)
async def change_email(
    body: ChangeEmailRequest,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    if not security.verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is incorrect")
    new_email = body.new_email.lower()
    if new_email == user.email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "that is already your current email")
    taken = await session.scalar(select(User).where(User.email == new_email))
    if taken is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "that email is already in use")
    raw_token = _new_raw_token()
    user.pending_email = new_email
    user.email_verify_token_hash = _hash_token(raw_token)
    user.email_verify_expires = datetime.now(UTC) + timedelta(hours=EMAIL_VERIFY_TTL_HOURS)
    await audit.record(
        session, action="user.email_change_requested", actor_email=user.email, user_id=user.id,
        ip=client_ip(request), after={"pending_email": new_email},
    )
    await session.commit()
    # Send the verification link to the NEW address — proves they control it.
    temp = User(email=new_email, full_name=user.full_name, password_hash="")
    await _send_verification_email(temp, raw_token)


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
        await session.execute(
            select(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False), RefreshToken.expires_at > datetime.now(UTC))
            .order_by(RefreshToken.created_at.desc())
        )
    ).scalars().all()
    return [
        SessionOut(
            id=r.id, ip=r.ip, user_agent=r.user_agent, created_at=r.created_at,
            last_used_at=r.last_used_at, expires_at=r.expires_at, current=(r.jti == current_jti),
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
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "type your account email exactly to confirm deletion")

    rows = (
        await session.execute(select(Membership).where(Membership.user_id == user.id))
    ).scalars().all()
    orgs_to_delete: list[uuid.UUID] = []
    blocked_orgs: list[uuid.UUID] = []
    for m in rows:
        other_members = await session.scalar(
            select(func.count(Membership.id)).where(Membership.org_id == m.org_id, Membership.user_id != user.id)
        )
        if other_members:
            # Shared org: only a problem if this user is its only admin — the
            # remaining members would be left with no one who can manage it.
            if m.role == Role.org_admin:
                other_admins = await session.scalar(
                    select(func.count(Membership.id)).where(
                        Membership.org_id == m.org_id, Membership.role == Role.org_admin, Membership.user_id != user.id
                    )
                )
                if not other_admins:
                    blocked_orgs.append(m.org_id)
        else:
            # This user is the org's only member at all — it's their solo
            # workspace; deleting the account takes it (and everything in
            # it — projects, findings, evidence, everything) with it, same
            # as §30's "no orphaned records" for project deletion.
            orgs_to_delete.append(m.org_id)

    if blocked_orgs:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "you are the only admin of at least one organization with other members — promote another "
            "member to org_admin before deleting your account",
        )

    await audit.record(
        session, action="user.account_delete", actor_email=user.email, user_id=user.id,
        ip=client_ip(request), after={"deleted_solo_orgs": [str(o) for o in orgs_to_delete]},
    )
    for org_id in orgs_to_delete:
        org = await session.get(Organization, org_id)
        if org is not None:
            await session.delete(org)  # cascades every project/asset/finding/etc. that org owned
    await session.delete(user)  # memberships cascade
    await session.commit()
