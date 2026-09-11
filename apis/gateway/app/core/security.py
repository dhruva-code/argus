"""Password hashing, JWT issue/verify, and TOTP helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import pyotp
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

_pwd = CryptContext(schemes=["argon2"], deprecated="auto")

ALGORITHM = "HS256"
TokenKind = Literal["access", "refresh"]


def hash_password(raw: str) -> str:
    return _pwd.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return _pwd.verify(raw, hashed)
    except ValueError:
        return False


def _now() -> datetime:
    return datetime.now(UTC)


def ensure_aware(dt: datetime | None) -> datetime | None:
    """SQLite (used by the test suite, and available as a lightweight
    deployment option) doesn't preserve timezone info through a round trip
    even for `DateTime(timezone=True)` columns — a value read back can come
    out naive. Postgres (the default/production backend) doesn't have this
    problem, but comparing a naive value against `datetime.now(UTC)` raises
    TypeError regardless of backend, so every expiry check normalizes
    through this first rather than assuming the storage backend in use."""
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=UTC)


def create_token(
    subject: str,
    kind: TokenKind,
    *,
    extra: dict[str, Any] | None = None,
    jti: str | None = None,
) -> tuple[str, datetime]:
    if kind == "access":
        expires = _now() + timedelta(minutes=settings.jwt_access_ttl_minutes)
    else:
        expires = _now() + timedelta(days=settings.jwt_refresh_ttl_days)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": kind,
        "iat": int(_now().timestamp()),
        "exp": int(expires.timestamp()),
        "jti": jti or uuid.uuid4().hex,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM), expires


def decode_token(token: str, *, expected_kind: TokenKind | None = None) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except JWTError as exc:  # noqa: TRY003
        raise ValueError(f"invalid token: {exc}") from exc
    if expected_kind and payload.get("type") != expected_kind:
        raise ValueError(f"expected {expected_kind} token, got {payload.get('type')}")
    return payload


# ── TOTP ───────────────────────────────────────────────────────────────────


def new_mfa_secret() -> str:
    return pyotp.random_base32()


def mfa_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Argus")


def verify_mfa(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)
