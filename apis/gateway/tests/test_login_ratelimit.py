"""Login rate limiting (§24) — locks out by source IP after repeated
failed attempts, resets on a successful login, and fails open if Redis
itself is unreachable (see app/core/ratelimit.py)."""

from __future__ import annotations

import uuid

import pytest

from app.core.ratelimit import (
    MAX_FAILED_ATTEMPTS,
    clear_failed_attempts,
    is_locked_out,
    record_failed_attempt,
)


@pytest.mark.asyncio
async def test_locks_out_after_threshold_and_clears():
    ip = f"203.0.113.{uuid.uuid4().int % 250}"
    locked, _ = await is_locked_out(ip)
    assert locked is False

    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        await record_failed_attempt(ip)
    locked, _ = await is_locked_out(ip)
    assert locked is False, "must not lock out before reaching the threshold"

    await record_failed_attempt(ip)
    locked, retry_after = await is_locked_out(ip)
    assert locked is True
    assert retry_after > 0

    await clear_failed_attempts(ip)
    locked, _ = await is_locked_out(ip)
    assert locked is False, "clearing (a successful login) must lift the lockout"


@pytest.mark.asyncio
async def test_fails_open_when_redis_unreachable(monkeypatch: pytest.MonkeyPatch):
    import redis.asyncio as aioredis

    broken = aioredis.from_url("redis://127.0.0.1:1", decode_responses=True)  # nothing listens here
    monkeypatch.setattr("app.core.ratelimit.get_redis", lambda: broken)

    ip = f"203.0.113.{uuid.uuid4().int % 250}"
    # Neither the check nor the record call may raise or block logins —
    # a rate limiter whose own backend is down must never become an
    # accidental full lockout.
    await record_failed_attempt(ip)
    locked, retry_after = await is_locked_out(ip)
    assert locked is False
    assert retry_after == 0


@pytest.mark.asyncio
async def test_login_endpoint_locks_out_and_audits(client):
    from app.core import security
    from app.db import SessionLocal
    from app.models import Membership, Organization, Role, User

    email = f"ratelimit-{uuid.uuid4().hex[:8]}@test.local"
    async with SessionLocal() as session:
        org = Organization(name="RL Org", slug=f"rl-org-{uuid.uuid4().hex[:8]}")
        session.add(org)
        await session.flush()
        user = User(
            email=email,
            full_name="RL",
            password_hash=security.hash_password("correct-password-1"),
            is_superuser=True,
            email_verified=True,
        )
        session.add(user)
        await session.flush()
        session.add(Membership(user_id=user.id, org_id=org.id, role=Role.super_admin))
        await session.commit()

    for _ in range(MAX_FAILED_ATTEMPTS):
        r = await client.post("/api/auth/login", json={"email": email, "password": "wrong"})
        assert r.status_code == 401

    # One more, even with the CORRECT password, must now be rate-limited.
    r = await client.post("/api/auth/login", json={"email": email, "password": "correct-password-1"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers
