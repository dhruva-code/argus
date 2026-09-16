"""Sessions / change-password / account deletion, and the per-user
notification-preferences / Telegram-pairing API.

No registration/email-verification/password-reset tests here — those
flows were removed along with public registration (single bootstrap-admin
model; see app/bootstrap_admin.py and app/routers/auth.py).
"""

from __future__ import annotations

import uuid

import pytest


async def _new_account(client, session_factory, *, password: str = "first-password-123"):  # noqa: S107
    """Creates an account directly (the only way one exists now — see
    tests/conftest.py's admin_client for the same pattern) and logs in for
    real, returning (email, access_token)."""
    from app.core import security
    from app.models import Membership, Organization, Role, User

    email = f"acct-{uuid.uuid4().hex[:8]}@test.local"
    async with session_factory() as session:
        org = Organization(name="Acct Org", slug=f"acct-org-{uuid.uuid4().hex[:8]}")
        session.add(org)
        await session.flush()
        user = User(
            email=email,
            full_name="Test User",
            password_hash=security.hash_password(password),
            is_superuser=True,
            email_verified=True,
        )
        session.add(user)
        await session.flush()
        session.add(Membership(user_id=user.id, org_id=org.id, role=Role.super_admin))
        await session.commit()

    r = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return email, r.json()["access_token"]


@pytest.mark.asyncio
async def test_sessions_and_change_password(client):
    from app.db import SessionLocal

    email, token = await _new_account(client, SessionLocal)
    client.headers["Authorization"] = f"Bearer {token}"

    r = await client.get("/api/auth/sessions")
    assert r.status_code == 200
    assert len(r.json()) >= 1

    r = await client.post(
        "/api/auth/change-password",
        json={"current_password": "first-password-123", "new_password": "second-password-456"},
    )
    assert r.status_code == 204

    r = await client.post("/api/auth/login", json={"email": email, "password": "second-password-456"})
    assert r.status_code == 200
    # old password no longer works
    r = await client.post("/api/auth/login", json={"email": email, "password": "first-password-123"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_account_deletion_requires_correct_confirmation(client):
    from app.db import SessionLocal

    email, token = await _new_account(client, SessionLocal, password="delete-me-password-1")  # noqa: S106
    client.headers["Authorization"] = f"Bearer {token}"

    # Wrong confirmation text is rejected.
    r = await client.post(
        "/api/auth/account/delete", json={"password": "delete-me-password-1", "confirm": "not-my-email"}
    )
    assert r.status_code == 400

    r = await client.post(
        "/api/auth/account/delete", json={"password": "delete-me-password-1", "confirm": email}
    )
    assert r.status_code == 204

    # Deleted — login now fails.
    r = await client.post("/api/auth/login", json={"email": email, "password": "delete-me-password-1"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_notification_preferences_roundtrip(admin_client):
    r = await admin_client.get("/api/settings/notifications")
    assert r.status_code == 200, r.text
    defaults = r.json()
    assert defaults["email_enabled"] is True
    assert defaults["events"]["scan_completed"] is True

    r = await admin_client.put(
        "/api/settings/notifications",
        json={
            "telegram_enabled": True,
            "events": {"new_asset": True},
            "quiet_hours_start": 23,
            "quiet_hours_end": 7,
        },
    )
    assert r.status_code == 200, r.text
    updated = r.json()
    assert updated["telegram_enabled"] is True
    assert updated["events"]["new_asset"] is True
    assert updated["events"]["scan_completed"] is True  # untouched keys survive a partial update
    assert updated["quiet_hours_start"] == 23


@pytest.mark.asyncio
async def test_telegram_pairing_without_bot_configured(admin_client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    r = await admin_client.get("/api/settings/telegram/status")
    assert r.status_code == 200
    assert r.json()["linked"] is False

    r = await admin_client.post("/api/settings/telegram/pair")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["pairing_code"]) >= 6
    assert body["bot_configured"] is False  # honestly reports the bot isn't configured, not fake-success

    r = await admin_client.post("/api/settings/notifications/test-telegram")
    assert r.status_code == 200
    assert r.json()["success"] is False  # not linked yet — must fail, not pretend to send


@pytest.mark.asyncio
async def test_test_email_reports_provider_error_not_crash(admin_client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    r = await admin_client.post("/api/settings/notifications/test-email")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "not configured" in body["detail"].lower()
