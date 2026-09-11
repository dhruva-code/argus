"""Registration + email verification + password reset + sessions + account
deletion, and the per-user notification-preferences / Telegram-pairing API.
"""

from __future__ import annotations

import uuid

import pytest


@pytest.fixture
def captured_tokens(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Captures the raw verification/reset token instead of actually sending
    email — there is no real SMTP server in the test environment, and the
    token is one-way-hashed in the database (can't be recovered from there)."""
    captured: dict[str, str] = {}

    async def fake_send_verification(user, raw_token: str) -> None:
        captured["verify_token"] = raw_token
        captured["verify_email"] = user.email

    monkeypatch.setattr("app.routers.auth._send_verification_email", fake_send_verification)

    class _FakeProvider:
        def send(self, to, subject, body_text, body_html=None):
            if "reset your" in subject.lower():
                # extract the token from the reset link in the body
                for tok in body_text.split():
                    if "token=" in tok:
                        captured["reset_token"] = tok.split("token=", 1)[1]
            captured["last_to"] = to
            captured["last_subject"] = subject

    monkeypatch.setattr("app.routers.auth.get_email_provider", lambda: _FakeProvider())
    monkeypatch.setattr("app.routers.settings.get_email_provider", lambda: _FakeProvider())
    return captured


@pytest.mark.asyncio
async def test_register_verify_login_flow(client, captured_tokens):
    email = f"newuser-{uuid.uuid4().hex[:8]}@proton.me"  # Proton address — must work like any other
    r = await client.post(
        "/api/auth/register",
        json={"email": email, "password": "correct-horse-battery-1", "full_name": "New User"},
    )
    assert r.status_code == 201, r.text
    assert captured_tokens["verify_email"] == email

    # Cannot log in before verifying.
    r = await client.post("/api/auth/login", json={"email": email, "password": "correct-horse-battery-1"})
    assert r.status_code == 403, r.text

    # Verify with the captured token.
    r = await client.post("/api/auth/verify-email", json={"token": captured_tokens["verify_token"]})
    assert r.status_code == 200, r.text
    assert "access_token" in r.json()

    # Now login works.
    r = await client.post("/api/auth/login", json={"email": email, "password": "correct-horse-battery-1"})
    assert r.status_code == 200, r.text

    # Bad/expired token is rejected, not silently accepted.
    r = await client.post("/api/auth/verify-email", json={"token": "not-a-real-token"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_register_duplicate_email_does_not_leak_existence(client, captured_tokens):
    email = f"dup-{uuid.uuid4().hex[:8]}@example.com"
    r = await client.post("/api/auth/register", json={"email": email, "password": "correct-horse-battery-1"})
    assert r.status_code == 201

    r2 = await client.post("/api/auth/register", json={"email": email, "password": "another-password-1"})
    assert r2.status_code == 201  # same generic response either way
    assert "verification" in r2.json()["message"].lower()


@pytest.mark.asyncio
async def test_password_reset_flow(client, captured_tokens):
    email = f"resetme-{uuid.uuid4().hex[:8]}@example.com"
    await client.post("/api/auth/register", json={"email": email, "password": "original-password-1"})
    await client.post("/api/auth/verify-email", json={"token": captured_tokens["verify_token"]})

    r = await client.post("/api/auth/request-password-reset", json={"email": email})
    assert r.status_code == 204
    assert "reset_token" in captured_tokens

    r = await client.post(
        "/api/auth/reset-password",
        json={"token": captured_tokens["reset_token"], "new_password": "brand-new-password-1"},
    )
    assert r.status_code == 200, r.text

    # Old password no longer works; new one does.
    r = await client.post("/api/auth/login", json={"email": email, "password": "original-password-1"})
    assert r.status_code == 401
    r = await client.post("/api/auth/login", json={"email": email, "password": "brand-new-password-1"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_sessions_and_change_password(client, captured_tokens):
    email = f"sess-{uuid.uuid4().hex[:8]}@example.com"
    r = await client.post("/api/auth/register", json={"email": email, "password": "first-password-123"})
    r = await client.post("/api/auth/verify-email", json={"token": captured_tokens["verify_token"]})
    token = r.json()["access_token"]
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


@pytest.mark.asyncio
async def test_account_deletion_requires_correct_confirmation(client, captured_tokens):
    email = f"delme-{uuid.uuid4().hex[:8]}@example.com"
    await client.post("/api/auth/register", json={"email": email, "password": "delete-me-password-1"})
    r = await client.post("/api/auth/verify-email", json={"token": captured_tokens["verify_token"]})
    token = r.json()["access_token"]
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
        json={"telegram_enabled": True, "events": {"new_asset": True}, "quiet_hours_start": 23, "quiet_hours_end": 7},
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
