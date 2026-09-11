"""Account-level Settings → Notifications: email/Telegram preferences,
Telegram pairing, and test-send (§9, §11-13, §20-22).

Admin/system-wide settings (email provider config, worker limits, etc.) are
intentionally NOT here — those are environment/`.env`-driven (§24), not a
per-user API surface, so an ordinary user can never read or change them.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import telegram
from app.core.email import EmailSendError, get_email_provider
from app.core.security import ensure_aware
from app.db import get_session
from app.deps import get_current_user
from app.models import NotificationPreference, TelegramLink, User
from app.schemas import (
    NotificationPreferenceOut,
    NotificationPreferenceUpdate,
    TelegramPairResponse,
    TelegramStatusOut,
    TestNotificationResult,
)
from app.services.notifications import pairing_expiry

router = APIRouter(prefix="/api/settings", tags=["settings"])


async def _prefs(session: AsyncSession, user_id) -> NotificationPreference:
    p = await session.get(NotificationPreference, user_id)
    if p is None:
        p = NotificationPreference(user_id=user_id)
        session.add(p)
        await session.flush()
    return p


@router.get("/notifications", response_model=NotificationPreferenceOut)
async def get_notification_prefs(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> NotificationPreferenceOut:
    p = await _prefs(session, user.id)
    await session.commit()
    return NotificationPreferenceOut.model_validate(p)


@router.put("/notifications", response_model=NotificationPreferenceOut)
async def update_notification_prefs(
    body: NotificationPreferenceUpdate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> NotificationPreferenceOut:
    p = await _prefs(session, user.id)
    if body.email_enabled is not None:
        p.email_enabled = body.email_enabled
    if body.telegram_enabled is not None:
        p.telegram_enabled = body.telegram_enabled
    if body.events is not None:
        p.events = {**p.events, **body.events}
    if body.quiet_hours_start is not None:
        p.quiet_hours_start = body.quiet_hours_start
    if body.quiet_hours_end is not None:
        p.quiet_hours_end = body.quiet_hours_end
    if body.quiet_hours_override_critical is not None:
        p.quiet_hours_override_critical = body.quiet_hours_override_critical
    await session.commit()
    return NotificationPreferenceOut.model_validate(p)


# ── Telegram pairing (§11) ──────────────────────────────────────────────


@router.get("/telegram/status", response_model=TelegramStatusOut)
async def telegram_status(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> TelegramStatusOut:
    link = await session.get(TelegramLink, user.id)
    if link is None:
        return TelegramStatusOut(linked=False)
    pending = bool(
        link.pairing_code and link.pairing_expires and ensure_aware(link.pairing_expires) > datetime.now(UTC)
    )
    return TelegramStatusOut(
        linked=bool(link.chat_id),
        telegram_username=link.telegram_username,
        linked_at=link.linked_at,
        pairing_pending=pending,
    )


@router.post("/telegram/pair", response_model=TelegramPairResponse)
async def telegram_pair(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> TelegramPairResponse:
    if not telegram.configured():
        # Still returns a code so the UI has something to show, but flags
        # bot_configured=false so the frontend can explain why the deep
        # link/bot won't actually respond (§21 — actionable diagnosis).
        pass
    code = telegram.new_pairing_code()
    expires = pairing_expiry()
    link = await session.get(TelegramLink, user.id)
    if link is None:
        link = TelegramLink(user_id=user.id)
        session.add(link)
    link.pairing_code = code
    link.pairing_expires = expires
    await session.commit()
    return TelegramPairResponse(
        pairing_code=code, deep_link=telegram.deep_link(code), expires_at=expires,
        bot_configured=telegram.configured(),
    )


@router.delete("/telegram", status_code=status.HTTP_204_NO_CONTENT)
async def telegram_unlink(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> None:
    link = await session.get(TelegramLink, user.id)
    if link is not None:
        await session.delete(link)
        await session.commit()


# ── Test notifications (§21) ─────────────────────────────────────────────


@router.post("/notifications/test-email", response_model=TestNotificationResult)
async def test_email(
    user: User = Depends(get_current_user),
) -> TestNotificationResult:
    if not user.email_verified:
        return TestNotificationResult(success=False, detail="verify your email address first")
    try:
        get_email_provider().send(
            user.email, "Argus test notification",
            "This is a test notification from Argus. If you received this, email notifications are working.",
        )
    except EmailSendError as exc:
        return TestNotificationResult(success=False, detail=str(exc))
    return TestNotificationResult(success=True, detail=f"sent to {user.email}")


@router.post("/notifications/test-telegram", response_model=TestNotificationResult)
async def test_telegram(
    user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)
) -> TestNotificationResult:
    link = await session.get(TelegramLink, user.id)
    if link is None or not link.chat_id:
        return TestNotificationResult(success=False, detail="Telegram is not connected yet — pair it first")
    try:
        await telegram.send_message(
            link.chat_id, "<b>Argus</b>\n\nTest notification — Telegram notifications are working."
        )
    except telegram.TelegramSendError as exc:
        return TestNotificationResult(success=False, detail=str(exc))
    return TestNotificationResult(success=True, detail="sent")
