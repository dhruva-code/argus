"""Settings: per-user Notifications (email/Telegram preferences, pairing,
test-send — §9, §11-13, §20-22) and org-level AI & Analysis / Reports
branding (both gated behind the `settings.modify` permission, org_admin+).

Environment/`.env`-driven infra settings (email provider transport,
worker limits, etc.) are intentionally NOT here — those aren't a runtime
API surface at all, so no user, however privileged, can change them
through the app.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import telegram
from app.core.crypto import decrypt, encrypt, mask
from app.core.email import EmailSendError, get_email_provider
from app.core.security import ensure_aware
from app.db import get_session
from app.deps import Principal, get_current_user, get_principal, require_permission
from app.models import AiSettings, NotificationPreference, ReportSettings, TelegramLink, User
from app.schemas import (
    AiSettingsOut,
    AiSettingsUpdate,
    AiTestResult,
    NotificationPreferenceOut,
    NotificationPreferenceUpdate,
    ReportSettingsOut,
    ReportSettingsUpdate,
    TelegramPairResponse,
    TelegramStatusOut,
    TestNotificationResult,
)
from app.services.ai import resolve_config, test_connection
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
        pairing_code=code,
        deep_link=telegram.deep_link(code),
        expires_at=expires,
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
            user.email,
            "Argus test notification",
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


# ── Settings → AI & Analysis (org-level, settings.modify) ────────────────


async def _ai_settings(session: AsyncSession, org_id: uuid.UUID) -> AiSettings:
    row = await session.get(AiSettings, org_id)
    if row is None:
        row = AiSettings(org_id=org_id)
        session.add(row)
        await session.flush()
    return row


def _ai_out(row: AiSettings) -> AiSettingsOut:
    masked = ""
    if row.api_key_enc:
        try:
            masked = mask(decrypt(row.api_key_enc))
        except ValueError:
            masked = "****(unreadable — re-enter the key)"
    return AiSettingsOut(
        enabled=row.enabled,
        provider=row.provider,
        model=row.model,
        api_key_masked=masked,
        ollama_base_url=row.ollama_base_url,
        analyze_every_phase=row.analyze_every_phase,
        status=row.last_test_status,
        last_test_detail=row.last_test_detail,
        last_test_at=row.last_test_at,
    )


@router.get("/ai", response_model=AiSettingsOut)
async def get_ai_settings(
    principal: Principal = Depends(get_principal), session: AsyncSession = Depends(get_session)
) -> AiSettingsOut:
    row = await _ai_settings(session, principal.org.id)
    await session.commit()
    return _ai_out(row)


@router.put("/ai", response_model=AiSettingsOut)
async def update_ai_settings(
    body: AiSettingsUpdate,
    principal: Principal = Depends(require_permission("settings.modify")),
    session: AsyncSession = Depends(get_session),
) -> AiSettingsOut:
    row = await _ai_settings(session, principal.org.id)
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.provider is not None:
        row.provider = body.provider
    if body.model is not None:
        row.model = body.model
    if body.ollama_base_url is not None:
        row.ollama_base_url = body.ollama_base_url
    if body.analyze_every_phase is not None:
        row.analyze_every_phase = body.analyze_every_phase
    if body.api_key is not None:
        row.api_key_enc = encrypt(body.api_key) if body.api_key else None
        # a changed (or cleared) key invalidates any previous test result —
        # the new key hasn't been verified against the provider yet.
        row.last_test_status = "not_configured"
        row.last_test_detail = ""
        row.last_test_at = None
    await session.commit()
    return _ai_out(row)


@router.post("/ai/test", response_model=AiTestResult)
async def test_ai_settings(
    principal: Principal = Depends(require_permission("settings.modify")),
    session: AsyncSession = Depends(get_session),
) -> AiTestResult:
    row = await _ai_settings(session, principal.org.id)
    cfg = await resolve_config(session, principal.org.id)
    # Ollama is a local server — it has no API key at all, so only
    # Anthropic-family providers need one configured before testing.
    if cfg.provider != "ollama" and not cfg.api_key:
        row.last_test_status, row.last_test_detail = "not_configured", "no API key configured"
        await session.commit()
        return AiTestResult(success=False, detail=row.last_test_detail)
    ok, detail = await test_connection(cfg)
    row.last_test_status = "ok" if ok else "failed"
    row.last_test_detail = detail
    row.last_test_at = datetime.now(UTC)
    await session.commit()
    return AiTestResult(success=ok, detail=detail)


# ── Settings → Reports (org-level, settings.modify) ───────────────────────

_ALLOWED_LOGO_TYPES = ("image/png", "image/jpeg", "image/webp")
_MAX_LOGO_BYTES = 300_000


async def _report_settings(session: AsyncSession, org_id: uuid.UUID) -> ReportSettings:
    row = await session.get(ReportSettings, org_id)
    if row is None:
        row = ReportSettings(org_id=org_id)
        session.add(row)
        await session.flush()
    return row


def _report_out(row: ReportSettings) -> ReportSettingsOut:
    return ReportSettingsOut(
        company_name=row.company_name,
        has_logo=bool(row.logo_data_uri),
        report_title=row.report_title,
        author=row.author,
        contact_email=row.contact_email,
        confidentiality_label=row.confidentiality_label,
        accent_color=row.accent_color,
    )


@router.get("/reports", response_model=ReportSettingsOut)
async def get_report_settings(
    principal: Principal = Depends(get_principal), session: AsyncSession = Depends(get_session)
) -> ReportSettingsOut:
    row = await _report_settings(session, principal.org.id)
    await session.commit()
    return _report_out(row)


@router.put("/reports", response_model=ReportSettingsOut)
async def update_report_settings(
    body: ReportSettingsUpdate,
    principal: Principal = Depends(require_permission("settings.modify")),
    session: AsyncSession = Depends(get_session),
) -> ReportSettingsOut:
    row = await _report_settings(session, principal.org.id)
    if body.company_name is not None:
        row.company_name = body.company_name
    if body.report_title is not None:
        row.report_title = body.report_title
    if body.author is not None:
        row.author = body.author
    if body.contact_email is not None:
        row.contact_email = body.contact_email
    if body.confidentiality_label is not None:
        row.confidentiality_label = body.confidentiality_label
    if body.accent_color is not None:
        row.accent_color = body.accent_color
    if body.logo_data_uri is not None:
        if body.logo_data_uri == "":
            row.logo_data_uri = None
        else:
            if not body.logo_data_uri.startswith("data:"):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "logo must be a data: URI")
            header = body.logo_data_uri.split(",", 1)[0]
            if not any(t in header for t in _ALLOWED_LOGO_TYPES):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"logo must be one of: {', '.join(_ALLOWED_LOGO_TYPES)} (SVG rejected — can embed scripts)",
                )
            if len(body.logo_data_uri) > _MAX_LOGO_BYTES:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, f"logo too large — max {_MAX_LOGO_BYTES // 1000}KB"
                )
            row.logo_data_uri = body.logo_data_uri
    await session.commit()
    return _report_out(row)
