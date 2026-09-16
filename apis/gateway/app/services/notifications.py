"""Unified per-user notification service (§9, §13-15).

Callers (scan-completion handlers, finding ingestion, etc.) only ever call
`NotificationService.notify(...)`. This module owns everything downstream:
checking the user's per-event preference and quiet hours, picking which
channels apply, queuing the actual send (never synchronously — §14, so a
slow mail/Telegram API never blocks a worker or an API request), and
retrying with backoff up to a bounded number of attempts before marking the
delivery `dead_letter` (§15).

Architecture:

    caller -> NotificationService.notify() -> notification_deliveries row
                                             -> Redis list argus:notifications:queue
                                                         -> run_notification_worker()
                                                            -> EmailProvider / Telegram adapter

Known limitation (documented, not hidden): retry backoff is scheduled with
in-process `asyncio.sleep`, not a persisted delayed queue — a gateway
restart mid-backoff drops that specific pending retry (the delivery row is
left `retrying` and is not automatically resumed). Given this app already
runs the gateway as a single long-lived process (see scripts/lib/services.sh),
this is an accepted tradeoff for this pass; a persisted delayed queue is the
natural next step if the gateway ever runs multi-replica.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import telegram
from app.core.email import EmailSendError, get_email_provider
from app.core.redis import get_redis
from app.core.security import ensure_aware
from app.db import SessionLocal
from app.models import NotificationDelivery, NotificationPreference, TelegramLink, User

log = logging.getLogger("argus.notifications")

QUEUE_KEY = "argus:notifications:queue"
MAX_ATTEMPTS = 4
BACKOFF_SECONDS = [30, 120, 600]  # 30s, 2m, 10m — matches §15's example, then dead_letter

# Events that ignore quiet hours unless the user explicitly turns that off.
_CRITICAL_EVENTS = {"finding_critical", "system_error", "scan_failed"}


async def _get_or_create_prefs(session: AsyncSession, user_id) -> NotificationPreference:
    prefs = await session.get(NotificationPreference, user_id)
    if prefs is None:
        prefs = NotificationPreference(user_id=user_id)
        session.add(prefs)
        await session.flush()
    return prefs


def _in_quiet_hours(prefs: NotificationPreference, tz_name: str) -> bool:
    if prefs.quiet_hours_start is None or prefs.quiet_hours_end is None:
        return False
    try:
        from zoneinfo import ZoneInfo

        hour = datetime.now(ZoneInfo(tz_name or "UTC")).hour
    except Exception:  # noqa: BLE001 — bad/unknown tz name, don't block notifications over it
        hour = datetime.now(UTC).hour
    start, end = prefs.quiet_hours_start, prefs.quiet_hours_end
    if start == end:
        return False
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # wraps past midnight, e.g. 23-7


class NotificationService:
    @staticmethod
    async def notify(
        session: AsyncSession,
        *,
        user_id,
        event_type: str,
        subject: str,
        body_text: str,
        body_html: str | None = None,
        force: bool = False,
    ) -> list[str]:
        """Queues delivery on every channel the user has enabled for this
        event. Returns the channel names actually queued (empty if the user
        has the event/channels disabled, or is in quiet hours)."""
        user = await session.get(User, user_id)
        if user is None or not user.is_active:
            return []
        prefs = await _get_or_create_prefs(session, user_id)

        if not force and not prefs.events.get(event_type, False):
            return []
        if not force and event_type not in _CRITICAL_EVENTS and _in_quiet_hours(prefs, user.timezone):
            return []
        if (
            not force
            and event_type in _CRITICAL_EVENTS
            and _in_quiet_hours(prefs, user.timezone)
            and not prefs.quiet_hours_override_critical
        ):
            return []

        channels: list[tuple[str, dict[str, Any]]] = []
        if prefs.email_enabled and user.email_verified:
            channels.append(("email", {"to": user.email}))
        if prefs.telegram_enabled:
            link = await session.get(TelegramLink, user_id)
            if link and link.chat_id:
                channels.append(("telegram", {"chat_id": link.chat_id}))

        queued: list[str] = []
        r = get_redis()
        for channel, target in channels:
            delivery = NotificationDelivery(
                user_id=user_id, channel=channel, event_type=event_type, subject=subject[:300]
            )
            session.add(delivery)
            await session.flush()
            job = {
                "delivery_id": str(delivery.id),
                "channel": channel,
                "target": target,
                "subject": subject,
                "body_text": body_text,
                "body_html": body_html,
            }
            await r.rpush(QUEUE_KEY, json.dumps(job))
            queued.append(channel)
        return queued


async def _deliver_once(job: dict) -> None:
    channel = job["channel"]
    if channel == "email":
        provider = get_email_provider()
        provider.send(job["target"]["to"], job["subject"], job["body_text"], job.get("body_html"))
    elif channel == "telegram":
        await telegram.send_message(job["target"]["chat_id"], job["body_text"])
    else:
        raise ValueError(f"unknown notification channel: {channel}")


async def _record_status(delivery_id: str, *, status: str, attempts: int, error: str = "") -> None:
    async with SessionLocal() as session:
        row = await session.get(NotificationDelivery, delivery_id)
        if row is None:
            return
        row.status = status
        row.attempts = attempts
        row.last_error = error[:500]
        if status == "sent":
            row.delivered_at = datetime.now(UTC)
        await session.commit()


async def _deliver_with_retry(job: dict) -> None:
    delivery_id = job["delivery_id"]
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            await _deliver_once(job)
            await _record_status(delivery_id, status="sent", attempts=attempt)
            return
        except (EmailSendError, telegram.TelegramSendError, ValueError) as exc:
            log.warning(
                "notification delivery failed (channel=%s attempt=%d/%d): %s",
                job["channel"],
                attempt,
                MAX_ATTEMPTS,
                exc,
            )
            if attempt >= MAX_ATTEMPTS:
                await _record_status(delivery_id, status="dead_letter", attempts=attempt, error=str(exc))
                return
            await _record_status(delivery_id, status="retrying", attempts=attempt, error=str(exc))
            await asyncio.sleep(BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)])


async def run_notification_worker(stop: asyncio.Event) -> None:
    r = get_redis()
    log.info("notification worker started")
    inflight: set[asyncio.Task] = set()
    while not stop.is_set():
        try:
            item = await r.blpop(QUEUE_KEY, timeout=2)
        except Exception:  # noqa: BLE001 — Redis hiccup; back off and retry, don't crash the task
            await asyncio.sleep(2)
            continue
        inflight = {t for t in inflight if not t.done()}
        if item is None:
            continue
        _key, raw = item
        try:
            job = json.loads(raw)
        except (TypeError, ValueError):
            log.warning("dropping malformed notification job")
            continue
        task = asyncio.create_task(_deliver_with_retry(job))
        inflight.add(task)
    if inflight:
        await asyncio.gather(*inflight, return_exceptions=True)
    log.info("notification worker stopped")


async def run_telegram_pairing_poller(stop: asyncio.Event) -> None:
    """Long-polls Telegram for incoming /start <code> messages and pairs
    them to a pending telegram_links row. No-op (never polls) when
    TELEGRAM_BOT_TOKEN isn't configured."""
    if not telegram.configured():
        log.info("telegram pairing poller disabled (TELEGRAM_BOT_TOKEN not set)")
        return
    log.info("telegram pairing poller started")
    offset: int | None = None
    while not stop.is_set():
        updates = await telegram.get_updates(offset, timeout=20)
        for upd in updates:
            offset = upd["update_id"] + 1
            parsed = telegram.extract_pairing_code(upd)
            if not parsed:
                continue
            code, chat_id, username = parsed
            async with SessionLocal() as session:
                link = await session.scalar(select(TelegramLink).where(TelegramLink.pairing_code == code))
                if link is None or (
                    link.pairing_expires and ensure_aware(link.pairing_expires) < datetime.now(UTC)
                ):
                    continue
                link.chat_id = chat_id
                link.telegram_username = username
                link.linked_at = datetime.now(UTC)
                link.pairing_code = None
                link.pairing_expires = None
                await session.commit()
                log.info("telegram paired for user %s", link.user_id)
        if stop.is_set():
            break
    log.info("telegram pairing poller stopped")


def pairing_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(minutes=15)
