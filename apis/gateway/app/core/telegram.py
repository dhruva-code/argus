"""Telegram Bot API adapter (§10-12).

Uses only the public Bot API (`sendMessage`, `getUpdates`) over HTTPS — no
unofficial/private API, no simulated behavior. The bot token lives in
`TELEGRAM_BOT_TOKEN` (backend env only; never sent to the frontend bundle —
see app/routers/settings.py, which never returns it in any response).

Pairing flow (§11): the user clicks "Connect Telegram" in Settings, which
calls `POST /api/settings/telegram/pair` to get a short pairing code and a
t.me deep link. They open the bot and send `/start <code>` (or just the bare
code as their first message). `poll_for_pairings()` — a background task
started alongside the notification worker — long-polls `getUpdates` and, for
each incoming message, checks whether its text matches a pending
(unexpired) `telegram_links.pairing_code`; if so it records the sender's
chat_id and marks that link verified. No Telegram credentials are ever
asked of the user — only what the integration needs (their message to our
bot, which is how any Telegram bot identifies a chat).
"""

from __future__ import annotations

import logging
import os
import secrets

import httpx

log = logging.getLogger("argus.telegram")

_API_BASE = "https://api.telegram.org"


class TelegramSendError(Exception):
    pass


def bot_token() -> str:
    return os.getenv("TELEGRAM_BOT_TOKEN", "")


def configured() -> bool:
    return bool(bot_token())


def bot_username() -> str:
    return os.getenv("TELEGRAM_BOT_USERNAME", "")


def new_pairing_code() -> str:
    # Short, human-typeable, still ~35 bits of entropy — fine for a code
    # that's single-use and expires in 15 minutes (see routers/settings.py).
    return secrets.token_hex(4).upper()


def deep_link(code: str) -> str:
    uname = bot_username()
    if not uname:
        return ""
    return f"https://t.me/{uname}?start={code}"


async def send_message(chat_id: str, text: str) -> None:
    token = bot_token()
    if not token:
        raise TelegramSendError("TELEGRAM_BOT_TOKEN is not configured — set it in .env or Admin Settings")
    url = f"{_API_BASE}/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"})
        if resp.status_code != 200:
            # Telegram's error body can include the token in the *request*
            # we sent, never in the response — safe to include verbatim.
            raise TelegramSendError(f"Telegram API returned {resp.status_code}: {resp.text[:300]}")
    except httpx.HTTPError as exc:
        raise TelegramSendError(f"Telegram API request failed: {exc}") from exc


async def get_updates(offset: int | None, timeout: int = 25) -> list[dict]:
    """Long-poll for new messages sent to the bot. Returns the raw `result`
    list from getUpdates (each item has update_id + message)."""
    token = bot_token()
    if not token:
        return []
    url = f"{_API_BASE}/bot{token}/getUpdates"
    params: dict[str, int] = {"timeout": timeout}
    if offset is not None:
        params["offset"] = offset
    try:
        async with httpx.AsyncClient(timeout=timeout + 10) as client:
            resp = await client.get(url, params=params)
        if resp.status_code != 200:
            log.warning("telegram getUpdates returned %s", resp.status_code)
            return []
        data = resp.json()
        return data.get("result", [])
    except httpx.HTTPError as exc:
        log.warning("telegram getUpdates failed: %s", exc)
        return []


def extract_pairing_code(update: dict) -> tuple[str, str, str] | None:
    """Returns (code, chat_id, telegram_username) if this update looks like
    a pairing attempt, else None."""
    msg = update.get("message") or {}
    text = str(msg.get("text", "")).strip()
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    username = str(msg.get("from", {}).get("username", ""))
    if not text or not chat_id:
        return None
    # Accept "/start CODE" or a bare "CODE".
    if text.startswith("/start"):
        parts = text.split(maxsplit=1)
        code = parts[1].strip() if len(parts) > 1 else ""
    else:
        code = text
    code = code.upper()
    if not code or not code.isalnum():
        return None
    return code, chat_id, username
