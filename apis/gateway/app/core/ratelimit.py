"""Login rate limiting / failed-attempt tracking (§24).

Backed by Redis (already a hard dependency for the job queue) rather than
in-process memory, so the limit holds even if the gateway ever runs as
multiple worker processes. Keyed by source IP only, deliberately — this
platform's single-bootstrap-admin model (see app/bootstrap_admin.py) means
the login *email* is a fixed, publicly-documented value
(argus@argus.local), so an email-keyed limit would protect nothing an
IP-keyed one doesn't already cover, and IP-keyed also rate-limits an
attacker who tries multiple guessed addresses.

Fails open: if Redis itself is unreachable, login is allowed rather than
the app becoming uses-Redis-to-lock-everyone-out. A Redis outage should
degrade AI/scanning-adjacent features, not the ability to log in at all.
"""

from __future__ import annotations

import logging

from app.core.redis import get_redis

log = logging.getLogger("argus.ratelimit")

MAX_FAILED_ATTEMPTS = 10
WINDOW_SECONDS = 15 * 60  # 15 minutes


def _key(ip: str) -> str:
    return f"argus:login_fail:{ip or 'unknown'}"


async def is_locked_out(ip: str) -> tuple[bool, int]:
    """Returns (locked_out, seconds_remaining). Fails open on any Redis
    error — a rate limiter that can accidentally lock out every user
    because its own backend hiccupped is worse than no rate limiter."""
    try:
        r = get_redis()
        count = await r.get(_key(ip))
        if count is None or int(count) < MAX_FAILED_ATTEMPTS:
            return False, 0
        ttl = await r.ttl(_key(ip))
        return True, max(ttl, 0)
    except Exception as exc:  # noqa: BLE001
        log.warning("rate-limit check failed open (redis unreachable?): %s", exc)
        return False, 0


async def record_failed_attempt(ip: str) -> None:
    try:
        r = get_redis()
        key = _key(ip)
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, WINDOW_SECONDS)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not record failed login attempt (redis unreachable?): %s", exc)


async def clear_failed_attempts(ip: str) -> None:
    try:
        r = get_redis()
        await r.delete(_key(ip))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not clear failed-login counter (redis unreachable?): %s", exc)
