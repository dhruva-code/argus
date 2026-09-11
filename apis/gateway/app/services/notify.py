"""Outbound notifications (M6).

Reads `project.notification_policy`:

    {
      "slack_webhook":  "https://hooks.slack.com/services/…",   # optional
      "webhook_url":    "https://example.com/argus-hook",        # optional, gets full JSON
      "email":          "team@example.com",                      # optional (needs SMTP_* env)
      "events":         ["scan_complete", "new_finding", "new_critical", "surface_change"],
      "min_severity":   "medium"
    }

Delivery is best-effort — a failing hook is logged, never raised.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx

log = logging.getLogger("argus.notify")

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _wants(policy: dict, event: str) -> bool:
    events = policy.get("events")
    if events is None:
        return True  # default: notify on everything the policy has a channel for
    return event in events


def _channels(policy: dict) -> bool:
    return bool(policy.get("slack_webhook") or policy.get("webhook_url") or policy.get("email"))


async def _post(url: str, payload: dict, *, slack: bool) -> None:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            await c.post(url, json=payload)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify %s failed: %s", "slack" if slack else "webhook", exc)


def _send_email(to: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    if not host:
        return
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM", "argus@localhost")
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as s:
            if os.getenv("SMTP_STARTTLS", "true") == "true":
                s.starttls()
            if os.getenv("SMTP_USER"):
                s.login(os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", ""))
            s.send_message(msg)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify email failed: %s", exc)


async def dispatch(project, event: str, title: str, lines: list[str], payload: dict[str, Any]) -> None:
    policy = project.notification_policy or {}
    if not _channels(policy) or not _wants(policy, event):
        return

    text = f"*{title}*\n" + "\n".join(f"• {ln}" for ln in lines[:20])
    full = {"project": project.name, "project_id": str(project.id), "event": event,
            "title": title, "summary": lines, "data": payload}

    if url := policy.get("slack_webhook"):
        await _post(url, {"text": text}, slack=True)
    if url := policy.get("webhook_url"):
        await _post(url, full, slack=False)
    if to := policy.get("email"):
        _send_email(to, f"[Argus] {title}", title + "\n\n" + "\n".join(lines))


async def notify_scan_complete(session, project, job, delta: dict) -> None:
    """Called when a scan reaches a terminal state."""
    policy = project.notification_policy or {}
    min_rank = _SEV_RANK.get(str(policy.get("min_severity", "info")).lower(), 0)

    counts = delta.get("counts", {})
    new_findings = [
        f for f in delta.get("new", {}).get("findings", [])
        if _SEV_RANK.get(f.get("severity", "info"), 0) >= min_rank
    ]

    lines = [f"scan {job.status.value} — {job.result_count} results"]
    if counts:
        lines.append(
            f"{counts.get('new_findings', 0)} new findings, "
            f"{counts.get('new_assets', 0)} new assets, "
            f"{counts.get('resolved_findings', 0)} resolved"
        )
    for f in new_findings[:10]:
        lines.append(f"[{f['severity']}] {f['name']} — {f['host']}")

    event = "scan_complete"
    if any(f["severity"] == "critical" for f in new_findings):
        event = "new_critical"
    elif new_findings:
        event = "new_finding"
    elif counts.get("new_assets") or counts.get("resolved_assets"):
        event = "surface_change"

    await dispatch(project, event, f"{project.name}: scan finished", lines, delta)
