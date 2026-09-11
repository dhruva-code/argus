"""Email provider abstraction (§8 of the finalization spec).

The rest of the application calls `get_email_provider().send(...)` and never
imports `smtplib`/a vendor SDK directly, so switching providers is a config
change, not a code change.

**SMTP is the only provider actually implemented and tested here** — it
needs no paid account and works with any standards-compliant mail host,
including sending *to* `@proton.me`/`@protonmail.com` addresses (see
docs/AUTHENTICATION.md — that document distinguishes "Proton as an email
*destination*", which this fully supports, from "Proton as an OAuth/OIDC
*identity provider*", which Proton does not currently offer to third-party
apps). Resend/SendGrid/SES are defined as documented, honest stubs: calling
`.send()` on one raises `NotImplementedError` naming exactly what's missing,
rather than silently no-op'ing or pretending to send. Wiring a real HTTP
call in for any of them is a small, contained change in this one file.

Credentials are read from environment variables only — never from source,
never logged (see `app/services/notifications.py`, which never logs message
bodies either).
"""

from __future__ import annotations

import logging
import os
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage

log = logging.getLogger("argus.email")


class EmailSendError(Exception):
    """Raised on a provider-reported failure; message is safe to show a user
    (never includes credentials)."""


class EmailProvider(ABC):
    @abstractmethod
    def send(self, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        """Raises EmailSendError on failure. Must not raise on missing
        configuration silently — callers rely on the exception to report a
        clear diagnosis (§21)."""


class SMTPProvider(EmailProvider):
    """The default, always-available provider. Configure via SMTP_HOST (+
    optional SMTP_PORT/SMTP_USER/SMTP_PASSWORD/SMTP_STARTTLS/SMTP_FROM)."""

    def __init__(self) -> None:
        self.host = os.getenv("SMTP_HOST", "")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("SMTP_USER", "")
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.starttls = os.getenv("SMTP_STARTTLS", "true").lower() != "false"
        self.from_addr = os.getenv("SMTP_FROM", "argus@localhost")

    def configured(self) -> bool:
        return bool(self.host)

    def send(self, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        if not self.configured():
            raise EmailSendError("SMTP is not configured (SMTP_HOST is unset) — set it in .env or Admin Settings")
        msg = EmailMessage()
        msg["From"] = self.from_addr
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body_text)
        if body_html:
            msg.add_alternative(body_html, subtype="html")
        try:
            with smtplib.SMTP(self.host, self.port, timeout=10) as s:
                if self.starttls:
                    s.starttls()
                if self.user:
                    s.login(self.user, self.password)
                s.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            # str(exc) can echo back server responses but never the
            # credentials themselves (smtplib doesn't include them in
            # exception text).
            raise EmailSendError(f"SMTP delivery failed: {exc}") from exc


class _UnimplementedProvider(EmailProvider):
    """Interface exists (§8); the HTTP call to the vendor API is not wired
    in. Never silently pretends to send."""

    def __init__(self, name: str, docs_url: str) -> None:
        self._name = name
        self._docs_url = docs_url

    def send(self, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        raise NotImplementedError(
            f"{self._name} is not implemented in this build — see {self._docs_url}. "
            f"Set EMAIL_PROVIDER=smtp (the default) to send real mail."
        )


class ResendProvider(_UnimplementedProvider):
    def __init__(self) -> None:
        super().__init__("Resend", "https://resend.com/docs/api-reference/emails/send-email")


class SendGridProvider(_UnimplementedProvider):
    def __init__(self) -> None:
        super().__init__("SendGrid", "https://docs.sendgrid.com/api-reference/mail-send/mail-send")


class SESProvider(_UnimplementedProvider):
    def __init__(self) -> None:
        super().__init__("Amazon SES", "https://docs.aws.amazon.com/ses/latest/APIReference/Welcome.html")


_PROVIDERS: dict[str, type[EmailProvider]] = {
    "smtp": SMTPProvider,
    "resend": ResendProvider,
    "sendgrid": SendGridProvider,
    "ses": SESProvider,
}


def get_email_provider() -> EmailProvider:
    name = os.getenv("EMAIL_PROVIDER", "smtp").lower()
    cls = _PROVIDERS.get(name, SMTPProvider)
    if name not in _PROVIDERS:
        log.warning("unknown EMAIL_PROVIDER=%r, falling back to smtp", name)
    return cls()
