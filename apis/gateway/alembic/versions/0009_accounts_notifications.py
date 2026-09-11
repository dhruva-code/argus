"""User account finalization (folded into 0001_initial)

Revision ID: 0009_accounts_notifications
Revises: 0008_injection_engine

No-op — see 0002_m2_assets.py for why. Originally added email verification/
password reset/profile fields on `users`, session metadata on
`refresh_tokens`, and the notification_preferences/telegram_links/
notification_deliveries tables; now part of 0001_initial. (Its one real data
statement — backfilling `email_verified = true` for pre-existing rows — is
meaningless on the empty database 0001_initial now starts from.)
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0009_accounts_notifications"
down_revision: str | None = "0008_injection_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
