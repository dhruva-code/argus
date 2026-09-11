"""User account finalization: email verification, password reset, profile
fields, session metadata; per-user notification preferences; Telegram
linking; notification delivery log.

Revision ID: 0009_accounts_notifications
Revises: 0008_injection_engine
Create Date: 2026-09-11 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0009_accounts_notifications"
down_revision: str | None = "0008_injection_engine"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── users: profile + verification + reset ──────────────────────────────
    op.add_column("users", sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("email_verify_token_hash", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("email_verify_expires", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("pending_email", sa.String(length=320), nullable=True))
    op.add_column("users", sa.Column("password_reset_token_hash", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("password_reset_expires", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("timezone", sa.String(length=64), nullable=False, server_default="UTC"))
    op.add_column("users", sa.Column("language", sa.String(length=16), nullable=False, server_default="en"))
    op.add_column("users", sa.Column("avatar_url", sa.String(length=500), nullable=True))
    op.add_column("users", sa.Column("theme", sa.String(length=16), nullable=False, server_default="system"))
    op.create_index(op.f("ix_users_email_verify_token_hash"), "users", ["email_verify_token_hash"])
    op.create_index(op.f("ix_users_password_reset_token_hash"), "users", ["password_reset_token_hash"])

    # Existing users/rows predate email verification — treat pre-existing
    # accounts as already verified so this migration never locks anyone out.
    op.execute("UPDATE users SET email_verified = true")

    # ── refresh_tokens: session metadata for the Active Sessions UI ────────
    op.add_column("refresh_tokens", sa.Column("ip", sa.String(length=64), nullable=False, server_default=""))
    op.add_column(
        "refresh_tokens", sa.Column("user_agent", sa.String(length=300), nullable=False, server_default="")
    )
    op.add_column("refresh_tokens", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))

    # ── notification_preferences ────────────────────────────────────────────
    op.create_table(
        "notification_preferences",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("telegram_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("quiet_hours_start", sa.Integer(), nullable=True),
        sa.Column("quiet_hours_end", sa.Integer(), nullable=True),
        sa.Column("quiet_hours_override_critical", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    # ── telegram_links ───────────────────────────────────────────────────────
    op.create_table(
        "telegram_links",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("pairing_code", sa.String(length=16), nullable=True),
        sa.Column("pairing_expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("chat_id", sa.String(length=64), nullable=True),
        sa.Column("telegram_username", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(op.f("ix_telegram_links_pairing_code"), "telegram_links", ["pairing_code"])

    # ── notification_deliveries ─────────────────────────────────────────────
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("subject", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_notification_deliveries_user_id"), "notification_deliveries", ["user_id"])
    op.create_index(op.f("ix_notification_deliveries_event_type"), "notification_deliveries", ["event_type"])
    op.create_index(op.f("ix_notification_deliveries_status"), "notification_deliveries", ["status"])


def downgrade() -> None:
    op.drop_table("notification_deliveries")
    op.drop_index(op.f("ix_telegram_links_pairing_code"), table_name="telegram_links")
    op.drop_table("telegram_links")
    op.drop_table("notification_preferences")

    op.drop_column("refresh_tokens", "last_used_at")
    op.drop_column("refresh_tokens", "user_agent")
    op.drop_column("refresh_tokens", "ip")

    op.drop_index(op.f("ix_users_password_reset_token_hash"), table_name="users")
    op.drop_index(op.f("ix_users_email_verify_token_hash"), table_name="users")
    op.drop_column("users", "theme")
    op.drop_column("users", "avatar_url")
    op.drop_column("users", "language")
    op.drop_column("users", "timezone")
    op.drop_column("users", "password_reset_expires")
    op.drop_column("users", "password_reset_token_hash")
    op.drop_column("users", "pending_email")
    op.drop_column("users", "email_verify_expires")
    op.drop_column("users", "email_verify_token_hash")
    op.drop_column("users", "email_verified")
