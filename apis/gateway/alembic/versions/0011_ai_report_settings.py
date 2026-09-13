"""AI & Analysis + Reports org-level settings

Revision ID: 0011_ai_report_settings
Revises: 0010_wayback_urls

Adds `ai_settings` and `report_settings` — one row per org, created lazily
on first read/write (see app/services settings routers), holding:

- ai_settings: enabled flag, provider/model, encrypted API key
  (app.core.crypto ciphertext, never plaintext), last connection-test
  result.
- report_settings: PDF report branding (company name, logo data URI,
  title, author, contact, confidentiality label, accent color).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_ai_report_settings"
down_revision: str | None = "0010_wayback_urls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_settings",
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("provider", sa.String(40), nullable=False, server_default="anthropic"),
        sa.Column("model", sa.String(80), nullable=False, server_default="claude-sonnet-5"),
        sa.Column("api_key_enc", sa.String(2000), nullable=True),
        sa.Column("last_test_status", sa.String(20), nullable=False, server_default="not_configured"),
        sa.Column("last_test_detail", sa.String(500), nullable=False, server_default=""),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("org_id"),
    )
    op.create_table(
        "report_settings",
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("company_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("logo_data_uri", sa.String(350_000), nullable=True),
        sa.Column("report_title", sa.String(200), nullable=False, server_default="Security Assessment Report"),
        sa.Column("author", sa.String(200), nullable=False, server_default=""),
        sa.Column("contact_email", sa.String(300), nullable=False, server_default=""),
        sa.Column("confidentiality_label", sa.String(80), nullable=False, server_default="Confidential"),
        sa.Column("accent_color", sa.String(9), nullable=False, server_default="#2563eb"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("org_id"),
    )


def downgrade() -> None:
    op.drop_table("report_settings")
    op.drop_table("ai_settings")
