"""Wayback Machine capture timestamps on endpoints

Revision ID: 0010_wayback_urls
Revises: 0009_accounts_notifications

Adds `wayback_first_seen` / `wayback_last_seen` (nullable timestamps) to
`endpoints`, populated only for URLs discovered via the new Wayback CDX
recon source. This is a real migration (not a no-op like 0002-0009) — see
0001_initial.py's docstring for why those are folded in but new columns
after 0009 are added normally, the same as any other project.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_wayback_urls"
down_revision: str | None = "0009_accounts_notifications"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("wayback_first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("endpoints", sa.Column("wayback_last_seen", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("endpoints", "wayback_last_seen")
    op.drop_column("endpoints", "wayback_first_seen")
