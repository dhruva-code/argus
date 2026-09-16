"""Wayback Machine capture timestamps on endpoints

Revision ID: 0010_wayback_urls
Revises: 0009_accounts_notifications

Adds `wayback_first_seen` / `wayback_last_seen` (nullable timestamps) to
`endpoints`, populated only for URLs discovered via the new Wayback CDX
recon source.

Column-existence-guarded (see app/_migration_guards.py): 0001_initial
runs `Base.metadata.create_all()` against *current* `app/models.py`, which
already includes these columns — so on a database built via the full
0001->head chain from empty (any brand-new install), 0001 creates them
and this migration's plain `add_column` would then fail with "column
already exists". Confirmed by actually running the full chain against a
fresh Postgres database, not assumed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app._migration_guards import add_column_if_missing

revision: str = "0010_wayback_urls"
down_revision: str | None = "0009_accounts_notifications"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    add_column_if_missing(
        "endpoints", sa.Column("wayback_first_seen", sa.DateTime(timezone=True), nullable=True)
    )
    add_column_if_missing(
        "endpoints", sa.Column("wayback_last_seen", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("endpoints", "wayback_last_seen")
    op.drop_column("endpoints", "wayback_first_seen")
