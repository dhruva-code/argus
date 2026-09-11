"""add first_seen_scan to vhosts and repositories

Revision ID: 0007_scan_ref_vhost_repo
Revises: 0006_m5_ports_findings
Create Date: 2026-09-10 22:35:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_scan_ref_vhost_repo"
down_revision: str | None = "0006_m5_ports_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for table in ("vhosts", "repositories"):
        op.add_column(table, sa.Column("first_seen_scan", sa.Uuid(), nullable=True))
        op.create_foreign_key(
            f"fk_{table}_first_seen_scan",
            table,
            "scan_jobs",
            ["first_seen_scan"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    for table in ("vhosts", "repositories"):
        op.drop_constraint(f"fk_{table}_first_seen_scan", table, type_="foreignkey")
        op.drop_column(table, "first_seen_scan")
