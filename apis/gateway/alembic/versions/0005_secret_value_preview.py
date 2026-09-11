"""rename secrets.masked_value -> value_preview (values are shown unmasked)

Revision ID: 0005_secret_value_preview
Revises: 0004_m4_repositories_secrets
Create Date: 2026-09-10 21:40:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_secret_value_preview"
down_revision: str | None = "0004_m4_repositories_secrets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "secrets",
        "masked_value",
        new_column_name="value_preview",
        existing_type=sa.String(length=200),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "secrets",
        "value_preview",
        new_column_name="masked_value",
        existing_type=sa.String(length=200),
        existing_nullable=False,
    )
