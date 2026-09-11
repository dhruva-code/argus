"""rename secrets.masked_value -> value_preview (folded into 0001_initial)

Revision ID: 0005_secret_value_preview
Revises: 0004_m4_repositories_secrets

No-op — see 0002_m2_assets.py for why. Now part of 0001_initial.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0005_secret_value_preview"
down_revision: str | None = "0004_m4_repositories_secrets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
