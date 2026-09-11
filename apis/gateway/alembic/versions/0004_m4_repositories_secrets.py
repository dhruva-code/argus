"""m4 repositories secrets endpoint sensitivity (folded into 0001_initial)

Revision ID: 0004_m4_repositories_secrets
Revises: 0003_m3_infra_vhosts_endpoints

No-op — see 0002_m2_assets.py for why. Originally added `repositories`/
`secrets` and endpoint sensitivity columns; now part of 0001_initial.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0004_m4_repositories_secrets"
down_revision: str | None = "0003_m3_infra_vhosts_endpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
