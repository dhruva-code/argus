"""m3 infra vhosts endpoints (folded into 0001_initial)

Revision ID: 0003_m3_infra_vhosts_endpoints
Revises: 0002_m2_assets

No-op — see 0002_m2_assets.py for why. Originally added `vhosts`/
`endpoints` and extended the `assettype` enum with `asn`/`netblock`; all of
that is now part of 0001_initial's single-shot schema creation.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0003_m3_infra_vhosts_endpoints"
down_revision: str | None = "0002_m2_assets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
