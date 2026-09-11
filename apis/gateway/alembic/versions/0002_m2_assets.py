"""m2 assets asset_sources asset_edges (folded into 0001_initial)

Revision ID: 0002_m2_assets
Revises: 0001_initial

No-op. Originally added the `assets`/`asset_sources`/`asset_edges` tables
on top of a frozen M1 snapshot; 0001_initial now creates the complete
current schema in one shot (see its docstring for why), so this revision's
DDL would be a hard duplicate. Kept as a no-op, rather than deleted, so the
revision ID stays valid for any database already stamped at this point in
the chain. Do not add real DDL back here — add new migrations after 0009.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0002_m2_assets"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
