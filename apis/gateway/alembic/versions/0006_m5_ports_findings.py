"""m5 ports & vulnerability findings (folded into 0001_initial)

Revision ID: 0006_m5_ports_findings
Revises: 0005_secret_value_preview

No-op — see 0002_m2_assets.py for why. Originally added `ports`/`findings`;
now part of 0001_initial.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0006_m5_ports_findings"
down_revision: str | None = "0005_secret_value_preview"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
