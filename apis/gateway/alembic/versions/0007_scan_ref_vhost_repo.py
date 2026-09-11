"""add first_seen_scan to vhosts and repositories (folded into 0001_initial)

Revision ID: 0007_scan_ref_vhost_repo
Revises: 0006_m5_ports_findings

No-op — see 0002_m2_assets.py for why. Now part of 0001_initial.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0007_scan_ref_vhost_repo"
down_revision: str | None = "0006_m5_ports_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
