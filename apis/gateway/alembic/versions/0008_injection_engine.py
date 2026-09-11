"""Injection Testing Engine (folded into 0001_initial)

Revision ID: 0008_injection_engine
Revises: 0007_scan_ref_vhost_repo

No-op — see 0002_m2_assets.py for why. Originally added injection_points,
oast_events, auth_profiles, project soft-delete, endpoint classification,
and finding injection fields; now part of 0001_initial.
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0008_injection_engine"
down_revision: str | None = "0007_scan_ref_vhost_repo"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
