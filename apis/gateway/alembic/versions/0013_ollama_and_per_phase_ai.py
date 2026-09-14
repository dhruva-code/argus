"""Ollama provider support + opt-in per-phase AI analysis

Revision ID: 0013_ollama_and_per_phase_ai
Revises: 0012_jsonb_contains_filters

Adds `ai_settings.ollama_base_url` (local/self-hosted Ollama server, no API
key needed) and `ai_settings.analyze_every_phase` (opt-in: ask the
configured AI for a short bug-hunting strategy note after each recon phase
checkpoint, stored as a job event).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0013_ollama_and_per_phase_ai"
down_revision: str | None = "0012_jsonb_contains_filters"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "ai_settings",
        sa.Column("ollama_base_url", sa.String(300), nullable=False, server_default="http://localhost:11434"),
    )
    op.add_column(
        "ai_settings",
        sa.Column("analyze_every_phase", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("ai_settings", "analyze_every_phase")
    op.drop_column("ai_settings", "ollama_base_url")
