"""AI triage for findings and secrets

Revision ID: 0014_ai_triage_findings_secrets
Revises: 0013_ollama_and_per_phase_ai

Adds a distinct AI-assessment layer to `findings` and `secrets`, kept
strictly separate from each table's own scanner-owned evidence/verification
fields — AI never overwrites raw detection data, it only adds a parallel
opinion plus a suppression signal for the default list views.

`ai_fingerprint` is a hash of exactly the evidence that was sent to the
model/heuristic; the background triage task compares it against the
current evidence before re-running analysis, so unchanged findings/secrets
are not re-analyzed on every re-observation.

Column-existence-guarded (see app/_migration_guards.py) — 0001_initial's
`Base.metadata.create_all()` against current `app/models.py` already
creates these columns on a database built via the full 0001->head chain
from empty (any brand-new install); confirmed by actually running that
chain against a fresh Postgres database.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

from app._migration_guards import add_column_if_missing

revision: str = "0014_ai_triage_findings_secrets"
down_revision: str | None = "0013_ollama_and_per_phase_ai"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    add_column_if_missing(
        "findings", sa.Column("ai_classification", sa.String(120), nullable=False, server_default="")
    )
    add_column_if_missing(
        "findings",
        sa.Column("ai_false_positive_likelihood", sa.String(20), nullable=False, server_default=""),
    )
    add_column_if_missing("findings", sa.Column("ai_reasoning", sa.Text(), nullable=False, server_default=""))
    add_column_if_missing(
        "findings", sa.Column("ai_engine", sa.String(20), nullable=False, server_default="")
    )
    add_column_if_missing("findings", sa.Column("ai_analyzed_at", sa.DateTime(timezone=True), nullable=True))
    add_column_if_missing(
        "findings", sa.Column("ai_fingerprint", sa.String(64), nullable=False, server_default="")
    )

    add_column_if_missing(
        "secrets", sa.Column("ai_classification", sa.String(20), nullable=False, server_default="")
    )
    add_column_if_missing("secrets", sa.Column("ai_reasoning", sa.Text(), nullable=False, server_default=""))
    add_column_if_missing("secrets", sa.Column("ai_engine", sa.String(20), nullable=False, server_default=""))
    add_column_if_missing("secrets", sa.Column("ai_analyzed_at", sa.DateTime(timezone=True), nullable=True))
    add_column_if_missing(
        "secrets", sa.Column("ai_fingerprint", sa.String(64), nullable=False, server_default="")
    )


def downgrade() -> None:
    for col in ("ai_classification", "ai_reasoning", "ai_engine", "ai_analyzed_at", "ai_fingerprint"):
        op.drop_column("secrets", col)
    for col in (
        "ai_classification",
        "ai_false_positive_likelihood",
        "ai_reasoning",
        "ai_engine",
        "ai_analyzed_at",
        "ai_fingerprint",
    ):
        op.drop_column("findings", col)
