"""m4 repositories secrets endpoint sensitivity

Revision ID: 0004_m4_repositories_secrets
Revises: 0003_m3_infra_vhosts_endpoints
Create Date: 2026-09-10 19:15:41.491132
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_m4_repositories_secrets"
down_revision: str | None = "0003_m3_infra_vhosts_endpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SENS_VALUES = ("none", "low", "medium", "high", "critical")


def _sens(first: bool):
    """`sensitivity` enum — emit CREATE TYPE only on its first column use."""
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.ENUM(*_SENS_VALUES, name="sensitivity", create_type=first)
    return sa.Enum(*_SENS_VALUES, name="sensitivity")


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.Enum("github", "gitlab", "bitbucket", name="repoprovider"), nullable=False),
        sa.Column("full_name", sa.String(length=300), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("default_branch", sa.String(length=120), nullable=False),
        sa.Column("is_fork", sa.Boolean(), nullable=False),
        sa.Column("is_archived", sa.Boolean(), nullable=False),
        sa.Column("stars", sa.Integer(), nullable=False),
        sa.Column("pushed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovered_via", sa.String(length=120), nullable=False),
        sa.Column("matched_terms", sa.JSON(), nullable=False),
        sa.Column("iac_files", sa.JSON(), nullable=False),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "provider", "full_name", name="uq_repo"),
    )
    op.create_index(op.f("ix_repositories_full_name"), "repositories", ["full_name"], unique=False)
    op.create_index(op.f("ix_repositories_org_id"), "repositories", ["org_id"], unique=False)
    op.create_index(op.f("ix_repositories_project_id"), "repositories", ["project_id"], unique=False)
    op.create_table(
        "secrets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("detector_type", sa.String(length=80), nullable=False),
        sa.Column("detector", sa.String(length=40), nullable=False),
        sa.Column("source_kind", sa.String(length=20), nullable=False),
        sa.Column("source", sa.String(length=1000), nullable=False),
        sa.Column("location", sa.String(length=500), nullable=False),
        sa.Column("masked_value", sa.String(length=200), nullable=False),
        sa.Column("value_enc", sa.Text(), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("unverified", "verified", "false_positive", "revoked", name="secretstatus"),
            nullable=False,
        ),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("severity", _sens(True), nullable=False),
        sa.Column("repo_id", sa.Uuid(), nullable=True),
        sa.Column("extra", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("first_seen_scan", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["first_seen_scan"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["repo_id"], ["repositories.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "fingerprint", name="uq_secret_fingerprint"),
    )
    op.create_index(op.f("ix_secrets_detector_type"), "secrets", ["detector_type"], unique=False)
    op.create_index(op.f("ix_secrets_fingerprint"), "secrets", ["fingerprint"], unique=False)
    op.create_index(op.f("ix_secrets_org_id"), "secrets", ["org_id"], unique=False)
    op.create_index(op.f("ix_secrets_project_id"), "secrets", ["project_id"], unique=False)
    op.create_index(op.f("ix_secrets_status"), "secrets", ["status"], unique=False)
    op.add_column("endpoints", sa.Column("content_length", sa.Integer(), nullable=True))
    op.add_column(
        "endpoints",
        sa.Column("sensitivity", _sens(False), nullable=False, server_default="none"),
    )
    op.add_column(
        "endpoints",
        sa.Column("sensitivity_reason", sa.String(length=300), nullable=False, server_default=""),
    )
    op.create_index(op.f("ix_endpoints_sensitivity"), "endpoints", ["sensitivity"], unique=False)


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_endpoints_sensitivity"), table_name="endpoints")
    op.drop_column("endpoints", "sensitivity_reason")
    op.drop_column("endpoints", "sensitivity")
    op.drop_column("endpoints", "content_length")
    op.drop_index(op.f("ix_secrets_status"), table_name="secrets")
    op.drop_index(op.f("ix_secrets_project_id"), table_name="secrets")
    op.drop_index(op.f("ix_secrets_org_id"), table_name="secrets")
    op.drop_index(op.f("ix_secrets_fingerprint"), table_name="secrets")
    op.drop_index(op.f("ix_secrets_detector_type"), table_name="secrets")
    op.drop_table("secrets")
    op.drop_index(op.f("ix_repositories_project_id"), table_name="repositories")
    op.drop_index(op.f("ix_repositories_org_id"), table_name="repositories")
    op.drop_index(op.f("ix_repositories_full_name"), table_name="repositories")
    op.drop_table("repositories")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="repoprovider").drop(bind, checkfirst=True)
        sa.Enum(name="secretstatus").drop(bind, checkfirst=True)
        sa.Enum(name="sensitivity").drop(bind, checkfirst=True)
