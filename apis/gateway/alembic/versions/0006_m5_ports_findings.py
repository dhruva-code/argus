"""m5 ports & vulnerability findings

Revision ID: 0006_m5_ports_findings
Revises: 0005_secret_value_preview
Create Date: 2026-09-10 22:05:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_m5_ports_findings"
down_revision: str | None = "0005_secret_value_preview"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PORTSTATE = ("open", "filtered", "closed")
_FSEV = ("info", "low", "medium", "high", "critical")
_FSTATUS = (
    "open",
    "confirmed",
    "probable",
    "needs_review",
    "false_positive",
    "fixed",
    "accepted_risk",
)


def upgrade() -> None:
    op.create_table(
        "ports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("state", sa.Enum(*_PORTSTATE, name="portstate"), nullable=False),
        sa.Column("service", sa.String(length=80), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("banner", sa.String(length=500), nullable=False),
        sa.Column("tls", sa.Boolean(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("http_title", sa.String(length=300), nullable=False),
        sa.Column("hostnames", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("extra", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("first_seen_scan", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["first_seen_scan"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "ip", "port", "protocol", name="uq_port"),
    )
    op.create_index(op.f("ix_ports_ip"), "ports", ["ip"], unique=False)
    op.create_index(op.f("ix_ports_org_id"), "ports", ["org_id"], unique=False)
    op.create_index(op.f("ix_ports_project_id"), "ports", ["project_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("template_id", sa.String(length=200), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("severity", sa.Enum(*_FSEV, name="findingseverity"), nullable=False),
        sa.Column("status", sa.Enum(*_FSTATUS, name="findingstatus"), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("engine", sa.String(length=40), nullable=False),
        sa.Column("template_version", sa.String(length=40), nullable=False),
        sa.Column("scan_level", sa.String(length=20), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("matched_at", sa.String(length=1000), nullable=False),
        sa.Column("normalized_path", sa.String(length=500), nullable=False),
        sa.Column("matcher_name", sa.String(length=120), nullable=False),
        sa.Column("extracted", sa.JSON(), nullable=False),
        sa.Column("request", sa.Text(), nullable=True),
        sa.Column("response_excerpt", sa.Text(), nullable=True),
        sa.Column("curl_command", sa.Text(), nullable=True),
        sa.Column("reference", sa.JSON(), nullable=False),
        sa.Column("cve", sa.JSON(), nullable=False),
        sa.Column("cwe", sa.JSON(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("verification", sa.String(length=30), nullable=False),
        sa.Column("verification_note", sa.String(length=400), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("triage_reason", sa.String(length=500), nullable=False),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("extra", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("first_seen_scan", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["first_seen_scan"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "fingerprint", name="uq_finding"),
    )
    op.create_index(op.f("ix_findings_fingerprint"), "findings", ["fingerprint"], unique=False)
    op.create_index(op.f("ix_findings_host"), "findings", ["host"], unique=False)
    op.create_index(op.f("ix_findings_org_id"), "findings", ["org_id"], unique=False)
    op.create_index(op.f("ix_findings_project_id"), "findings", ["project_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index(op.f("ix_findings_template_id"), "findings", ["template_id"], unique=False)


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("ports")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="findingstatus").drop(bind, checkfirst=True)
        sa.Enum(name="findingseverity").drop(bind, checkfirst=True)
        sa.Enum(name="portstate").drop(bind, checkfirst=True)
