"""Injection Testing Engine: injection_points, oast_events, auth_profiles;
project soft-delete; endpoint classification; finding injection fields;
performance indexes.

Revision ID: 0008_injection_engine
Revises: 0007_scan_ref_vhost_repo
Create Date: 2026-09-11 08:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_injection_engine"
down_revision: str | None = "0007_scan_ref_vhost_repo"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── project soft-delete (§18) ──────────────────────────────────────────
    op.add_column("projects", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("projects", sa.Column("deletion_job_id", sa.Uuid(), nullable=True))

    # ── endpoint classification (§14) ──────────────────────────────────────
    op.add_column(
        "endpoints",
        sa.Column("endpoint_class", sa.String(length=30), nullable=False, server_default="unknown"),
    )
    op.add_column("endpoints", sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "endpoints", sa.Column("auth_required", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.create_index(op.f("ix_endpoints_endpoint_class"), "endpoints", ["endpoint_class"])
    op.create_index(op.f("ix_endpoints_risk_score"), "endpoints", ["risk_score"])

    # ── auth_profiles ───────────────────────────────────────────────────────
    op.create_table(
        "auth_profiles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("header_name", sa.String(length=120), nullable=False),
        sa.Column("cookie_name", sa.String(length=120), nullable=False),
        sa.Column("location", sa.String(length=10), nullable=False),
        sa.Column("value_enc", sa.Text(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name", name="uq_auth_profile_name"),
    )
    op.create_index(op.f("ix_auth_profiles_org_id"), "auth_profiles", ["org_id"])
    op.create_index(op.f("ix_auth_profiles_project_id"), "auth_profiles", ["project_id"])

    # ── injection_points ─────────────────────────────────────────────────────
    op.create_table(
        "injection_points",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("endpoint_id", sa.Uuid(), nullable=True),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("url", sa.String(length=2000), nullable=False),
        sa.Column("host", sa.String(length=300), nullable=False),
        sa.Column("param_name", sa.String(length=200), nullable=False),
        sa.Column("location", sa.String(length=20), nullable=False),
        sa.Column("param_type", sa.String(length=20), nullable=False),
        sa.Column("context", sa.String(length=20), nullable=False),
        sa.Column("technology", sa.String(length=300), nullable=False),
        sa.Column("auth_state", sa.String(length=40), nullable=False),
        sa.Column("candidate_classes", sa.JSON(), nullable=False),
        sa.Column("tested_classes", sa.JSON(), nullable=False),
        sa.Column("best_result", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("auth_profile_id", sa.Uuid(), nullable=True),
        sa.Column("last_tested", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("first_seen_scan", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["auth_profile_id"], ["auth_profiles.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["endpoint_id"], ["endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["first_seen_scan"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id", "method", "url", "param_name", "location", name="uq_injection_point"
        ),
    )
    op.create_index(op.f("ix_injection_points_endpoint_id"), "injection_points", ["endpoint_id"])
    op.create_index(op.f("ix_injection_points_host"), "injection_points", ["host"])
    op.create_index(op.f("ix_injection_points_org_id"), "injection_points", ["org_id"])
    op.create_index(op.f("ix_injection_points_project_id"), "injection_points", ["project_id"])

    # ── oast_events ───────────────────────────────────────────────────────
    op.create_table(
        "oast_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False),
        sa.Column("remote_addr", sa.String(length=64), nullable=False),
        sa.Column("request_summary", sa.String(length=2000), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_oast_events_org_id"), "oast_events", ["org_id"])
    op.create_index(op.f("ix_oast_events_project_id"), "oast_events", ["project_id"])
    op.create_index(op.f("ix_oast_events_token"), "oast_events", ["token"])

    # ── finding injection-engine fields (§1-13) ─────────────────────────────
    op.add_column("findings", sa.Column("parameter", sa.String(length=200), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("param_location", sa.String(length=20), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("injection_class", sa.String(length=30), nullable=False, server_default=""))
    op.add_column("findings", sa.Column("detection_method", sa.String(length=30), nullable=False, server_default=""))
    op.add_column(
        "findings",
        sa.Column("verification_tier", sa.String(length=20), nullable=False, server_default="potential"),
    )
    op.add_column("findings", sa.Column("evidence_quality", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("findings", sa.Column("injection_point_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_findings_injection_point_id", "findings", "injection_points",
        ["injection_point_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index(op.f("ix_findings_injection_class"), "findings", ["injection_class"])
    op.create_index(op.f("ix_findings_verification_tier"), "findings", ["verification_tier"])

    # ── §25 performance indexes: common list/filter combinations ───────────
    op.create_index("ix_findings_project_status", "findings", ["project_id", "status"])
    op.create_index("ix_findings_project_severity", "findings", ["project_id", "severity"])
    op.create_index("ix_assets_project_status", "assets", ["project_id", "status"])
    op.create_index("ix_endpoints_project_risk", "endpoints", ["project_id", "risk_score"])
    op.create_index("ix_ports_project_ip", "ports", ["project_id", "ip"])
    op.create_index("ix_scan_jobs_project_created", "scan_jobs", ["project_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_project_created", table_name="scan_jobs")
    op.drop_index("ix_ports_project_ip", table_name="ports")
    op.drop_index("ix_endpoints_project_risk", table_name="endpoints")
    op.drop_index("ix_assets_project_status", table_name="assets")
    op.drop_index("ix_findings_project_severity", table_name="findings")
    op.drop_index("ix_findings_project_status", table_name="findings")

    op.drop_index(op.f("ix_findings_verification_tier"), table_name="findings")
    op.drop_index(op.f("ix_findings_injection_class"), table_name="findings")
    op.drop_constraint("fk_findings_injection_point_id", "findings", type_="foreignkey")
    op.drop_column("findings", "injection_point_id")
    op.drop_column("findings", "evidence_quality")
    op.drop_column("findings", "verification_tier")
    op.drop_column("findings", "detection_method")
    op.drop_column("findings", "injection_class")
    op.drop_column("findings", "param_location")
    op.drop_column("findings", "parameter")

    op.drop_index(op.f("ix_oast_events_token"), table_name="oast_events")
    op.drop_index(op.f("ix_oast_events_project_id"), table_name="oast_events")
    op.drop_index(op.f("ix_oast_events_org_id"), table_name="oast_events")
    op.drop_table("oast_events")

    op.drop_index(op.f("ix_injection_points_project_id"), table_name="injection_points")
    op.drop_index(op.f("ix_injection_points_org_id"), table_name="injection_points")
    op.drop_index(op.f("ix_injection_points_host"), table_name="injection_points")
    op.drop_index(op.f("ix_injection_points_endpoint_id"), table_name="injection_points")
    op.drop_table("injection_points")

    op.drop_index(op.f("ix_auth_profiles_project_id"), table_name="auth_profiles")
    op.drop_index(op.f("ix_auth_profiles_org_id"), table_name="auth_profiles")
    op.drop_table("auth_profiles")

    op.drop_index(op.f("ix_endpoints_risk_score"), table_name="endpoints")
    op.drop_index(op.f("ix_endpoints_endpoint_class"), table_name="endpoints")
    op.drop_column("endpoints", "auth_required")
    op.drop_column("endpoints", "risk_score")
    op.drop_column("endpoints", "endpoint_class")

    op.drop_column("projects", "deletion_job_id")
    op.drop_column("projects", "deleted_at")
