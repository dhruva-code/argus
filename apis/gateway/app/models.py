"""SQLAlchemy models for Milestone 1.

Tenancy rule: every row below organization level carries ``org_id`` and every
query in the routers filters on the caller's organization. See
docs/ARCHITECTURE.md § Multi-tenancy.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


# Real JSONB everywhere (so .contains() compiles to Postgres's `@>`
# containment operator — SQLAlchemy resolves operator overloads from a
# column's *declared* type, so `.with_variant(JSONB(), "postgresql")` on a
# generic JSON base does NOT work here: .contains() still resolves to
# generic JSON's LIKE-based comparator even on a Postgres-bound column).
# SQLite (tests) can't compile JSONB DDL at all, so this DDL-compiler hook
# renders it as plain JSON there — SQLite has no @>-vs-LIKE distinction to
# preserve, and no test exercises a Postgres-specific containment query.
# Use JSONB (not plain JSON), not bare JSON, for any list-of-strings column
# that's ever filtered with .contains() — see Asset.technologies /
# Endpoint.tags / Endpoint.sources.
@compiles(JSONB, "sqlite")
def _jsonb_as_json_on_sqlite(element, compiler, **kw):
    return "JSON"


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


# ── Enums ──────────────────────────────────────────────────────────────────


class Role(enum.StrEnum):
    super_admin = "super_admin"
    org_admin = "org_admin"
    security_lead = "security_lead"
    security_analyst = "security_analyst"
    researcher = "researcher"
    viewer = "viewer"


class ScopeEffect(enum.StrEnum):
    allow = "allow"
    deny = "deny"


class ScopeMatcher(enum.StrEnum):
    domain = "domain"
    subdomain = "subdomain"
    wildcard = "wildcard"
    cidr = "cidr"
    ip = "ip"
    asn = "asn"
    url = "url"
    regex = "regex"


class JobStatus(enum.StrEnum):
    queued = "queued"
    running = "running"
    paused = "paused"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"
    partially_completed = "partially_completed"


class ToolHealth(enum.StrEnum):
    ok = "ok"
    degraded = "degraded"
    missing = "missing"
    unknown = "unknown"


class RiskProfile(enum.StrEnum):
    low = "low"
    moderate = "moderate"
    high = "high"
    critical = "critical"


class AssetType(enum.StrEnum):
    domain = "domain"
    subdomain = "subdomain"
    ip = "ip"
    url = "url"
    asn = "asn"
    netblock = "netblock"


class AssetStatus(enum.StrEnum):
    unknown = "unknown"
    resolved = "resolved"
    alive = "alive"
    dead = "dead"


class EdgeKind(enum.StrEnum):
    resolves_to = "resolves_to"
    cname_to = "cname_to"
    redirects_to = "redirects_to"
    hosts = "hosts"
    belongs_to = "belongs_to"  # ip -> netblock
    announced_by = "announced_by"  # netblock -> asn
    serves = "serves"  # ip -> virtual host


class VHostClass(enum.StrEnum):
    default = "default"
    interesting = "interesting"
    potential_internal = "potential_internal"
    unusual_response = "unusual_response"


class HTTPMethod(enum.StrEnum):
    get = "GET"
    post = "POST"
    put = "PUT"
    patch = "PATCH"
    delete = "DELETE"
    head = "HEAD"
    options = "OPTIONS"


class Sensitivity(enum.StrEnum):
    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SecretStatus(enum.StrEnum):
    unverified = "unverified"
    verified = "verified"
    false_positive = "false_positive"
    revoked = "revoked"


class RepoProvider(enum.StrEnum):
    github = "github"
    gitlab = "gitlab"
    bitbucket = "bitbucket"


class PortState(enum.StrEnum):
    open = "open"
    filtered = "filtered"
    closed = "closed"


class FindingSeverity(enum.StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingStatus(enum.StrEnum):
    open = "open"
    confirmed = "confirmed"
    probable = "probable"
    needs_review = "needs_review"
    false_positive = "false_positive"
    fixed = "fixed"
    accepted_risk = "accepted_risk"


# ── Identity ───────────────────────────────────────────────────────────────


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    retention_raw_days: Mapped[int] = mapped_column(Integer, default=90)
    retention_screenshot_days: Mapped[int] = mapped_column(Integer, default=180)
    retention_audit_days: Mapped[int] = mapped_column(Integer, default=365)

    members: Mapped[list[Membership]] = relationship(back_populates="org", cascade="all, delete-orphan")
    projects: Mapped[list[Project]] = relationship(back_populates="org", cascade="all, delete-orphan")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Account/profile (finalization pass)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verify_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    email_verify_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pending_email: Mapped[str | None] = mapped_column(
        String(320), nullable=True
    )  # set on change-email until re-verified
    password_reset_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    password_reset_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    language: Mapped[str] = mapped_column(String(16), default="en")
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    theme: Mapped[str] = mapped_column(String(16), default="system")  # system | light | dark

    memberships: Mapped[list[Membership]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Membership(Base, TimestampMixin):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id", name="uq_member_user_org"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.viewer, nullable=False)

    user: Mapped[User] = relationship(back_populates="memberships")
    org: Mapped[Organization] = relationship(back_populates="members")


class RefreshToken(Base, TimestampMixin):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Projects & scope ───────────────────────────────────────────────────────


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    program_name: Mapped[str] = mapped_column(String(200), default="")
    client: Mapped[str] = mapped_column(String(200), default="")
    program_url: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    rules_of_engagement: Mapped[str] = mapped_column(Text, default="")
    risk_profile: Mapped[RiskProfile] = mapped_column(Enum(RiskProfile), default=RiskProfile.moderate)
    default_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_profiles.id", ondelete="SET NULL"), nullable=True
    )
    schedule_cron: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notification_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    # soft-delete (§18): set on "Delete Project"; a background job then wipes the
    # project's data and, after that job reports done, the row itself.
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deletion_job_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    org: Mapped[Organization] = relationship(back_populates="projects")
    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="ScopeRule.position"
    )
    jobs: Mapped[list[ScanJob]] = relationship(back_populates="project", cascade="all, delete-orphan")


class ScopeRule(Base, TimestampMixin):
    __tablename__ = "scope_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    effect: Mapped[ScopeEffect] = mapped_column(Enum(ScopeEffect), nullable=False)
    matcher: Mapped[ScopeMatcher] = mapped_column(Enum(ScopeMatcher), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    paths: Mapped[list] = mapped_column(JSON, default=list)
    note: Mapped[str] = mapped_column(String(300), default="")

    project: Mapped[Project] = relationship(back_populates="scope_rules")


class ScanProfile(Base, TimestampMixin):
    __tablename__ = "scan_profiles"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    phases: Mapped[dict] = mapped_column(JSON, default=dict)
    rate_limits: Mapped[dict] = mapped_column(JSON, default=dict)
    requires_active_ack: Mapped[bool] = mapped_column(Boolean, default=True)


# ── Jobs ───────────────────────────────────────────────────────────────────


class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus), default=JobStatus.queued, nullable=False, index=True
    )
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    rate_limits: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    worker: Mapped[str | None] = mapped_column(String(120), nullable=True)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    project: Mapped[Project] = relationship(back_populates="jobs")
    events: Mapped[list[JobEvent]] = relationship(
        back_populates="job", cascade="all, delete-orphan", order_by="JobEvent.at"
    )


class JobEvent(Base):
    __tablename__ = "job_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(30), nullable=False)
    level: Mapped[str] = mapped_column(String(16), default="INFO")
    message: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    job: Mapped[ScanJob] = relationship(back_populates="events")


# ── Tools ──────────────────────────────────────────────────────────────────


class ToolIntegration(Base, TimestampMixin):
    __tablename__ = "tool_integrations"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_tool_org_name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    health: Mapped[ToolHealth] = mapped_column(Enum(ToolHealth), default=ToolHealth.unknown)
    health_detail: Mapped[str] = mapped_column(Text, default="")
    installed_version: Mapped[str] = mapped_column(String(60), default="")
    tested_version: Mapped[str] = mapped_column(String(60), default="")
    min_version: Mapped[str] = mapped_column(String(60), default="")
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    safety_class: Mapped[str] = mapped_column(String(20), default="")
    needs_api_key: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    versions: Mapped[list[ToolVersion]] = relationship(
        back_populates="tool",
        cascade="all, delete-orphan",
        order_by="ToolVersion.detected_at.desc()",
    )


class ToolVersion(Base):
    __tablename__ = "tool_versions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    tool_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tool_integrations.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[str] = mapped_column(String(60), nullable=False)
    health: Mapped[str] = mapped_column(String(20), default="unknown")
    detail: Mapped[str] = mapped_column(Text, default="")
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    tool: Mapped[ToolIntegration] = relationship(back_populates="versions")


# ── Assets (M2 — Asset Identity Engine) ────────────────────────────────────


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "type", "value", name="uq_asset_project_type_value"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)

    in_scope: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    scope_reason: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[AssetStatus] = mapped_column(Enum(AssetStatus), default=AssetStatus.unknown, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=40)

    # resolution / network
    ip_addresses: Mapped[list] = mapped_column(JSON, default=list)
    cname: Mapped[str] = mapped_column(String(300), default="")
    asn: Mapped[str] = mapped_column(String(32), default="")
    is_wildcard: Mapped[bool] = mapped_column(Boolean, default=False)

    # infrastructure enrichment (M3, mostly for IP assets)
    ptr: Mapped[str] = mapped_column(String(300), default="")
    netblock: Mapped[str] = mapped_column(String(64), default="")
    asn_org: Mapped[str] = mapped_column(String(200), default="")
    cloud_provider: Mapped[str] = mapped_column(String(60), default="")
    geo_country: Mapped[str] = mapped_column(String(4), default="")

    # http probe
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_title: Mapped[str] = mapped_column(String(500), default="")
    http_server: Mapped[str] = mapped_column(String(200), default="")
    http_scheme: Mapped[str] = mapped_column(String(10), default="")
    http_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str] = mapped_column(String(120), default="")
    final_url: Mapped[str] = mapped_column(String(1000), default="")
    tls_names: Mapped[list] = mapped_column(JSON, default=list)
    technologies: Mapped[list] = mapped_column(JSONB, default=list)  # filtered via .contains()

    tags: Mapped[list] = mapped_column(JSON, default=list)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )

    sources: Mapped[list[AssetSource]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class AssetSource(Base):
    __tablename__ = "asset_sources"
    __table_args__ = (UniqueConstraint("asset_id", "source", name="uq_asset_source"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(60), nullable=False)
    detail: Mapped[str] = mapped_column(String(300), default="")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    asset: Mapped[Asset] = relationship(back_populates="sources")


class AssetEdge(Base):
    __tablename__ = "asset_edges"
    __table_args__ = (UniqueConstraint("src_asset_id", "dst_asset_id", "kind", name="uq_edge"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    src_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    dst_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[EdgeKind] = mapped_column(Enum(EdgeKind), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# ── Virtual hosts (M3 — Phase 6) ──────────────────────────────────────────


class VHost(Base):
    __tablename__ = "vhosts"
    __table_args__ = (UniqueConstraint("project_id", "ip", "hostname", name="uq_vhost"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    scheme: Mapped[str] = mapped_column(String(10), default="https")
    port: Mapped[int] = mapped_column(Integer, default=443)
    classification: Mapped[VHostClass] = mapped_column(
        Enum(VHostClass), default=VHostClass.default, index=True
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_bytes: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(500), default="")
    server: Mapped[str] = mapped_column(String(200), default="")
    baseline_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    baseline_bytes: Mapped[int] = mapped_column(Integer, default=0)
    similarity: Mapped[float] = mapped_column(default=1.0)  # 0..1 vs baseline
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


# ── Endpoints (M3 — Phase 7) ──────────────────────────────────────────────


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("project_id", "method", "normalized_url", name="uq_endpoint_project_method_norm"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    method: Mapped[str] = mapped_column(String(10), default="GET")
    host: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    scheme: Mapped[str] = mapped_column(String(10), default="https")
    path: Mapped[str] = mapped_column(String(1000), default="/")
    # /users/{id}?page — the structural signature endpoints dedup on
    normalized_url: Mapped[str] = mapped_column(String(1200), nullable=False, index=True)
    sample_url: Mapped[str] = mapped_column(String(2000), default="")
    query_keys: Mapped[list] = mapped_column(JSON, default=list)
    params: Mapped[list] = mapped_column(JSON, default=list)  # [{name, kind, in}]
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str] = mapped_column(String(120), default="")
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    sensitivity: Mapped[Sensitivity] = mapped_column(Enum(Sensitivity), default=Sensitivity.none, index=True)
    sensitivity_reason: Mapped[str] = mapped_column(String(300), default="")
    tags: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # api, admin, swagger, graphql, js… — filtered via .contains()
    sources: Mapped[list] = mapped_column(
        JSONB, default=list
    )  # katana, gau, robots, ffuf… — filtered via .contains()
    # §14 classification + testing-priority score (0-100); §16 API intelligence
    endpoint_class: Mapped[str] = mapped_column(String(30), default="unknown", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    # Wayback Machine CDX capture time range for this URL (distinct from
    # first_seen/last_seen above, which track when *Argus* discovered the
    # endpoint, not when the Internet Archive crawled it). Null when the
    # endpoint was never observed via the wayback source.
    wayback_first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wayback_last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Source-code intelligence & secrets (M4 — Phases 8 & 10) ───────────────


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("project_id", "provider", "full_name", name="uq_repo"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    provider: Mapped[RepoProvider] = mapped_column(Enum(RepoProvider), default=RepoProvider.github)
    full_name: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    default_branch: Mapped[str] = mapped_column(String(120), default="")
    is_fork: Mapped[bool] = mapped_column(Boolean, default=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    stars: Mapped[int] = mapped_column(Integer, default=0)
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discovered_via: Mapped[str] = mapped_column(String(120), default="")
    matched_terms: Mapped[list] = mapped_column(JSON, default=list)
    iac_files: Mapped[list] = mapped_column(JSON, default=list)  # dockerfile, k8s, terraform…
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint", name="uq_secret_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    # Deterministic dedup key: sha256(type + location + last-4-of-value).
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    detector_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    detector: Mapped[str] = mapped_column(String(40), default="")  # trufflehog | gitleaks | custom
    source_kind: Mapped[str] = mapped_column(String(20), default="js")  # js | repo | endpoint
    source: Mapped[str] = mapped_column(String(1000), default="")
    location: Mapped[str] = mapped_column(String(500), default="")  # file:line
    # Real leading characters of the value for list views (a prefix, not a mask).
    value_preview: Mapped[str] = mapped_column(String(200), default="")
    # Full value, also kept encrypted at rest (DB/backup-leak protection);
    # decrypted and returned to operators with finding.read.
    value_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[SecretStatus] = mapped_column(
        Enum(SecretStatus), default=SecretStatus.unverified, index=True
    )
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    severity: Mapped[Sensitivity] = mapped_column(Enum(Sensitivity), default=Sensitivity.high)
    repo_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True
    )
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


# ── Ports & vulnerability findings (M5 — Phases 11 & 12) ──────────────────


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("project_id", "ip", "port", "protocol", name="uq_port"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[PortState] = mapped_column(Enum(PortState), default=PortState.open)
    service: Mapped[str] = mapped_column(String(80), default="")
    product: Mapped[str] = mapped_column(String(200), default="")
    version: Mapped[str] = mapped_column(String(80), default="")
    banner: Mapped[str] = mapped_column(String(500), default="")
    tls: Mapped[bool] = mapped_column(Boolean, default=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    http_title: Mapped[str] = mapped_column(String(300), default="")
    hostnames: Mapped[list] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(40), default="naabu")
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint", name="uq_finding"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    # sha256(template_id + host + normalized_path + matcher_name)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    template_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(300), default="")
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity), default=FindingSeverity.info, index=True
    )
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.open, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    engine: Mapped[str] = mapped_column(String(40), default="nuclei")
    template_version: Mapped[str] = mapped_column(String(40), default="")
    scan_level: Mapped[str] = mapped_column(String(20), default="passive")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    host: Mapped[str] = mapped_column(String(255), default="", index=True)
    matched_at: Mapped[str] = mapped_column(String(1000), default="")
    normalized_path: Mapped[str] = mapped_column(String(500), default="")
    matcher_name: Mapped[str] = mapped_column(String(120), default="")
    extracted: Mapped[list] = mapped_column(JSON, default=list)
    request: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    curl_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference: Mapped[list] = mapped_column(JSON, default=list)
    cve: Mapped[list] = mapped_column(JSON, default=list)
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    verification: Mapped[str] = mapped_column(String(30), default="unverified")
    verification_note: Mapped[str] = mapped_column(String(400), default="")
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    triage_reason: Mapped[str] = mapped_column(String(500), default="")
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    # Injection Testing Engine fields (§1-13) — populated when engine="injection-engine";
    # left at their defaults for nuclei/waf-cdn/derived findings.
    parameter: Mapped[str] = mapped_column(String(200), default="")
    param_location: Mapped[str] = mapped_column(
        String(20), default=""
    )  # query|body_form|body_json|path|header|cookie|graphql_var
    injection_class: Mapped[str] = mapped_column(String(30), default="", index=True)
    detection_method: Mapped[str] = mapped_column(
        String(30), default=""
    )  # error_based|boolean_based|time_based|reflection|oast_callback|canary
    verification_tier: Mapped[str] = mapped_column(
        String(20), default="potential", index=True
    )  # potential|likely|verified
    evidence_quality: Mapped[int] = mapped_column(Integer, default=0)
    injection_point_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("injection_points.id", ondelete="SET NULL"), nullable=True
    )
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


# ── Injection Testing Engine (§1-13) ────────────────────────────────────────


class InjectionPoint(Base):
    """A classified, testable parameter — the row the Injection Point Explorer
    (§12) lists and lets an analyst re-test individually."""

    __tablename__ = "injection_points"
    __table_args__ = (
        UniqueConstraint("project_id", "method", "url", "param_name", "location", name="uq_injection_point"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True, index=True
    )
    method: Mapped[str] = mapped_column(String(10), default="GET")
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    host: Mapped[str] = mapped_column(String(300), default="", index=True)
    param_name: Mapped[str] = mapped_column(String(200), nullable=False)
    location: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # query|body_form|body_json|path|header|cookie|graphql_var
    param_type: Mapped[str] = mapped_column(
        String(20), default="unknown"
    )  # numeric|string|json|uuid|bool|unknown
    context: Mapped[str] = mapped_column(
        String(20), default=""
    )  # html|attribute|javascript|url|css|json|dom_sink
    technology: Mapped[str] = mapped_column(String(300), default="")
    auth_state: Mapped[str] = mapped_column(String(40), default="unauthenticated")
    candidate_classes: Mapped[list] = mapped_column(JSON, default=list)
    tested_classes: Mapped[list] = mapped_column(JSON, default=list)
    best_result: Mapped[str] = mapped_column(
        String(20), default="untested"
    )  # untested|none|potential|likely|verified
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    auth_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("auth_profiles.id", ondelete="SET NULL"), nullable=True
    )
    last_tested: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    first_seen_scan: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )


class OASTEvent(Base):
    """An out-of-band interaction received by the platform's own HTTP callback
    collector, correlated back to the injection point/finding that generated
    the token (§7, §10). DNS interaction is not implemented — see PERFORMANCE.md
    / known limitations."""

    __tablename__ = "oast_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(10), default="http")
    remote_addr: Mapped[str] = mapped_column(String(64), default="")
    request_summary: Mapped[str] = mapped_column(String(2000), default="")
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuthProfile(Base):
    """A reusable auth context the injection engine (and future authenticated
    DAST) attaches to requests (§17). The secret material is Fernet/Vault
    encrypted; it is never written to logs or returned by the API."""

    __tablename__ = "auth_profiles"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_auth_profile_name"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # none|basic|bearer|api_key|cookie|oauth_session
    header_name: Mapped[str] = mapped_column(String(120), default="")
    cookie_name: Mapped[str] = mapped_column(String(120), default="")
    location: Mapped[str] = mapped_column(String(10), default="header")  # header|cookie|query
    value_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# ── Audit ──────────────────────────────────────────────────────────────────


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str] = mapped_column(String(320), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(60), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    before: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


# ── User notification preferences, Telegram linking, delivery log ─────────
#
# Per-user (not per-project — see app/services/notify.py for the older,
# still-active per-project Slack/webhook/email policy on scan completion).
# This is the account-level "how do I personally want to hear about things"
# layer the Settings → Notifications page reads/writes.

_DEFAULT_NOTIFICATION_EVENTS = {
    "scan_started": False,
    "scan_completed": True,
    "scan_failed": True,
    "scan_partially_completed": True,
    "finding_critical": True,
    "finding_high": True,
    "new_asset": False,
    "weekly_summary": True,
    "system_error": True,
}


class NotificationPreference(Base, TimestampMixin):
    __tablename__ = "notification_preferences"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    email_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    telegram_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    events: Mapped[dict] = mapped_column(JSON, default=lambda: dict(_DEFAULT_NOTIFICATION_EVENTS))
    quiet_hours_start: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0-23, local hour
    quiet_hours_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quiet_hours_override_critical: Mapped[bool] = mapped_column(Boolean, default=True)


class TelegramLink(Base, TimestampMixin):
    """One row per user once paired; a pending (unpaired) row has chat_id NULL
    and an unexpired pairing_code."""

    __tablename__ = "telegram_links"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    pairing_code: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    pairing_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    chat_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telegram_username: Mapped[str] = mapped_column(String(120), default="")
    linked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationDelivery(Base, TimestampMixin):
    """One row per attempted notification — the retry/dead-letter/audit
    trail §15 asks for. `status`: queued | sent | retrying | failed |
    dead_letter."""

    __tablename__ = "notification_deliveries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(20), nullable=False)  # email | telegram
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(500), default="")
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Settings → AI & Analysis / Reports ────────────────────────────────────


class AiSettings(Base, TimestampMixin):
    """One row per org. `api_key_enc` is Fernet/Vault-Transit ciphertext
    (app.core.crypto) — the plaintext key is never stored, logged, or
    returned by any API response; only a masked preview is ever shown."""

    __tablename__ = "ai_settings"

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    provider: Mapped[str] = mapped_column(String(40), default="anthropic")  # anthropic | ollama
    model: Mapped[str] = mapped_column(String(80), default="claude-sonnet-5")
    api_key_enc: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    # Ollama is a local/self-hosted HTTP server, not a hosted API — no key,
    # just a reachable base URL (e.g. http://localhost:11434).
    ollama_base_url: Mapped[str] = mapped_column(String(300), default="http://localhost:11434")
    # Opt-in: when true, a recon scan asks the configured AI for a short
    # bug-hunting strategy note after each phase checkpoint (new endpoints/
    # findings/tech detected so far -> what to prioritize next), stored as a
    # job event. Off by default — this is extra load on every phase of every
    # scan, so it must be a deliberate choice, not a surprise default.
    analyze_every_phase: Mapped[bool] = mapped_column(Boolean, default=False)
    last_test_status: Mapped[str] = mapped_column(
        String(20), default="not_configured"
    )  # not_configured | ok | failed
    last_test_detail: Mapped[str] = mapped_column(String(500), default="")
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportSettings(Base, TimestampMixin):
    """One row per org — branding/metadata applied to every generated
    report (PDF cover page, footers, etc). Purely cosmetic; never affects
    finding data."""

    __tablename__ = "report_settings"

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    company_name: Mapped[str] = mapped_column(String(200), default="")
    # small logo as a data: URI (no object-storage integration wired up in
    # this build) — capped and content-type-validated at the API boundary.
    logo_data_uri: Mapped[str | None] = mapped_column(String(350_000), nullable=True)
    report_title: Mapped[str] = mapped_column(String(200), default="Security Assessment Report")
    author: Mapped[str] = mapped_column(String(200), default="")
    contact_email: Mapped[str] = mapped_column(String(300), default="")
    confidentiality_label: Mapped[str] = mapped_column(String(80), default="Confidential")
    accent_color: Mapped[str] = mapped_column(String(9), default="#2563eb")  # #rrggbb[aa]
