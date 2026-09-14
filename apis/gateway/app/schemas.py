"""Pydantic request/response models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.types import Email
from app.models import (
    JobStatus,
    RiskProfile,
    Role,
    ScopeEffect,
    ScopeMatcher,
    ToolHealth,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ── Auth ───────────────────────────────────────────────────────────────────


class SetupRequest(BaseModel):
    org_name: str = Field(min_length=2, max_length=200)
    admin_email: Email
    admin_password: str = Field(min_length=12, max_length=200)
    admin_name: str = Field(default="", max_length=200)


class LoginRequest(BaseModel):
    email: Email
    password: str
    mfa_code: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_at: datetime


class RefreshRequest(BaseModel):
    refresh_token: str


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaVerifyRequest(BaseModel):
    code: str


class OrgSummary(ORMModel):
    id: uuid.UUID
    name: str
    slug: str
    role: Role | None = None


class MeResponse(ORMModel):
    id: uuid.UUID
    email: Email
    full_name: str
    is_superuser: bool
    mfa_enabled: bool
    email_verified: bool = True
    timezone: str = "UTC"
    language: str = "en"
    avatar_url: str | None = None
    theme: str = "system"
    created_at: datetime
    last_login_at: datetime | None = None
    organizations: list[OrgSummary]
    active_org: uuid.UUID | None = None
    role: Role | None = None
    permissions: list[str] = []


# ── Registration / verification / password reset (§5-7) ────────────────────


class RegisterRequest(BaseModel):
    email: Email
    password: str = Field(min_length=12, max_length=200)
    full_name: str = Field(default="", max_length=200)
    org_name: str = Field(default="", max_length=200)


class RegisterResponse(BaseModel):
    message: str
    email: Email


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: Email


class RequestPasswordResetRequest(BaseModel):
    email: Email


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12, max_length=200)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=200)


class ChangeEmailRequest(BaseModel):
    new_email: Email
    current_password: str


class UpdateProfileRequest(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    timezone: str | None = Field(default=None, max_length=64)
    language: str | None = Field(default=None, max_length=16)
    theme: str | None = Field(default=None, pattern=r"^(system|light|dark)$")


class DeleteAccountRequest(BaseModel):
    password: str
    confirm: str  # must equal the user's own email, typed back


class SessionOut(ORMModel):
    id: uuid.UUID
    ip: str
    user_agent: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    current: bool = False


# ── Notifications / Telegram (§9-15, §20-22) ────────────────────────────────


class NotificationPreferenceOut(ORMModel):
    email_enabled: bool
    telegram_enabled: bool
    events: dict[str, bool]
    quiet_hours_start: int | None
    quiet_hours_end: int | None
    quiet_hours_override_critical: bool


class NotificationPreferenceUpdate(BaseModel):
    email_enabled: bool | None = None
    telegram_enabled: bool | None = None
    events: dict[str, bool] | None = None
    quiet_hours_start: int | None = Field(default=None, ge=0, le=23)
    quiet_hours_end: int | None = Field(default=None, ge=0, le=23)
    quiet_hours_override_critical: bool | None = None


class TelegramPairResponse(BaseModel):
    pairing_code: str
    deep_link: str
    expires_at: datetime
    bot_configured: bool


class TelegramStatusOut(BaseModel):
    linked: bool
    telegram_username: str = ""
    linked_at: datetime | None = None
    pairing_pending: bool = False


class TestNotificationResult(BaseModel):
    success: bool
    detail: str


# ── Settings → AI & Analysis ─────────────────────────────────────────────


class AiSettingsOut(BaseModel):
    enabled: bool
    provider: str
    model: str
    # Never the real key — "" when unset, else a masked preview like "sk-a****".
    api_key_masked: str
    ollama_base_url: str
    analyze_every_phase: bool
    status: str  # not_configured | ok | failed
    last_test_detail: str
    last_test_at: datetime | None = None


class AiSettingsUpdate(BaseModel):
    enabled: bool | None = None
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=80)
    # Provide to set/replace; omit to leave the stored key untouched; pass ""
    # to clear it. Never echoed back by any endpoint. Meaningless for
    # provider="ollama" (a local server has no key).
    api_key: str | None = Field(default=None, max_length=500)
    ollama_base_url: str | None = Field(default=None, max_length=300)
    analyze_every_phase: bool | None = None


class AiTestResult(BaseModel):
    success: bool
    detail: str


# ── Settings → Reports ───────────────────────────────────────────────────


class ReportSettingsOut(BaseModel):
    company_name: str
    has_logo: bool
    report_title: str
    author: str
    contact_email: str
    confidentiality_label: str
    accent_color: str


class ReportSettingsUpdate(BaseModel):
    company_name: str | None = Field(default=None, max_length=200)
    report_title: str | None = Field(default=None, max_length=200)
    author: str | None = Field(default=None, max_length=200)
    contact_email: str | None = Field(default=None, max_length=300)
    confidentiality_label: str | None = Field(default=None, max_length=80)
    accent_color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")
    # data: URI (image/png|jpeg|svg+xml;base64,...); pass "" to remove. Field
    # cap is intentionally above the router's actual _MAX_LOGO_BYTES (300KB)
    # so an over-the-business-limit-but-not-absurd upload gets the router's
    # friendly 400 ("logo too large") instead of a generic Pydantic 422.
    logo_data_uri: str | None = Field(default=None, max_length=350_000)


# ── Scope ──────────────────────────────────────────────────────────────────


class ScopeRuleIn(BaseModel):
    effect: ScopeEffect
    matcher: ScopeMatcher
    value: str = Field(min_length=1, max_length=500)
    ports: list[int] = []
    paths: list[str] = []
    note: str = Field(default="", max_length=300)


class ScopeRuleOut(ScopeRuleIn):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    position: int


class ScopePolicyIn(BaseModel):
    rules: list[ScopeRuleIn]


class ScopeTestRequest(BaseModel):
    host: str = ""
    ip: str = ""
    port: int = 0
    path: str = ""
    asn: str = ""


class ScopeTestResult(BaseModel):
    allowed: bool
    rule_id: str
    reason: str


# ── Projects ───────────────────────────────────────────────────────────────


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    program_name: str = ""
    client: str = ""
    program_url: str = ""
    description: str = ""
    rules_of_engagement: str = ""
    risk_profile: RiskProfile = RiskProfile.moderate
    schedule_cron: str | None = None
    notification_policy: dict[str, Any] = {}


class ProjectOut(ORMModel):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    program_name: str
    client: str
    program_url: str
    description: str
    rules_of_engagement: str
    risk_profile: RiskProfile
    schedule_cron: str | None
    notification_policy: dict[str, Any]
    default_profile_id: uuid.UUID | None
    is_archived: bool
    deleted_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    scope_rule_count: int = 0


class ProjectDeletePreview(BaseModel):
    project_name: str
    counts: dict[str, int]


class ProjectDeleteRequest(BaseModel):
    confirm_name: str = Field(min_length=1, max_length=200)


class ProjectDeleteResult(BaseModel):
    deleted: bool
    permanent: bool
    counts: dict[str, int] = {}


# ── Scan profiles ──────────────────────────────────────────────────────────


class ScanProfileOut(ORMModel):
    id: uuid.UUID
    key: str
    name: str
    description: str
    is_builtin: bool
    phases: dict[str, Any]
    rate_limits: dict[str, Any]
    requires_active_ack: bool


# ── Jobs ───────────────────────────────────────────────────────────────────


class JobCreate(BaseModel):
    type: str = Field(pattern=r"^(tool\.health|scope\.selftest|recon\.scan)$")
    params: dict[str, Any] = {}
    # For any active job type the client must acknowledge authorization.
    authorization_ack: bool = False


class JobOut(ORMModel):
    id: uuid.UUID
    project_id: uuid.UUID
    type: str
    status: JobStatus
    params: dict[str, Any]
    rate_limits: dict[str, Any]
    worker: str | None
    request_count: int
    result_count: int
    error_count: int
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime


class ScanDeleteRequest(BaseModel):
    job_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    purge_data: bool = False
    reason: str = ""


class ScanDeleteResult(BaseModel):
    deleted: int
    purged: dict[str, int] = {}
    skipped: list[str] = []


class JobEventOut(ORMModel):
    id: uuid.UUID
    type: str
    level: str
    message: str
    data: dict[str, Any]
    at: datetime


# ── Tools ──────────────────────────────────────────────────────────────────


class ToolOut(ORMModel):
    id: uuid.UUID
    name: str
    display_name: str
    enabled: bool
    health: ToolHealth
    health_detail: str
    installed_version: str
    tested_version: str
    min_version: str
    capabilities: list[str]
    safety_class: str
    needs_api_key: bool
    has_api_key: bool = False
    rate_limit_rps: int
    last_checked_at: datetime | None


class ToolConfigIn(BaseModel):
    enabled: bool | None = None
    api_key: str | None = None
    rate_limit_rps: int | None = Field(default=None, ge=1, le=1000)
    config: dict[str, Any] | None = None


# ── Assets (M2) ────────────────────────────────────────────────────────────


class AssetSourceOut(ORMModel):
    source: str
    detail: str
    first_seen: datetime
    last_seen: datetime


class AssetOut(ORMModel):
    id: uuid.UUID
    type: str
    value: str
    in_scope: bool
    scope_reason: str
    status: str
    confidence: int
    ip_addresses: list[str]
    cname: str
    asn: str
    is_wildcard: bool
    ptr: str
    netblock: str
    asn_org: str
    cloud_provider: str
    geo_country: str
    http_status: int | None
    http_title: str
    http_server: str
    http_scheme: str
    http_port: int | None
    content_type: str
    final_url: str
    tls_names: list[str]
    technologies: list[str]
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    sources: list[AssetSourceOut] = []


class AssetSummary(BaseModel):
    total: int
    in_scope: int
    alive: int
    resolved: int
    by_type: dict[str, int]
    by_status: dict[str, int]
    technologies: list[dict[str, Any]]
    edges: int
    new_last_24h: int


class AssetGraphNode(BaseModel):
    id: str
    type: str
    value: str
    status: str
    in_scope: bool


class AssetGraphEdge(BaseModel):
    src: str
    dst: str
    kind: str


class AssetGraph(BaseModel):
    nodes: list[AssetGraphNode]
    edges: list[AssetGraphEdge]


class VHostOut(ORMModel):
    id: uuid.UUID
    ip: str
    hostname: str
    scheme: str
    port: int
    classification: str
    status_code: int | None
    response_bytes: int
    title: str
    server: str
    baseline_status: int | None
    baseline_bytes: int
    similarity: float
    in_scope: bool
    first_seen: datetime
    last_seen: datetime


class EndpointOut(ORMModel):
    id: uuid.UUID
    method: str
    host: str
    scheme: str
    path: str
    normalized_url: str
    sample_url: str
    query_keys: list[str]
    params: list[dict[str, Any]]
    status_code: int | None
    content_type: str
    content_length: int | None
    sensitivity: str
    sensitivity_reason: str
    in_scope: bool
    tags: list[str]
    sources: list[str]
    first_seen: datetime
    last_seen: datetime
    wayback_first_seen: datetime | None = None
    wayback_last_seen: datetime | None = None


class EndpointSummary(BaseModel):
    total: int
    in_scope: int
    by_method: dict[str, int]
    by_tag: dict[str, int]
    hosts: int
    with_params: int
    by_sensitivity: dict[str, int] = {}
    wayback_total: int = 0
    wayback_new: int = 0
    wayback_parameterized: int = 0
    wayback_interesting: int = 0


class SecretOut(ORMModel):
    id: uuid.UUID
    fingerprint: str
    detector_type: str
    detector: str
    source_kind: str
    source: str
    location: str
    value: str = ""
    value_preview: str = ""
    verified: bool
    status: str
    confidence: int
    severity: str
    has_encrypted_value: bool = False
    first_seen: datetime
    last_seen: datetime


class SecretPatch(BaseModel):
    status: str = Field(pattern=r"^(unverified|verified|false_positive|revoked)$")
    reason: str = ""


class SecretSummary(BaseModel):
    total: int
    unverified: int
    verified: int
    false_positive: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_source_kind: dict[str, int]


class RepositoryOut(ORMModel):
    id: uuid.UUID
    provider: str
    full_name: str
    url: str
    description: str
    default_branch: str
    is_fork: bool
    is_archived: bool
    stars: int
    pushed_at: datetime | None
    discovered_via: str
    matched_terms: list[str]
    iac_files: list[str]
    in_scope: bool
    first_seen: datetime
    last_seen: datetime


# ── Ports & findings (M5) ─────────────────────────────────────────────────


class PortOut(ORMModel):
    id: uuid.UUID
    ip: str
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    banner: str
    tls: bool
    http_status: int | None
    http_title: str
    hostnames: list[str]
    source: str
    in_scope: bool
    first_seen: datetime
    last_seen: datetime


class PortSummary(BaseModel):
    total: int
    hosts: int
    by_service: dict[str, int]
    by_port: dict[str, int]
    web_ports: int
    tls_ports: int


class FindingOut(ORMModel):
    id: uuid.UUID
    fingerprint: str
    template_id: str
    name: str
    severity: str
    status: str
    confidence: int
    engine: str
    template_version: str
    scan_level: str
    tags: list[str]
    host: str
    matched_at: str
    normalized_path: str
    matcher_name: str
    extracted: list[str]
    request: str | None
    response_excerpt: str | None
    curl_command: str | None
    reference: list[str]
    cve: list[str]
    cwe: list[str]
    cvss_score: float | None
    description: str
    remediation: str
    verification: str
    verification_note: str
    triage_reason: str
    priority_score: int = 0
    priority_band: str = "low"
    in_scope: bool
    first_seen: datetime
    last_seen: datetime
    updated_at: datetime


class FindingPatch(BaseModel):
    status: str = Field(
        pattern=r"^(open|confirmed|probable|needs_review|false_positive|fixed|accepted_risk)$"
    )
    reason: str = ""


class FindingSummary(BaseModel):
    total: int
    open: int
    confirmed: int
    needs_review: int
    false_positive: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    oob_confirmed: int
    template_version: str = ""


# ── Dashboard ──────────────────────────────────────────────────────────────


class DashboardStats(BaseModel):
    projects: int
    active_jobs: int
    jobs_last_24h: int
    tools_ok: int
    tools_degraded: int
    tools_missing: int
    scope_rules: int
    assets: int
    assets_alive: int
    assets_new_24h: int
    secrets_open: int = 0
    sensitive_paths: int = 0
    open_ports: int = 0
    findings_open: int = 0
    findings_critical: int = 0
    exposure_score: int
    job_status_breakdown: dict[str, int]
    jobs_over_time: list[dict[str, Any]]
    recent_jobs: list[JobOut]


# ── Audit ──────────────────────────────────────────────────────────────────


class AuditOut(ORMModel):
    id: uuid.UUID
    actor_email: str
    ip: str
    action: str
    object_type: str
    object_id: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    reason: str
    at: datetime


# ── Injection Testing Engine (§1-17) ────────────────────────────────────────


class InjectionPointOut(ORMModel):
    id: uuid.UUID
    method: str
    url: str
    host: str
    param_name: str
    location: str
    param_type: str
    context: str
    technology: str
    auth_state: str
    candidate_classes: list[str]
    tested_classes: list[str]
    best_result: str
    confidence: int
    last_tested: datetime | None
    first_seen: datetime
    last_seen: datetime


class InjectionOverviewOut(BaseModel):
    total_points: int
    tested_points: int
    untested_points: int
    coverage_pct: float
    by_result: dict[str, int]
    by_class: dict[str, dict[str, Any]]


class AuthProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(pattern=r"^(none|basic|bearer|api_key|cookie|oauth_session)$")
    header_name: str = ""
    cookie_name: str = ""
    location: str = Field(default="header", pattern=r"^(header|cookie|query)$")
    value: str = Field(min_length=1, max_length=8000)


class AuthProfileOut(ORMModel):
    """Never carries the secret — `value_enc` is intentionally excluded."""

    id: uuid.UUID
    name: str
    kind: str
    header_name: str
    cookie_name: str
    location: str
    created_at: datetime
    at: datetime
