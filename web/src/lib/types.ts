export type Role =
  | "super_admin"
  | "org_admin"
  | "security_lead"
  | "security_analyst"
  | "researcher"
  | "viewer";

export interface OrgSummary {
  id: string;
  name: string;
  slug: string;
  role: Role | null;
}

export interface Me {
  id: string;
  email: string;
  full_name: string;
  is_superuser: boolean;
  mfa_enabled: boolean;
  email_verified: boolean;
  timezone: string;
  language: string;
  avatar_url: string | null;
  theme: "system" | "light" | "dark";
  created_at: string;
  last_login_at: string | null;
  organizations: OrgSummary[];
  active_org: string | null;
  role: Role | null;
  permissions: string[];
}

export interface SessionInfo {
  id: string;
  ip: string;
  user_agent: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string;
  current: boolean;
}

export interface NotificationPreference {
  email_enabled: boolean;
  telegram_enabled: boolean;
  events: Record<string, boolean>;
  quiet_hours_start: number | null;
  quiet_hours_end: number | null;
  quiet_hours_override_critical: boolean;
}

export interface TelegramStatus {
  linked: boolean;
  telegram_username: string;
  linked_at: string | null;
  pairing_pending: boolean;
}

export interface TelegramPairResponse {
  pairing_code: string;
  deep_link: string;
  expires_at: string;
  bot_configured: boolean;
}

export interface TestNotificationResult {
  success: boolean;
  detail: string;
}

export interface AiSettings {
  enabled: boolean;
  provider: string;
  model: string;
  api_key_masked: string;
  ollama_base_url: string;
  analyze_every_phase: boolean;
  status: "not_configured" | "ok" | "failed";
  last_test_detail: string;
  last_test_at: string | null;
}

export interface FindingAiAnalysis {
  observed_evidence: Record<string, unknown>;
  ai_analysis: {
    engine: string;
    classification: string;
    false_positive_likelihood: string;
    severity_reasoning: string;
  };
  ai_recommendation: {
    remediation: string;
  };
}

export interface AiTestResult {
  success: boolean;
  detail: string;
}

export interface ReportSettings {
  company_name: string;
  has_logo: boolean;
  report_title: string;
  author: string;
  contact_email: string;
  confidentiality_label: string;
  accent_color: string;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  program_name: string;
  client: string;
  program_url: string;
  description: string;
  rules_of_engagement: string;
  risk_profile: "low" | "moderate" | "high" | "critical";
  schedule_cron: string | null;
  notification_policy: Record<string, unknown>;
  default_profile_id: string | null;
  is_archived: boolean;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
  scope_rule_count: number;
}

export interface ProjectDeletePreview {
  project_name: string;
  counts: Record<string, number>;
}

export interface AuthProfile {
  id: string;
  name: string;
  kind: "none" | "basic" | "bearer" | "api_key" | "cookie" | "oauth_session";
  header_name: string;
  cookie_name: string;
  location: "header" | "cookie" | "query";
  created_at: string;
}

export type ScopeEffect = "allow" | "deny";
export type ScopeMatcher =
  | "domain"
  | "subdomain"
  | "wildcard"
  | "cidr"
  | "ip"
  | "asn"
  | "url"
  | "regex";

export interface ScopeRule {
  id?: string;
  position?: number;
  effect: ScopeEffect;
  matcher: ScopeMatcher;
  value: string;
  ports: number[];
  paths: string[];
  note: string;
}

export type JobStatus =
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled"
  | "partially_completed";

export interface Job {
  id: string;
  project_id: string;
  type: string;
  status: JobStatus;
  params: Record<string, unknown>;
  rate_limits: Record<string, unknown>;
  worker: string | null;
  request_count: number;
  result_count: number;
  error_count: number;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  created_at: string;
}

export interface JobEvent {
  id: string;
  type: string;
  level: string;
  message: string;
  data: Record<string, unknown>;
  at: string;
}

export interface Tool {
  id: string;
  name: string;
  display_name: string;
  enabled: boolean;
  health: "ok" | "degraded" | "missing" | "unknown";
  health_detail: string;
  installed_version: string;
  tested_version: string;
  min_version: string;
  capabilities: string[];
  safety_class: string;
  needs_api_key: boolean;
  has_api_key: boolean;
  rate_limit_rps: number;
  last_checked_at: string | null;
}

export interface ScanProfile {
  id: string;
  key: string;
  name: string;
  description: string;
  is_builtin: boolean;
  phases: Record<string, boolean>;
  rate_limits: Record<string, number>;
  requires_active_ack: boolean;
}

export interface DashboardStats {
  projects: number;
  active_jobs: number;
  jobs_last_24h: number;
  tools_ok: number;
  tools_degraded: number;
  tools_missing: number;
  scope_rules: number;
  assets: number;
  assets_alive: number;
  assets_new_24h: number;
  secrets_open: number;
  sensitive_paths: number;
  open_ports: number;
  findings_open: number;
  findings_critical: number;
  exposure_score: number;
  job_status_breakdown: Record<string, number>;
  jobs_over_time: { date: string; count: number }[];
  recent_jobs: Job[];
}

export type AssetType = "domain" | "subdomain" | "ip" | "url";
export type AssetStatus = "unknown" | "resolved" | "alive" | "dead";

// Asset.confidence / .sources / .last_seen are still returned by the API
// (other consumers — reports, a future detail view — may still want them)
// but are intentionally omitted here: the Asset Inventory table is the
// only place this type is used, and it no longer displays those columns.
// See CHANGELOG.md for why they were removed from the UI.
export interface Asset {
  id: string;
  type: AssetType;
  value: string;
  in_scope: boolean;
  scope_reason: string;
  status: AssetStatus;
  ip_addresses: string[];
  cname: string;
  asn: string;
  is_wildcard: boolean;
  http_status: number | null;
  http_title: string;
  http_server: string;
  http_scheme: string;
  http_port: number | null;
  content_type: string;
  final_url: string;
  tls_names: string[];
  technologies: string[];
  tags: string[];
  ptr: string;
  netblock: string;
  asn_org: string;
  cloud_provider: string;
  geo_country: string;
  first_seen: string;
}

export interface AssetSummary {
  total: number;
  in_scope: number;
  alive: number;
  resolved: number;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
  technologies: { name: string; count: number }[];
  edges: number;
  new_last_24h: number;
}

export interface Asset3 extends Asset {
  ptr: string;
  netblock: string;
  asn_org: string;
  cloud_provider: string;
  geo_country: string;
}

export interface VHost {
  id: string;
  ip: string;
  hostname: string;
  scheme: string;
  port: number;
  classification: "default" | "interesting" | "potential_internal" | "unusual_response";
  status_code: number | null;
  response_bytes: number;
  title: string;
  server: string;
  baseline_status: number | null;
  baseline_bytes: number;
  similarity: number;
  in_scope: boolean;
  first_seen: string;
  last_seen: string;
}

export interface Endpoint {
  id: string;
  method: string;
  host: string;
  scheme: string;
  path: string;
  normalized_url: string;
  sample_url: string;
  query_keys: string[];
  params: { name: string; kind: string; in: string }[];
  status_code: number | null;
  content_type: string;
  content_length: number | null;
  sensitivity: "none" | "low" | "medium" | "high" | "critical";
  sensitivity_reason: string;
  in_scope: boolean;
  tags: string[];
  sources: string[];
  first_seen: string;
  last_seen: string;
  wayback_first_seen: string | null;
  wayback_last_seen: string | null;
}

export interface EndpointSummary {
  total: number;
  in_scope: number;
  by_method: Record<string, number>;
  by_tag: Record<string, number>;
  by_sensitivity: Record<string, number>;
  hosts: number;
  with_params: number;
  // Count of endpoints whose *current* status_code is one of
  // 200/301/302/303/307/401 — see VALIDATED_STATUS_CODES in
  // app/routers/assets.py. Distinct from `total`, which includes dead
  // ends (403/404/5xx) and passively-discovered/unprobed endpoints.
  validated_total: number;
  wayback_total: number;
  wayback_new: number;
  wayback_parameterized: number;
  wayback_interesting: number;
}

export interface AssetGraphNode {
  id: string;
  type: string;
  value: string;
  status: string;
  in_scope: boolean;
}
export interface AssetGraphEdge {
  src: string;
  dst: string;
  kind: string;
}
export interface AssetGraph {
  nodes: AssetGraphNode[];
  edges: AssetGraphEdge[];
}

export type Severity = "none" | "low" | "medium" | "high" | "critical";
export type SecretStatus = "unverified" | "verified" | "false_positive" | "revoked";

export type SecretAiClassification = "" | "true_positive" | "likely" | "potential" | "false_positive";

export interface Secret {
  id: string;
  fingerprint: string;
  detector_type: string;
  detector: string;
  source_kind: string;
  source: string;
  location: string;
  value: string;
  value_preview: string;
  verified: boolean;
  status: SecretStatus;
  confidence: number;
  severity: Severity;
  has_encrypted_value: boolean;
  // AI triage — a parallel opinion, never a substitute for the detector
  // fields above. "" means not yet analyzed.
  ai_classification: SecretAiClassification;
  ai_reasoning: string;
  ai_engine: string;
  ai_analyzed_at: string | null;
  first_seen: string;
  last_seen: string;
}

export interface SecretSummary {
  total: number;
  unverified: number;
  verified: number;
  false_positive: number;
  suppressed_total: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_source_kind: Record<string, number>;
}

export interface Repository {
  id: string;
  provider: string;
  full_name: string;
  url: string;
  description: string;
  default_branch: string;
  is_fork: boolean;
  is_archived: boolean;
  stars: number;
  pushed_at: string | null;
  discovered_via: string;
  matched_terms: string[];
  iac_files: string[];
  in_scope: boolean;
  first_seen: string;
  last_seen: string;
}

export interface Port {
  id: string;
  ip: string;
  port: number;
  protocol: string;
  state: string;
  service: string;
  product: string;
  version: string;
  banner: string;
  tls: boolean;
  http_status: number | null;
  http_title: string;
  hostnames: string[];
  source: string;
  in_scope: boolean;
  first_seen: string;
  last_seen: string;
}

export interface PortSummary {
  total: number;
  hosts: number;
  by_service: Record<string, number>;
  by_port: Record<string, number>;
  web_ports: number;
  tls_ports: number;
}

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus =
  | "open"
  | "confirmed"
  | "probable"
  | "needs_review"
  | "false_positive"
  | "fixed"
  | "accepted_risk";

export interface Finding {
  id: string;
  fingerprint: string;
  template_id: string;
  name: string;
  severity: FindingSeverity;
  status: FindingStatus;
  confidence: number;
  engine: string;
  template_version: string;
  scan_level: string;
  tags: string[];
  host: string;
  matched_at: string;
  normalized_path: string;
  matcher_name: string;
  extracted: string[];
  request: string | null;
  response_excerpt: string | null;
  curl_command: string | null;
  reference: string[];
  cve: string[];
  cwe: string[];
  cvss_score: number | null;
  description: string;
  remediation: string;
  verification: string;
  verification_note: string;
  triage_reason: string;
  priority_score: number;
  priority_band: string;
  in_scope: boolean;
  // AI triage — a parallel opinion layered on top of `verification`/
  // `confidence` above, never a substitute for them. "" means not yet
  // analyzed.
  ai_classification: string;
  ai_false_positive_likelihood: "" | "low" | "medium" | "high";
  ai_reasoning: string;
  ai_engine: string;
  ai_analyzed_at: string | null;
  first_seen: string;
  last_seen: string;
  updated_at: string;
}

export interface ExposureDelta {
  baseline: string | null;
  has_baseline: boolean;
  current_scan: string | null;
  previous_scan: string | null;
  new: {
    assets?: { type: string; value: string; status: string }[];
    findings?: { severity: string; name: string; host: string; status: string }[];
    ports?: { ip: string; port: number; service: string }[];
    secrets?: { type: string; location: string }[];
  };
  resolved: {
    assets?: { type: string; value: string; status: string }[];
    findings?: { severity: string; name: string; host: string }[];
  };
  counts: Record<string, number>;
}

export interface FindingSummary {
  total: number;
  open: number;
  confirmed: number;
  needs_review: number;
  false_positive: number;
  suppressed_total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  oob_confirmed: number;
  template_version: string;
}

export interface AuditRow {
  id: string;
  actor_email: string;
  ip: string;
  action: string;
  object_type: string;
  object_id: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  reason: string;
  at: string;
}
