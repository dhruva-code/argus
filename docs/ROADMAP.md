# Roadmap

Argus is built in milestones; each milestone leaves a working application.

## M1 — Platform spine ✅ (this release)

Auth + RBAC, org/project tenancy, the scope engine (Go authoritative + Python
mirror, fixture-tested), durable job system with pause/resume/cancel/stop-all,
the Go orchestrator with SSRF guard and the tool plugin framework, the Tool
Manager, the executive dashboard, the Next.js UI (setup wizard, dashboard,
projects, scope editor, job viewer with live logs, tools, audit, settings), the
`argus` CLI, Docker Compose, migrations, seed data, OpenAPI.

Non-networked job types only: `scope.selftest`, `tool.health`.

## M2 — Passive & active discovery ✅ (delivered)

Phases 1, 2, 5. Passive subdomain enumeration (Subfinder + assetfinder), active
enumeration + permutation bruteforce + wildcard detection (DNSX), and the
merge / resolve / alive-host engine (HTTPX). The normalized **Asset Identity
Engine** — one Asset per `(project, type, value)`, accumulating source
attribution, merging partial field updates, status only ever upgrading,
evidence-based confidence scoring. New tables `assets` / `asset_sources` /
`asset_edges`. New `recon.scan` job type driven by a scan profile's phase
toggles, with an authorization-acknowledgement gate. Only in-scope hosts (scope
engine) whose resolved IPs pass the SSRF guard are actively probed;
`ARGUS_SYNTHETIC_RECON=true` gives a deterministic offline surface for CI. The
UI's project **Assets** tab (filterable inventory, technology distribution,
summary) and the asset relationship graph endpoint.

Still open for M2.5 / M3: the packet-level egress proxy (every request re-checked
against scope at the socket), rate-limit auto-backoff on 429/403, batched asset
ingestion for very large surfaces, Amass + CT/passive-DNS providers, `-all`
source expansion as an opt-in.

## M3 — Infrastructure, vhosts, endpoints ✅ (delivered)

Phases 3, 6, 7.

- **Infrastructure mapping** — every resolved in-scope IP is enriched via Team
  Cymru's DNS service (ASN, netblock, country — no API key), its PTR record, and
  a cloud-provider inference from the ASN organization. `asn` and `netblock`
  become assets; `belongs_to` / `announced_by` edges build the
  domain → subdomain → IP → netblock → ASN chain.
- **Virtual-host enumeration** — for each in-scope IP, every candidate hostname
  that points at it is sent as a `Host:` header and the response compared
  (status + body-size + title similarity) against a random-Host baseline;
  results are classified default / interesting / potential-internal /
  unusual-response.
- **URL & endpoint discovery** — `katana` (crawl) + `gau` (historical URLs) +
  well-known probes (robots / sitemap / OpenAPI / GraphQL). Every URL is
  normalized and **route-templated** (`/users/123` → `/users/{id}`,
  `/v1/<uuid>` → `/v1/{uuid}`), then deduplicated on the structural signature
  `method + host + normalized_path + sorted(query_keys)`. Endpoints are only
  kept for hosts that actually resolved (passive enum returns junk CT names).

New: the **guarded HTTP engine** (`orchestrator/internal/httpengine`) — every
request re-checks scope and SSRF at dial time on the real connection IP, with a
shared rate limiter and response-size cap. New tables `vhosts`, `endpoints`;
`assets` gains `ptr` / `netblock` / `asn_org` / `cloud_provider` / `geo_country`.
UI: project **Infrastructure** and **Endpoints** tabs.

Still open: batched asset/endpoint ingestion for very large surfaces, an
actively-maintained cloud-range dataset (vs ASN-name inference), the interactive
graph visualization (data is served; rendering is M7).

## M4 — JS analysis, content & source intel ✅ (delivered)

Phases 8, 9, 10.

- **JavaScript analysis & secret extraction** (`js_analysis_secrets`) — every
  discovered `*.js` URL (katana crawl first, `gau` history only as top-up;
  deduped by host+path, capped at 200) is fetched through the guarded HTTP
  engine and scanned for secrets with **TruffleHog + Gitleaks** (one batched
  pass over the whole set) plus a set of custom high-signal detectors. The same
  bodies are mined for referenced endpoints, external/internal domains, source
  maps and S3 buckets; newly seen hosts are re-evaluated against scope.
- **Directory & sensitive-file discovery** (`directory_discovery`) — each alive
  in-scope host (max 20) is fuzzed with `ffuf` (`common.txt`, bounded:
  `-t 40 -rate ≥30 -maxtime-job 180`, response-size capped). A 15-rule
  **sensitivity classifier** tags every hit critical / high / medium / low /
  none with a human reason (`/.git`, `/.env`, backups, actuator, admin panels…).
- **Source-code intelligence** (`source_code_intel`) — a GitHub org is inferred
  from the root domain, its repos enumerated (optional `GITHUB_TOKEN`), IaC
  files detected via the git-trees API, and non-fork recently-pushed repos run
  through TruffleHog. Repos are correlated back to the project as assets.

**Secret handling**: the full value is returned to operators holding
`finding.read` — masking defeats validation, which is the whole point of the
finding. It is *also* Fernet-encrypted at rest (`value_enc`) so a DB or backup
leak does not expose it, and the ciphertext column is never serialized. Every
status change (`PATCH /secrets/{id}`: unverified → verified / false_positive /
revoked) writes an audit record. Dedup key is `sha256(type|location|last4)`.

New tables `secrets`, `repositories`; `endpoints` gains `content_length` /
`sensitivity` / `sensitivity_reason`. New API: `/secrets`, `/secrets/summary`,
`PATCH /secrets/{id}`, `/repositories`; dashboard gains `secrets_open` /
`sensitive_paths`. UI: project **Secrets & Source** tab, sensitivity badges on
the Endpoints tab, dashboard cards. New tools registered: `trufflehog`,
`gitleaks`.

Still open: GitLab/Bitbucket providers (only GitHub wired), AST-level JS parsing
(currently regex + scanner-based), TruffleHog **verified**-credential mode behind
an explicit opt-in, an actively-maintained wordlist manager in the UI.

## M5 — Ports & vulnerability scanning ✅ (delivered)

Phases 11, 12, 13.

- **Port scan & service fingerprinting** (`port_service_fingerprint`) — a bounded
  **Naabu** connect-scan (`-s c`, no CAP_NET_RAW) of every IP an in-scope
  hostname resolves to that also passes the SSRF guard (≤25 IPs, `top-100` by
  default). Open ports get a coarse service name, an **nmap `-sV`** service /
  version pass, and a guarded HTTP probe of web ports (title / server, via an
  in-scope Host header). Emits `port` events → `ports` table.
- **Automated vulnerability scan** (`automated_vuln_scan`) — a bounded **Nuclei**
  run (≤15 targets, curated template dirs, `-c 50`, phase-budgeted at 25 min).
  The genuinely unsafe template classes — `dos`, `intrusive`, `fuzz`, `brute` —
  are **always excluded**. The **three-level model** widens coverage:
  `passive` (exposure / misconfig / tech / takeover, no OOB), `safe_verify`
  (+ CVEs / default-logins / generic vulns, interactsh OOB on), `manual_review`
  (same coverage; findings held for an analyst). nuclei-templates version is
  recorded on every finding.
- **False-positive reduction & verification engine** (`finding_verification`,
  runs in the gateway on every ingest) — each match is deduplicated on
  `sha256(template_id | host | normalized_path | matcher_name)` and scored:
  out-of-band interaction (+30, `verification = oob_confirmed`), named matcher,
  extracted values, CVE metadata raise confidence; a list of low-signal
  templates (`http-missing-security-headers`, `tech-detect`, TLS/DNS
  fingerprints…) is pinned to ≤35 and never auto-promotes past `probable`.
  Auto-status: `confirmed` (OOB or ≥85) / `probable` (≥60) / `needs_review`.
  A human triage decision (`confirmed` / `false_positive` / `fixed` /
  `accepted_risk`) is **never** overwritten by a later scan.

New tables `ports`, `findings`; new API `/ports`, `/ports/summary`, `/findings`,
`/findings/summary`, `PATCH /findings/{id}` (audited). New tool: `nmap`. UI:
project **Findings** tab (severity/status filters, expandable evidence: matched
URL, CVE/CWE, curl command, response excerpt, remediation) and an **open
ports** table on the Infrastructure tab; dashboard gains open-ports and
open-findings cards.

### Active injection testing (`vuln_level: aggressive`)

An explicitly-acknowledged fourth level adds **Nuclei DAST** — template-controlled
active fuzzing of in-scope endpoint parameters for SQLi, command injection, CRLF,
CSTI, LFI/RFI, open redirect, SSRF and SSTI. It requires
`params.injection_ack = true` (a `ReconPlanError` otherwise), runs at low
concurrency / rate with `-fuzz-scope` pinned to the allow-list, is
phase-budgeted, and only feeds URLs that already carry a query string. A DAST
match is a real payload confirmed against a real response signature, so the
verification engine scores it `payload_confirmed` and it lands `confirmed`.
`dos` templates stay excluded even here.

Still open: per-endpoint POST-body fuzzing, a template allow/deny manager in the
UI.

## M6 — Findings, reporting, monitoring ✅ (delivered)

- **Phase 4 — `waf_cdn_origin_intel`** (completes the 12-phase active pipeline) —
  fingerprints the WAF/CDN in front of each alive host from ~20 response-header
  signatures (Cloudflare / Akamai / CloudFront / Fastly / Imperva / Sucuri / …),
  then probes a set of origin-revealing hostnames and flags any resolved IP that
  is *not* announced by a CDN/cloud AS as a possible **origin-IP exposure**
  (medium). Emits `finding` + tagged `asset` events.
- **Priority / risk engine** (`services/priority.py`) — every finding gets a
  0-100 `priority_score` blending severity weight × verification confidence ×
  triage-status multiplier × the project's risk profile (a real CVSS ≥ 9 nudges
  it up). Bands: urgent / high / moderate / low. `/findings?sort=priority` (the
  default) ranks by it.
- **Unified finding engine** (`services/findings.py:derive_from_*`) — secrets,
  high/critical sensitive paths, and dangerously-exposed services (redis,
  mongodb, docker, elasticsearch…) are promoted into the `findings` table with a
  synthetic `template_id` and run through the same verification + priority
  engine, so one queue / one report / one delta covers everything.
- **Assessment reports** (`services/reports.py`, `GET /projects/{id}/report`) —
  the current attack surface + priority-ranked findings + secret candidates +
  exposed services in **Markdown / JSON / CSV / HTML / PDF** (fpdf2). Secret
  *values* are never included. DOCX is the remaining format.
- **Exposure-delta / monitoring** (`services/monitoring.py`,
  `GET /projects/{id}/exposure-delta`) — the current surface vs the previous
  recon scan's finish time (or an explicit `since`); what appeared / went away.
- **Notifications** (`services/notify.py`) — on a scan finishing, a Slack webhook
  / generic webhook / SMTP email is sent per `project.notification_policy`
  (`events`, `min_severity` filters). Best-effort, never raises.
- **Scheduled continuous monitoring** (`services/scheduler.py`) — one in-process
  loop enqueues a `recon.scan` per project `schedule_cron` (croniter), skips
  projects with an active scan, and marks the job `scheduled`. `ARGUS_SCHEDULER=off`
  on replicas that must not run it.
- **Data-retention enforcement** — the same loop hourly deletes `job_events` /
  `scan_jobs` older than the org's `retention_raw_days` and `audit_logs` older
  than `retention_audit_days`.
- **Priority / risk engine** — 0-100 `priority_score` per finding.
- **Delete scans** (`POST /projects/{id}/scans/delete`, `DELETE /jobs/{id}`) —
  select & remove finished scans + event logs; `purge_data` also drops the rows
  each scan first introduced. Audited. UI: checkbox bulk-delete.

Still open for M6: DOCX reports, the evidence / PoC package generator with
automatic redaction, Discord/Teams notification formatters.

## M7 — Enterprise & intelligence ✅ (partially delivered — RBAC refinements deferred)

- **Attack-surface graph** — `/assets/graph` data rendered as a column layout
  following the domain → subdomain → IP → netblock → ASN resolution chain, with
  hover-isolation and out-of-scope marking (project **Graph** tab).
- **Advanced analytics** (`GET /projects/{id}/analytics`) — false-positive rate,
  mean time-to-triage, scan cadence & duration, riskiest hosts, noisiest
  templates, verification mix (project **Analytics** tab).
- **AI-assisted analysis** (`services/ai.py`, `POST /projects/{id}/ai-summary`) —
  **read-only**: executive summary, related-finding clusters, remediation order.
  Uses the Anthropic API when `ARGUS_AI_API_KEY` is set, otherwise a
  deterministic heuristic. Never triggers scans or changes scope.
- **Prometheus + OpenTelemetry** — `GET /api/metrics` (request counters/latency
  histogram + surface gauges); FastAPI auto-instrumentation when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
- **HashiCorp Vault secret backend** — `app/core/crypto.py` uses Vault Transit
  when `VAULT_ADDR` + `VAULT_TRANSIT_KEY` are set (ciphertext prefixed `vault:`
  so local rows still decrypt); Fernet otherwise.
- **Kubernetes Helm chart** — `deploy/helm/argus` (gateway / orchestrator / web,
  optional bundled postgres / redis / minio, ingress, ServiceMonitor).

Still open for M7: interactive graph zoom/pan/expand, Grafana dashboards, the
AI provider abstraction for non-Anthropic models, **enterprise RBAC refinements
(deferred by request)**.
