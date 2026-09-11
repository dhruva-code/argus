# Architecture

## Services

| Service | Language | Responsibility |
|---|---|---|
| `web` | Next.js 14 / React / TS | Operator UI. Proxies `/api/*` to the gateway (same-origin, no CORS in prod). |
| `gateway` | Python 3.12 / FastAPI | REST + SSE API, auth, RBAC, tenancy, persistence, job enqueue, event consumption. Never executes security tools. |
| `orchestrator` | Go 1.23 | Consumes jobs from Redis, enforces scope + SSRF policy, runs tool plugins, streams events back. The only component that runs external binaries. |
| `postgres` | — | System of record. |
| `redis` | — | Durable job queue, event bus, control channel, worker heartbeats. |
| `minio` | — | S3-compatible object storage for raw tool output, evidence, reports (used from M2 on). |

```
Browser ──► web ──► gateway ──► postgres
                       │  ▲
              enqueue  │  │ events (persist + SSE fan-out)
                       ▼  │
                     redis (queue + pub/sub)
                       │  ▲
                 claim │  │ publish
                       ▼  │
                  orchestrator ──► tool plugins ──► subfinder / dnsx / httpx / …
                       │
                       └──► minio (artifacts)
```

## Request → job → result flow

1. `POST /api/projects/{id}/jobs` (or `/api/tools/health-check`). The gateway
   writes a `scan_jobs` row (`status=queued`), records an audit entry, and
   builds the **wire job**: the job id, type, params, the compiled **scope
   policy** for the project, and the rate limits.
2. The wire job is `SET` at `argus:job:<id>` and the id is `RPUSH`ed onto
   `argus:jobs:queued`.
3. An orchestrator worker `BLMOVE`s the id to `argus:jobs:processing`, loads the
   payload, and runs the handler for the job type under a cancellable context.
   It writes a heartbeat to `argus:job:<id>:hb` every 10s.
4. Every status change, log line, and result is `PUBLISH`ed to `argus:events`.
5. The gateway's single event-consumer task (one per process) receives each
   event, writes a `job_events` row, updates the `scan_jobs` row
   (status/counters/worker), and fans the event out to any connected SSE
   clients via the in-process `EventHub`.
6. The UI's job page reads the historical `job_events` once, then tails
   `GET /api/jobs/{id}/stream` (SSE over `fetch`, so the `Authorization` header
   can be sent) for live lines.

If a worker dies mid-job, its heartbeat expires; on its next start the
orchestrator's `RecoverStale` sweep moves the orphaned id back to the queue, and
the gateway's `recover_orphaned_jobs` fails any `scan_jobs` row still marked
`running` with no heartbeat.

## Scope engine parity

The scope decision engine exists twice:

- `orchestrator/internal/scope` (Go) — **authoritative**. Every job and every
  outbound HTTP request (from M2) is checked here.
- `apis/gateway/app/scope` (Python) — mirror. Powers the scope editor's "test a
  target" feature and pre-validates a scan's declared targets.

Both are executed against `testdata/fixtures/scope_cases.json` in CI
(`make test-scope-parity`). The fixture file is the single source of truth for
the semantics; a change to one implementation that breaks a fixture fails the
build.

Evaluation order: normalize the target → if any **deny** rule matches, deny
(return it) → if any **allow** rule matches, allow → otherwise **default deny**.

## Multi-tenancy

`organizations` is the tenant boundary. Every table below it carries `org_id`.
The `get_principal` dependency resolves the caller's membership (via the
`X-Org-Id` header, defaulting to their first org) into a `Principal`
(`user`, `org`, `role`, `permissions`). Every router query filters on
`principal.org.id`; a row from another org returns 404, not 403, so tenancy is
not probeable.

## RBAC

Six roles (`viewer` → `super_admin`) map to a fixed permission set in
`app/core/rbac.py`. Permissions are monotonic by rank (a higher role is a strict
superset). Routers declare `Depends(require_permission("scan.execute"))` or call
`principal.require(...)`. Superusers get every permission regardless of role.

## Data model (M1)

```
organizations ─┬─ memberships ── users ── refresh_tokens
               ├─ projects ─┬─ scope_rules
               │            └─ scan_jobs ── job_events
               ├─ scan_profiles          (6 built-ins seeded per org)
               ├─ tool_integrations ── tool_versions
               └─ audit_logs            (append-only)
```

M2 adds `assets`, `asset_sources`, `asset_edges` (the Asset Identity Engine).
M3 adds `vhosts`, `endpoints`. M4 adds `secrets` and `repositories` (and
`sensitivity` columns on `endpoints`). M5 adds `ports` and `findings`. Later
milestones add `technologies`, `certificates`, `finding_evidence`,
`finding_events`, `screenshots`, `reports`, `notifications`, `workflow_runs` —
see [ROADMAP.md](ROADMAP.md).

## Recon pipeline (M2)

`orchestrator/internal/recon` runs three phases for a `recon.scan` job:

1. **passive_subdomain_enum** — `subfinder` (curated sources) + `assetfinder`.
   Every host is scope-evaluated and emitted as an `asset` event. Output is
   capped at the profile's `max_targets` (in-scope hosts kept first) — a passive
   source can return tens of thousands of junk certificate names for a common
   domain.
2. **active_subdomain_enum** — `dnsx` resolution (A/AAAA/CNAME), wildcard-DNS
   detection per root, optional permutation bruteforce against in-scope roots
   only. Emits IP assets and `resolves_to` / `cname_to` edges.
3. **merge_resolve_alive** — `httpx` on hosts that are **in scope** *and* whose
   resolved IPs pass the SSRF guard. Records status, title, server, tech, TLS
   SANs; emits `alive`/`dead` status, URL assets, and `hosts` / `redirects_to`
   edges.

The gateway's event consumer routes `asset` / `asset_edge` events to
`services/assets.py` — the **Asset Identity Engine** — which upserts by
`(project, type, value)`: source attribution accumulates, list fields union,
status only moves up `unknown → dead → resolved → alive`, and confidence is
recomputed (`40 + 15·min(sources,3) + 15·resolved + 25·alive`, capped 99).
`ARGUS_SYNTHETIC_RECON=true` swaps the tool adapters for a deterministic offline
surface (used by `internal/recon` tests and offline dev).

M3 adds three more phases and three more event types:

4. **infrastructure_mapping** — Team Cymru DNS (ASN / netblock / country) + PTR +
   cloud inference for each resolved in-scope IP. Emits `asn` / `netblock`
   assets and `belongs_to` / `announced_by` edges.
5. **vhost_enum** — via `httpengine`, per in-scope IP: a random-Host baseline
   then each candidate hostname; similarity (status + size + title) drives the
   classification. Emits `vhost` events (→ `vhosts` table).
6. **url_endpoint_discovery** — `katana` + `gau` + well-known probes. Each URL is
   normalized + route-templated and deduplicated on `method + host +
   normalized_path + sorted(query_keys)`. Emits `endpoint` events (→ `endpoints`
   table), only for hosts that resolved.

`orchestrator/internal/httpengine` is the guarded client for phases 5/6 (and
later 8–12): scope + SSRF re-checked at dial time on the connection IP
(hostnames are resolved and every returned address checked, so a DNS-rebind
cannot slip a private IP through), shared token-bucket rate limiter,
response-size cap, `ScopeError` / `SSRFError` typed so callers treat "blocked"
as expected.

M4 adds three more phases and two more event types (`secret`, `repository`):

7. **js_analysis_secrets** — `*.js` URLs (katana crawl, then `gau` top-up;
   deduped by host+path, ≤200) fetched via `httpengine`, all bodies batched into
   one dir and scanned once with **TruffleHog + Gitleaks**, plus per-file custom
   high-signal detectors. Bodies are also mined for endpoints, domains, source
   maps and S3 buckets; new hosts are re-scoped. Emits `secret` + `endpoint` +
   `asset` events.
8. **directory_discovery** — `ffuf` against each alive in-scope host (≤20),
   bounded (`-t 40 -rate ≥30 -maxtime-job 180`, `-fs` at the body cap). A
   15-rule **sensitivity classifier** (`classifySensitivity`) tags each hit
   critical…none with a reason. Emits `endpoint` events carrying `sensitivity` /
   `sensitivity_reason` / `content_length`.
9. **source_code_intel** — GitHub org inferred from the root domain; repos
   enumerated (optional `GITHUB_TOKEN`, rate-limit aware), IaC files detected via
   the git-trees API, non-fork recently-pushed repos scanned with TruffleHog
   (3-min cap). Emits `repository` + `secret` events.

Phases 7–9 each run under a per-phase `context.WithTimeout` budget (8 / 10 / 10
min) so one slow target cannot stall the job.

The gateway's event consumer routes `secret` events to
`services/assets.py:upsert_secret` — deduped by `(project, fingerprint)`, source
attribution accumulates. The `value` is stored both as `value_preview` (the real
leading characters, for list views) and encrypted once in `value_enc` (Fernet,
DB/backup-leak protection). `/secrets` decrypts and returns the full value to
callers with `finding.read` — masking it would defeat validation — but the
ciphertext column itself is never serialized. `repository` events upsert by `(project, provider, full_name)`,
list fields (`iac_files`, `matched_terms`) union and are only overwritten when
re-supplied.

M5 adds two more phases and two more event types (`port`, `finding`):

10. **port_service_fingerprint** — `naabu -s c` (unprivileged connect-scan) of the
    IPs an in-scope host resolves to (SSRF-guarded, ≤25), then `nmap -sV` for
    service/version and a guarded HTTP probe of web ports. An IP is in scope for
    probing because an in-scope hostname resolves to it; only an *explicit* IP/ASN
    deny rule takes it back out. Emits `port` events → `services/findings.py:upsert_port`
    (dedup on `(project, ip, port, protocol)`, service detail only-update-if-provided).
11. **automated_vuln_scan** — `nuclei` against alive in-scope hosts, curated
    template directories per level, `dos,intrusive,fuzz,brute` always excluded.
    `level` (`passive` / `safe_verify` / `manual_review`) comes from the scan
    profile (`safe_verify` when `finding_verification` is enabled) or an explicit
    `params.vuln_level`. Emits `finding` events.

`services/findings.py:upsert_finding` is the **verification / FP-reduction engine**
(Phase 13, always on): dedup on `sha256(template_id|host|normalized_path|matcher_name)`,
`verify_finding()` scores confidence from the scanner's signals (OOB interaction,
matcher name, extracted results, CVE metadata, template reputation) and proposes
`confirmed` / `probable` / `needs_review`; a status in `{confirmed, false_positive,
fixed, accepted_risk}` is treated as a human decision and never overwritten.

Phases 10/11 run under per-phase `context.WithTimeout` budgets (12 / 25 min).

**Phase 4 — `waf_cdn_origin_intel`** (`wafcdn.go`, M6): fingerprints the CDN/WAF
in front of each alive host from response-header signatures, then probes
origin-revealing hostnames and flags any resolved IP not announced by a
CDN/cloud AS (`ipASNOrg` map filled by the infra phase) as a possible origin
exposure. Emits `finding` + `asset` events.

The gateway adds three M6 read paths on top of the M5 tables:
`services/priority.py:finding_priority` computes a 0-100 `priority_score`
(severity × confidence × status × risk-profile); `services/reports.py` renders
an on-the-fly assessment report (MD/JSON/CSV/HTML) from the current inventory;
`services/monitoring.py:exposure_delta` diffs `first_seen`/`last_seen` against
the previous recon scan's finish time. `services/scans.py:delete_scans` removes
finished scan jobs (+ `job_events`, + optionally the rows they first introduced
via `first_seen_scan`) with explicit statements rather than DB cascade, and
purges the job's Redis keys.

## Tool plugin interface

`orchestrator/internal/plugin` defines the contract every tool implements:
metadata (binary name, version args, min/tested version, capabilities, safety
class, install hint), `DetectVersion`, and `Health`. `internal/tools` ships a
generic `cliTool` covering the ProjectDiscovery suite + ffuf. Process execution
goes through `plugin.Runner` — an argv-only path that never invokes a shell —
so scan-derived parameters can never become shell metacharacters. Tests inject a
fake `Runner`.
