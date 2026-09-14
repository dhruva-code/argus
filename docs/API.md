# API

Base path `/api`. Interactive schema at `/api/docs` (Swagger) and `/api/redoc`;
raw OpenAPI at `/api/openapi.json`.

Auth: `Authorization: Bearer <access_token>`. Multi-org users select the active
organization with `X-Org-Id: <uuid>` (defaults to the first membership).

## Auth

| Method | Path | Notes |
|---|---|---|
| GET | `/auth/setup-required` | Is the first-run wizard still available? |
| POST | `/auth/setup` | Create first admin + org. 409 once any user exists. |
| POST | `/auth/login` | `{email, password, mfa_code?}` → token pair. |
| POST | `/auth/refresh` | Rotate. Old refresh token is invalidated. |
| POST | `/auth/logout` | Revoke a refresh token. |
| GET | `/auth/me` | Current user, orgs, active role, permissions. |
| POST | `/auth/mfa/enroll` · `/auth/mfa/verify` · `/auth/mfa/disable` | TOTP. |

## Organizations

| Method | Path | Permission |
|---|---|---|
| GET/POST | `/orgs` | any / any |
| GET/POST | `/orgs/members` | `user.manage` |
| PATCH | `/orgs/members/{user_id}?role=` | `user.manage` |

## Projects & scope

| Method | Path | Permission |
|---|---|---|
| GET/POST | `/projects` | `project.read` / `project.write` |
| GET/PATCH | `/projects/{id}` | `project.read` / `project.write` |
| POST | `/projects/{id}/archive` | `project.write` |
| GET/PUT | `/projects/{id}/scope` | `project.read` / `scope.write` |
| POST | `/projects/{id}/scope/test` | `project.read` |

`PUT /scope` replaces the whole policy and is rejected (422) if it does not
compile (bad CIDR, bad regex, unknown matcher).

## Scan profiles

| Method | Path | |
|---|---|---|
| GET | `/scan-profiles` | 6 built-ins + org clones |
| POST | `/scan-profiles/{id}/clone?name=` | `project.write` |

## Assets (M2)

| Method | Path | Permission |
|---|---|---|
| GET | `/projects/{id}/assets` | `project.read` — filters: `q`, `type`, `status`, `in_scope`, `technology`, `sort`, `order`, `limit`, `offset` |
| GET | `/projects/{id}/assets/summary` | `project.read` — counts by type/status, technology distribution, edge count |
| GET | `/projects/{id}/assets/graph` | `project.read` — nodes + edges for the relationship graph |
| GET | `/projects/{id}/assets/{asset_id}` | `project.read` — one asset with full source attribution |
| GET | `/projects/{id}/vhosts` | `project.read` — virtual hosts (filters: `classification`, `ip`) — M3 |
| GET | `/projects/{id}/endpoints` | `project.read` — endpoint inventory (filters: `q`, `method`, `tag`, `host`, `in_scope`, `sensitivity`, `source` e.g. `wayback`, `status_code`, `extension`, `has_params`) — M3/M4; ordered by sensitivity desc. Endpoints found via the Wayback Machine also carry `wayback_first_seen`/`wayback_last_seen` — see [WAYBACK.md](WAYBACK.md). |
| GET | `/projects/{id}/endpoints/summary` | `project.read` — counts by method/tag, host count, `by_sensitivity`, plus `wayback_total`/`wayback_new`/`wayback_parameterized`/`wayback_interesting` — M3/M4 |

## Secrets & source (M4)

| Method | Path | Permission |
|---|---|---|
| GET | `/projects/{id}/secrets` | `finding.read` — filters: `status`, `severity`, `source_kind`, `detector_type`, `limit`, `offset`. Returns the full `value` (masking defeats validation); it is also stored encrypted at rest and the ciphertext column is never serialized. |
| GET | `/projects/{id}/secrets/summary` | `finding.read` — counts by type / severity / source kind, verified / unverified / false-positive |
| PATCH | `/projects/{id}/secrets/{secret_id}` | `finding.modify` — `{"status":"verified\|false_positive\|revoked\|unverified","reason":"…"}`; writes a `secret.status_change` audit record |
| GET | `/projects/{id}/repositories` | `project.read` — discovered source repos (IaC files, matched terms, stars, push time) |
| GET | `/projects/{id}/findings?sort=priority\|severity` | `finding.read` — each finding carries `priority_score` (0-100) and `priority_band` from the risk engine; default sort is by priority |
| GET | `/projects/{id}/report?format=md\|json\|csv\|html\|pdf` | `report.generate` — assessment report; add `&download=true` for a download disposition. Secret *values* are never included (type/location/masked preview only); finding request/response evidence is included but redacted (API keys, tokens, cookies, Authorization headers). See [REPORTS.md](REPORTS.md) for the PDF's structure/branding. |
| GET | `/projects/{id}/exposure-delta?since=<iso8601>` | `project.read` — what appeared / went away since the previous scan (or `since`) |
| GET | `/projects/{id}/analytics?days=30` | `project.read` — FP rate, mean-time-to-triage, scan cadence, riskiest hosts, noisiest templates |
| POST | `/projects/{id}/ai-summary` | `finding.read` — read-only AI analysis across all findings (LLM when configured under Settings → AI & Analysis or `ARGUS_AI_API_KEY`, else heuristic) |
| POST | `/projects/{id}/findings/{finding_id}/ai-analysis` | `finding.read` — read-only AI analysis of one finding: `{observed_evidence, ai_analysis, ai_recommendation}`. See [AI_ANALYSIS.md](AI_ANALYSIS.md). |
| GET/PUT | `/settings/ai` | any authenticated (GET) / `settings.modify` (PUT) — AI provider (`anthropic`\|`ollama`)/model/enabled + masked key preview + `ollama_base_url` + `analyze_every_phase` (opt-in per-phase strategy notes). See [AI_ANALYSIS.md](AI_ANALYSIS.md). |
| POST | `/settings/ai/test` | `settings.modify` — test the configured AI connection (live for Ollama; billed-request-based for Anthropic) |
| GET/PUT | `/settings/reports` | any authenticated (GET) / `settings.modify` (PUT) — PDF report branding (company/logo/title/author/contact/confidentiality/accent color) |
| GET | `/system/health` | any authenticated — database/redis/orchestrator/`ai` connectivity (Ollama checked live every poll; Anthropic reports last manual test) |
| GET | `/api/metrics` | any authenticated — Prometheus exposition (request + surface metrics) |
| POST | `/projects/{id}/scans/delete` | `scan.cancel` (+ `project.write` if `purge_data`) — `{"job_ids":[…],"purge_data":false,"reason":"…"}`; finished scans only, running/queued are `skipped`. Audited (`scan.delete`). |
| DELETE | `/jobs/{job_id}?purge_data=false` | `scan.cancel` (+ `project.write` if `purge_data`) — delete one finished scan |

Secret values are shown to authorized operators for validation and are also
Fernet-encrypted at rest (`value_enc` — never serialized). Access is gated by
`finding.read` and every triage action is audited.

## Ports & findings (M5)

| Method | Path | Permission |
|---|---|---|
| GET | `/projects/{id}/ports` | `project.read` — filters: `ip`, `service` |
| GET | `/projects/{id}/ports/summary` | `project.read` — counts by service / port, web + TLS ports |
| GET | `/projects/{id}/findings` | `finding.read` — filters: `status`, `severity`, `template_id`, `host`, `min_confidence`; ordered by severity then confidence |
| GET | `/projects/{id}/findings/summary` | `finding.read` — counts by severity / status, OOB-confirmed count, nuclei-templates version |
| PATCH | `/projects/{id}/findings/{finding_id}` | `finding.modify` — `{"status":"confirmed\|probable\|needs_review\|false_positive\|fixed\|accepted_risk\|open","reason":"…"}`; writes a `finding.status_change` audit record and is never re-classified by a later scan |

A finding carries its evidence (matched URL, request, response excerpt, curl
command, CVE/CWE, CVSS, remediation, references) plus the verification engine's
`confidence`, `verification` (`oob_confirmed` / `unverified`) and
`verification_note`.

## Jobs

| Method | Path | Permission |
|---|---|---|
| POST | `/projects/{id}/jobs` | `scan.execute` |

`recon.scan` job body: `{"type":"recon.scan","authorization_ack":true,"params":{"profile_key":"standard_bug_bounty","bruteforce":true}}`.
The gateway extracts root domains from the project's allow rules and the phase
list from the profile; 409 if the scope has no domain/subdomain/wildcard rule or
the profile enables no recon phase.

| GET | `/projects/{id}/jobs` · `/jobs` · `/jobs/{id}` | `project.read` |
| GET | `/jobs/{id}/events` | `project.read` — historical log |
| GET | `/jobs/{id}/stream` | `project.read` — SSE live tail |
| POST | `/jobs/{id}/cancel` | `scan.cancel` |
| POST | `/jobs/emergency-stop` · `/jobs/emergency-stop/clear` | `scan.cancel` |

Job types: `scope.selftest`, `tool.health` (M1, non-networked); `recon.scan`
(M2–M7, active — requires `authorization_ack`). `recon.scan` phases:
`passive_subdomain_enum`, `active_subdomain_enum`, `merge_resolve_alive` (M2),
`infrastructure_mapping`, `waf_cdn_origin_intel`, `vhost_enum`,
`url_endpoint_discovery` (M3/M6), `js_analysis_secrets`, `directory_discovery`,
`source_code_intel` (M4), `port_service_fingerprint`, `automated_vuln_scan` (M5).
Pass an explicit `params.phases` list to run a subset; prerequisite phases are
prepended automatically. `params.vuln_level` — `passive` / `safe_verify` /
`manual_review` / `aggressive`; `aggressive` adds active injection fuzzing
(Nuclei DAST) and additionally requires `params.injection_ack = true`.

## Tools

| Method | Path | Permission |
|---|---|---|
| GET | `/tools` · `/tools/{name}` | `project.read` |
| PATCH | `/tools/{name}` | `tool.configure` — `{enabled?, api_key?, rate_limit_rps?, config?}` |
| POST | `/tools/health-check` | `tool.configure` — queues a `tool.health` job |

## Dashboard / audit / system

| Method | Path | Permission |
|---|---|---|
| GET | `/dashboard` | `project.read` |
| GET | `/audit-logs` | `audit.read` |
| GET | `/system/health` | any authenticated |

## Errors

JSON `{"detail": "..."}` or FastAPI validation array. Status codes: 400 bad
input, 401 unauthenticated, 403 missing permission, 404 not found / wrong tenant,
409 conflict, 422 unprocessable (e.g. scope policy won't compile).
