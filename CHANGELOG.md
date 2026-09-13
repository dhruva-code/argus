# Changelog

## Unreleased — Wayback URLs, AI analysis, professional PDF reports

### Added

- **Wayback URL discovery.** A new data source alongside `gau`/`katana` in
  the existing `url_endpoint_discovery` phase (`orchestrator/internal/recon/endpoints.go`):
  queries the Internet Archive's public CDX API (`web.archive.org/cdx/search/cdx`)
  for historical URLs under each in-scope root, normalizes and deduplicates
  them through the same pipeline as every other source (a URL another
  source already found is never reprocessed), records a Wayback capture
  timestamp range (`wayback_first_seen`/`wayback_last_seen` on
  `endpoints`, migration `0010_wayback_urls`), and is scope-filtered before
  ever being fed to endpoint intelligence, parameter discovery, JS
  analysis, directory discovery, or injection-point discovery — exactly
  like every other endpoint source. A CDX API failure is reported as a
  clear `WARNING` in the job log, never a silent zero. New **Recon →
  Wayback URLs** project tab (stats: total/new/parameterized/interesting;
  filters: URL text, domain, extension, status code, parameterized-only,
  interesting/sensitive-only).
- **AI & Analysis settings** (`Settings → AI & Analysis`): a per-org
  enable toggle, provider/model configuration, and an API key stored
  encrypted at rest (reusing the existing Vault-Transit-or-local-Fernet
  `app.core.crypto` backend — never plaintext, never returned by any API
  response, only a masked preview shown in the UI) with a safe
  test-connection check surfacing Configured / Not Configured / Connection
  Failed. The platform works identically with AI disabled — analysis falls
  back to a deterministic heuristic.
- **AI-assisted per-finding analysis** (`POST
  /api/projects/{id}/findings/{id}/ai-analysis`, surfaced in the Findings
  panel): classification, false-positive likelihood, severity reasoning,
  and remediation guidance for one finding at a time, returned as three
  explicitly separate keys — `observed_evidence` (the finding's own
  scanner data, verbatim), `ai_analysis`, `ai_recommendation` — so AI
  output can never overwrite or be confused with the original evidence.
  Secrets/tokens/cookies/Authorization headers are redacted from any
  freeform text before it reaches the provider.
- **Professional PDF reports** (`app/services/reports.py`, full rewrite of
  `_render_pdf`): cover page (logo, title, target, assessment date,
  version, confidentiality label, prepared-by/contact), an
  auto-generated table of contents (fpdf2's real TOC/outline support, not
  a hand-rolled one), numbered sections (Executive Summary → Scope →
  Methodology → Attack Surface → Findings Summary with a severity bar
  chart → Detailed Findings → Remediation Summary → Appendix), a running
  header/footer with page numbers, and a full per-finding detail block
  (ID/severity/confidence/CWE/CVE/CVSS/affected asset/description/evidence/
  reproduction notes/sanitized request-response/remediation/references/
  detection source/verification status). Long request/response text wraps
  character-safely (`WrapMode.CHAR`) instead of overflowing. New
  `Settings → Reports` page for company name, logo (PNG/JPEG/WebP only —
  SVG rejected, it can embed scripts — capped at 300KB), report title,
  author, contact, confidentiality label, and accent color.
- **PDF generation reliability.** `validate_pdf()` does a best-effort
  structural sanity check (non-empty, `%PDF-`/`%%EOF` markers, rough page
  count) after every render — a broken render is now a clear `RuntimeError`
  instead of a silently corrupt file reaching a client. All text is
  sanitized through a latin-1-safe transliteration layer before reaching
  fpdf2's core fonts, so unsupported Unicode (CJK, emoji, smart
  punctuation) degrades to a safe placeholder instead of crashing report
  generation — verified with a 60-finding, mixed-Unicode stress test
  producing a clean 38-page PDF.

### Fixed

- **Injection param-extraction bug**: `orchestrator/internal/recon/pipeline.go`
  fed the injection-testing/vuln-scan engines through `uniqSorted()`, a
  helper meant for bare hostnames that truncated every URL at its first
  `/`, silently discarding 100% of real query parameters before they were
  ever tested. Fixed by using the already-existing, unused-for-this-purpose
  `uniqSorted2()` instead.
- **Two false-positive-prone injection verification methods**: path
  traversal's "self-reference" check never confirmed the tested parameter
  had any effect on the response before treating unchanged output as
  proof (fixed with an inert-parameter control probe,
  `inject_lfi.go`); time-based SQLi promoted a finding to "verified" from
  a single timing sample, indistinguishable from ordinary network jitter
  on a public target (fixed by requiring the delay to reproduce on an
  independent retry, `inject_sqli.go`).
- **Gateway crash-and-silent-error-loss on NUL-byte payloads**
  (`app/services/events.py`): a raw `0x00` byte in any event payload
  crashed Postgres's INSERT/UPDATE, and the resulting aborted transaction
  silently also swallowed the job's own `error_count` increment — a real
  failure was being recorded as nothing at all. Fixed with payload-wide
  NUL-byte scrubbing at the Redis-consumer ingestion boundary and a
  rollback-then-reload before the error-count bump.
- **fpdf2 API deprecation warnings** (`ln=1` throughout the old
  `_render_pdf`) resolved as part of the full PDF rewrite, which uses the
  current `new_x`/`new_y` API everywhere.
- **PDF cover-page layout bug**: `multi_cell()`'s default `new_x=RIGHT`
  left the text cursor at the right margin after the report title, so the
  next line (`p['client']`) rendered with ~0 remaining width and crashed
  with "Not enough horizontal space to render a single character" —
  fixed by setting `new_x=XPos.LMARGIN` explicitly on every cover-page
  `multi_cell()` call.
- **PDF table-of-contents overflow**: every per-finding heading (and every
  sub-heading inside each finding's detail block — Description, Evidence,
  Sanitized request, etc.) was registering as its own TOC/outline entry,
  which both made the TOC useless (hundreds of rows for a 50-finding
  report) and could overflow its reserved page and crash generation
  outright. Fixed by giving per-finding headings a distinct
  `finding_heading()` helper that renders identically but does not
  register in the table of contents — the TOC now stays a genuine
  8-section table of contents regardless of finding count.

### Known limitations

- PDF generation runs synchronously in the request path (as MD/CSV/HTML/JSON
  already did), not as a separate background job — a genuinely large,
  separate architecture change (new job type, polling UI) that was out of
  scope for this pass. It has been stress-tested at 60 findings (~38-51
  pages, well under a second) without issue; a project with an extreme
  finding count could still make the request slow.
- The AI settings UI only exposes Anthropic as a live-testable provider —
  `provider`/`model` are free-text fields for forward compatibility, but
  `test_connection()` and the analysis calls only implement the Anthropic
  Messages API today.
- Report logo storage is a `data:` URI column on `report_settings`
  (capped at 300KB), not an object-storage (MinIO) upload — this codebase
  has no MinIO integration wired into the gateway app yet to build on.
- The unified finding pipeline still maps injection Tier=Likely to a
  top-level `status: confirmed`/`severity: high` (only the finding's
  title/tags say "LIKELY") — the new AI per-finding analysis now reads the
  tier tag directly to avoid over-trusting this, but the underlying
  finding-severity mapping itself is unchanged from before this pass.

## 0.9.0-private — Finalization: accounts, notifications, private release prep

### Added

- **Self-registration + email verification.** `POST /api/auth/register`,
  `/verify-email`, `/resend-verification` — any email provider works,
  including `@proton.me`/`@protonmail.com` (no allowlist ever existed; see
  `docs/AUTHENTICATION.md`, which also documents why "Sign in with Proton"
  OAuth is not offered — Proton does not publish a third-party OAuth/OIDC
  endpoint).
- **Password reset**, **change password**, **change email** (re-verifies the
  new address), **active session list/revoke/revoke-all**, **account
  export**, **account deletion** (with password + typed-email confirmation;
  a self-registered user's solo workspace is deleted with them, a shared
  org's last admin is protected).
- **Email provider abstraction** (`app/core/email.py`): `EmailProvider` ABC,
  a real `SMTPProvider`, and honest `NotImplementedError`-raising stubs for
  Resend/SendGrid/SES (interface exists per spec; only SMTP is wired to a
  real vendor in this build).
- **Telegram notifications** (`app/core/telegram.py`): Bot API adapter
  (`sendMessage`, long-polled `getUpdates`), pairing-code flow (no
  credentials ever requested from the user), per-user enable/disable, test
  send.
- **Unified NotificationService** (`app/services/notifications.py`):
  per-user event preferences, quiet hours (with a critical-finding
  override), Redis-queued async delivery (never synchronous from a
  scanner/worker path), retry with backoff (30s/2m/10m) to a `dead_letter`
  status, full delivery audit trail (`notification_deliveries` table).
- **Settings UI restructure**: Profile / Account / Security / Notifications
  (Email, Telegram, Notification Types, Quiet Hours) / System, as a proper
  tabbed section clearly separated from operational scan navigation.
- **System Health** promoted to its own top-level nav item (`/system`),
  visually separated (divider) from Dashboard/Projects/Scan Jobs/Audit Logs.
- `/api/ready` (DB + Redis + config check, never leaks connection strings)
  and `/api/version`, both previously missing.
- `THIRD_PARTY_LICENSES.md` + `sbom.json`, generated (and re-generatable)
  by `scripts/generate_sbom.sh` from the actually-installed dependency set
  — not hand-maintained.
- `docs/AUTHENTICATION.md`, `FINALIZATION_STATUS.md`, `MANUAL_TEST_PLAN.md`.
- CI: `secret-scan` (gitleaks) and `dependency-review` jobs.
- Version bumped to `0.9.0-private` (private-beta prerelease identifier),
  displayed consistently in the API (`/api/version`, `/api/health`), the
  web UI sidebar, and generated reports (MD/HTML/PDF).

### Fixed

- **Naive/aware datetime comparison bug**: `refresh()`, and the new
  verify-email/reset-password/Telegram-pairing expiry checks, compared a
  value read back from the database directly against `datetime.now(UTC)`.
  This throws `TypeError` on SQLite (used by the test suite, and a valid
  lightweight deployment option) whenever the column round-trips as naive —
  Postgres wasn't affected, and `/api/auth/refresh` had zero test coverage
  before this pass, which is why it went unnoticed. Fixed with a shared
  `security.ensure_aware()` helper applied at every comparison site.
- Account-deletion logic's first draft blocked *every* self-registered user
  from ever deleting their own account (a solo-admin check didn't
  distinguish "sole admin of a shared org" from "sole member of your own
  personal workspace"). Fixed to allow the latter (deletes the org with the
  account) while still protecting the former.
- Sidebar footer had a hardcoded `Milestone 1 · v0.1.0` string; now fetches
  the live version from `/api/version`.

### Security

- Verification and password-reset tokens are SHA-256-hashed before storage
  — the raw token exists only in the one-time email sent to the user, never
  in the database.
- Added a repo-root `.gitleaksignore` documenting the two intentionally
  synthetic secrets in `orchestrator/internal/recon/secrets_test.go` (the
  platform's own secret-detector test fixtures) so CI's secret scan doesn't
  flag known-safe, deliberately-fake values while still catching anything
  real.

### Known limitations

- Telegram and SMTP success-path delivery were not tested against a real
  bot token / real mail account in this environment (no credentials
  available here) — both fail gracefully and honestly when unconfigured,
  verified by test; real-provider delivery is on the manual test plan
  (`MANUAL_TEST_PLAN.md` §4-5).
- Notification retry backoff is in-process (`asyncio.sleep`-scheduled), not
  a persisted delayed queue — see `app/services/notifications.py`'s module
  docstring.
- Admin-only Settings UI (editing email/Telegram provider config from the
  app instead of `.env`), global settings search, and several sidebar
  sections from the original spec (Scan Defaults, Appearance beyond
  theme, Performance, Storage, API Integrations, Advanced) were not built —
  see `FINALIZATION_STATUS.md`'s "Deferred" section for the full, honest
  list.

## Unreleased — Installation, startup, and troubleshooting framework

### Added

- **`install.sh`** — single entry point for environment setup. Detects OS
  (Kali/Parrot/Ubuntu/Debian primary, Mint/Pop!_OS/other Debian-derivatives
  best-effort), installs system packages, Python venv, Node deps, Go
  toolchain, and every security tool in `config/tools.yaml`; provisions
  Postgres/Redis; generates `.env` with real random secrets; applies
  migrations. Idempotent — safe to re-run. Flags: `--check`, `--repair`,
  `--upgrade`, `--dev`, `--production`, `--non-interactive`, `--force`.
- **`run.sh`** — primary control interface (`start`/`stop [--force]`/
  `restart`/`status`/`logs`/`doctor`/`self-test`). Native process management
  with real PID tracking (each service is its own process-group leader via
  `setsid`, so stop signals the whole group and nothing orphans), a fast
  startup health check, and a graceful shutdown order (orchestrator → web →
  gateway) that lets in-flight scan jobs checkpoint themselves.
- **`doctor.sh`** — diagnostic + safe-repair tool (`--check` [default],
  `--fix`, `--deep`, `--report`, plus focused `--tools`/`--workers`/
  `--database`/`--network`/`--permissions`/`--performance`/`--logs`).
  Classifies failures by category; `--fix` only ever performs a fixed,
  documented safe-repair list (never touches project data, the database
  schema/contents, secrets, or processes it didn't start).
- **`scripts/lib/`** — the shared framework the three entry points are built
  from: `common.sh`, `logging.sh`, `os_detection.sh`, `package_manager.sh`,
  `python.sh`, `node.sh`, `go.sh`, `docker.sh`, `database.sh`, `redis.sh`,
  `tools.sh`, `services.sh`, `health.sh`, `permissions.sh`, `diagnostics.sh`,
  `performance.sh`, `repair.sh`.
- **`config/tools.yaml`**, **`config/versions.yaml`**, **`config/system.yaml`**
  — centralized manifests for the security-tool catalog, language-version
  requirements, and hardware/threshold/port configuration. `tools.yaml`
  mirrors `orchestrator/internal/tools/registry.go` and
  `apis/gateway/app/tool_catalog.py`.
- **`scripts/env_setup.sh`** — `.env` generation with fresh secrets on first
  install; never overwrites an existing `.env`; additively appends any new
  keys `.env.example` has gained since (without touching existing lines).
- **`scripts/backup.sh`** — configuration + `pg_dump` backup, run
  automatically before `install.sh --upgrade`.
- **`scripts/self_test.sh`** (`./run.sh self-test`) — database, Redis, API,
  worker, scheduler, tool health, and frontend checks, plus the gateway
  pytest suite and orchestrator Go test suite (local fixtures only, never
  public infrastructure).
- **`scripts/report.sh`** (`./doctor.sh --report`) — sanitized diagnostic
  archive (OS/version info, service/tool status, config *key names* only,
  redacted log excerpts, no secrets).
- **`deploy/systemd/`** — optional `bbhunter.service` (gateway + in-process
  scheduler), `bbhunter-worker.service` (orchestrator), `bbhunter-web.service`
  (frontend) units with restart-on-failure, resource limits, and hardening.
  `run.sh` remains fully functional without them.
- New docs: `docs/TROUBLESHOOTING.md`, `docs/KALI.md`, `docs/PARROT.md`,
  `docs/UPGRADING.md`; `docs/INSTALL.md` and `docs/DEPLOYMENT.md` updated
  with the native install path.
- `.env.example` gained the previously-undocumented env vars the app
  already reads (`ARGUS_MAX_INJECTION_PARAMS`, `ARGUS_OAST_COLLECTOR_URL`,
  `ARGUS_XSS_BROWSER_VERIFY`, `ARGUS_WORDLISTS_DIR`, `ARGUS_FFUF_WORDLIST`,
  `ARGUS_NUCLEI_TEMPLATES_DIR`, `ARGUS_NAABU_PORTS`, `ARGUS_SCHEDULER`,
  `ARGUS_AI_API_KEY`/`ARGUS_AI_MODEL`, Vault Transit vars, OTel endpoint).

### Fixed

- `apis/gateway/requirements.txt` was significantly stale relative to what
  the app actually imports (missing `croniter`, `fpdf2`, `hvac`,
  `prometheus_client`, the `opentelemetry-*` packages entirely) and pinned
  to versions of `pydantic`/`pydantic-core` that fail to build from source
  on Python 3.14 (no prebuilt wheel yet, and the pinned version predates
  3.14 support). A fresh `pip install -r requirements.txt` on 3.14 would
  have failed outright. Re-pinned to the versions actually verified working
  (all 90 gateway tests pass).
- Database credentials were being embedded into a logged shell command
  string during `alembic upgrade head` (`scripts/lib/database.sh`),
  producing plaintext-password log lines in `logs/runtime.log` and
  `logs/doctor.log`. Fixed to pass `DATABASE_URL` via process-environment
  inheritance instead of command-line/log-visible text, and added a
  defense-in-depth redaction pass for `scheme://user:pass@host`-shaped
  strings in `scripts/lib/logging.sh` in case another code path does the
  same thing in the future.
- An orphaned `next-server` process could survive `kill` on its parent
  shell wrapper (`sh -c "next start"`) and keep port 3000 bound after a
  "stop". `services.sh` now launches every process as its own session/
  process-group leader and signals the whole group on stop.
- Several `VAR="$(cmd | other_cmd)"` assignments across the new lib modules
  were unsafe under `set -e -o pipefail` — a `grep` finding no match (a
  normal, expected outcome, e.g. "this YAML key/tool isn't present") made
  the whole pipeline report failure and abort the script. Audited and
  shielded throughout `scripts/lib/*.sh`.
- `logs/`, `runtime/`, `backups/` were not in `.gitignore`.

### Known limitations

- `install.sh`'s native (non-Docker) Postgres/Redis provisioning path
  (`db_install_native`/`redis_install_native`) is implemented but has only
  been exercised in the Docker-backing-services mode this environment
  actually runs — exercise it on a real fresh Kali/Parrot install before
  relying on it for production.
- No automated fresh-OS install test matrix was built, per explicit
  instruction — manual verification on real Kali/Parrot hardware/VMs is the
  user's own next step.
- `doctor.sh --report`'s redaction is pattern-based (same engine as
  `logging.sh`), not a secret-scanner — it catches every shape this project
  itself produces, but skim any report before sharing it externally anyway.
