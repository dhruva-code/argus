# Changelog

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
