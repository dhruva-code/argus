# Security

## Supported versions

Argus is currently in **private beta** (`0.9.x`). Only the latest commit on
`main` in the private repository receives security fixes — there is no
long-term-support branch yet. Once `1.0.0` ships publicly, this section will
list which minor versions continue to receive patches.

## Reporting a vulnerability

This repository is currently **private** and under active pre-release
development. If you have access to it and find a security issue:

- Do not open a public issue anywhere, and do not discuss it outside this
  repository's own private channels.
- Report it directly to the repository owner (see the repository's
  collaborator list / GitHub profile contact).
- Include: affected component, reproduction steps or PoC, impact, and
  whether it's already been exploited against a real target.

Responsible disclosure: the owner will acknowledge receipt, work on a fix
privately, and credit the reporter (if desired) once a fix ships. Because
this platform is itself a security-testing tool, a vulnerability in it could
directly translate into unauthorized access during someone else's
engagement — treat findings here with the same urgency as any other
security-tooling CVE.

## Scope and authorization expectations

Argus is built to test only infrastructure the operator is explicitly
authorized to test. This is enforced in software (scope engine + SSRF guard,
below), not just policy — but the platform cannot verify real-world
authorization (a signed bug-bounty scope, a pentest contract, written
permission). **The operator is responsible for having that authorization
before creating a project scope or running any active scan.** Running Argus
against infrastructure you don't have explicit permission to test is outside
this project's intended use and is the operator's legal responsibility, not
the software's.

## Authorization model for scanning

Argus is a defensive / authorized-assessment platform. Two independent gates
stand between a request and a packet leaving the host:

1. **Scope engine** — every job carries its project's compiled scope policy. The
   orchestrator refuses to act on any target that is not explicitly allowed
   (and not denied). From M2, the HTTP engine re-checks every individual request
   URL against the same policy.
2. **SSRF guard** (`orchestrator/internal/ssrf`) — every outbound URL is
   resolved and every resulting IP checked. Blocked by default: loopback,
   RFC1918, link-local, CGNAT (100.64/10), IPv6 ULA, unspecified/multicast, and
   cloud metadata endpoints (169.254.169.254, 100.100.100.200, fd00:ec2::254).
   Resolution-then-check defeats DNS rebinding. An operator may re-allow
   specific CIDRs via `SSRF_ALLOW_CIDRS` for an authorized internal engagement.

Active job types additionally require `authorization_ack: true` on the create
request. The UI shows the target, scope, exclusions, profile, rate limits, and
an estimated request volume before that box can be checked. An
`POST /api/jobs/emergency-stop` broadcasts `stop_all` on the control channel;
every worker cancels its in-flight jobs and stops claiming new ones until
cleared.

## Command-injection prevention

Tools are never run via a shell. `plugin.ExecRunner` builds an explicit `argv`
slice and calls `exec.CommandContext`; `Look` rejects any binary name containing
a path separator. There is no `shell=True`, no string interpolation into a
command line, anywhere in the codebase.

## Application hardening

| Concern | Control |
|---|---|
| Passwords | Argon2id (`passlib`) |
| Sessions | Short-lived JWT access token + rotating refresh token; refresh tokens are single-use and revocable (`refresh_tokens` table) |
| MFA | Optional TOTP (RFC 6238), enforced at login when enabled |
| Secrets at rest | Tool API keys encrypted with Fernet (`SECRET_ENCRYPTION_KEY`); never returned by the API, masked in the UI |
| SQL injection | SQLAlchemy Core/ORM parameterized queries only |
| Tenancy | `org_id` filter on every query; cross-tenant rows 404 |
| RBAC | Fixed role→permission matrix, enforced per route |
| Transport | Gateway speaks plain HTTP; terminate TLS at a reverse proxy (see INSTALL.md). `--proxy-headers --forwarded-allow-ips` set in the entrypoint |
| CORS | Locked to `ARGUS_CORS_ORIGINS`; in production the browser only ever talks to the `web` origin, which proxies same-origin `/api` |
| Audit | Every mutation writes an append-only `audit_logs` row (actor, IP, action, before/after, reason). No UI path updates or deletes them |

## Production start-up refuses to run when

- `ARGUS_ENV=production` and `JWT_SECRET` is still the dev default.
- `ARGUS_ENV=production` and `SECRET_ENCRYPTION_KEY` is unset.

## Secret handling

- **Application secrets** (tool API keys, Telegram bot token via env,
  Auth-Profile credentials for authenticated DAST) are encrypted at rest
  with Fernet (`SECRET_ENCRYPTION_KEY`) or, optionally, HashiCorp Vault
  Transit (`VAULT_*`) — see `apis/gateway/app/core/crypto.py`. Neither is
  ever returned by any API response.
- **User credentials**: passwords are Argon2id-hashed, never stored or
  logged in plaintext. Email-verification and password-reset tokens are
  SHA-256-hashed before being stored — the raw token exists only in the
  one-time email sent to the user (see `docs/AUTHENTICATION.md`).
- **Installer/ops secrets**: `install.sh`/`run.sh`/`doctor.sh` (see
  `scripts/lib/logging.sh`) redact anything that looks like a password,
  token, API key, or `user:pass@host`-shaped URL before writing to
  `logs/*.log`, and `doctor.sh --report`'s diagnostic archive includes
  configuration *key names* only, never values.
- **Never commit `.env`** — see `.gitignore` and the pre-push secret scan in
  `CHANGELOG.md` / CI (`.github/workflows/ci.yml`'s `secret-scan` job).

## Known limitations (0.9.0-private)

- No per-IP login/registration throttling yet at the application layer; put
  the gateway behind a reverse proxy that provides it for any
  internet-facing deployment (this matters more now that self-registration
  exists — see docs/AUTHENTICATION.md).
- The notification-delivery retry queue is in-process (`asyncio`-scheduled
  backoff, not a persisted delayed queue) — a gateway restart mid-retry
  drops that specific pending retry rather than resuming it. See
  `apis/gateway/app/services/notifications.py`.
- Telegram pairing uses long-polling (`getUpdates`), not a webhook — fine
  for a single-gateway deployment, not appropriate to run from more than one
  gateway replica at once (both would compete for the same updates).
- "Sign in with Proton" is not offered — see docs/AUTHENTICATION.md for why,
  and what email-address support (which *is* fully implemented) means
  instead.
