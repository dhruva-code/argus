# Security

## Supported versions

Argus (`0.9.x`) is **public** on GitHub. Only the latest commit on `main`
receives security fixes — there is no long-term-support branch yet.

## This is a public repository — read before you deploy

- **Never commit `.env`, real credentials, API keys, or private keys.**
  `.gitignore` excludes `.env`/`*.pem`/`*.key`/`*credentials*.json`/etc.
  by default — don't work around it.
- **The bootstrap admin credential is public knowledge.**
  `argus@argus.local` / `argus` is documented in this repository's own
  README/INSTALL/AUTHENTICATION docs — anyone can read it. It exists so a
  fresh install has *something* that works out of the box, not as a
  secret. **Change it immediately after first login** for any deployment
  reachable by anyone other than you, and set your own
  `ARGUS_DEFAULT_ADMIN_PASSWORD` in `.env` before running `install.sh` if
  you don't want the default used even transiently.
- **Never expose a freshly-installed instance to the internet** before
  changing that password. Login is rate-limited by source IP
  (`app/core/ratelimit.py`, 10 failed attempts / 15 minutes) specifically
  because the account identity here is fixed and public — but rate
  limiting slows a brute force, it doesn't replace a real password.
- Run a secret scan (`gitleaks detect --source .`, or see
  `.gitleaks.toml` for this repo's own CI-integrated config) before
  pushing if you've been editing `.env.example`, install scripts, or test
  fixtures that legitimately contain secret-*shaped* strings.

## Reporting a vulnerability

- **Do not open a public GitHub issue for a security vulnerability.**
- Report privately to the repository owner (see the repository's
  collaborator list / GitHub profile contact) or via GitHub's private
  vulnerability reporting (Security tab → "Report a vulnerability") if
  enabled on this repository.
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
| Login rate limiting | 10 failed attempts / 15 min, keyed by source IP (`app/core/ratelimit.py`, Redis-backed, fails open if Redis is down) — see "public repository" note above for why IP rather than account |
| Login audit | Every login attempt (success and failure, with reason) writes an `audit_logs` row — `auth.login`/`auth.login_failed` |
| MFA | Optional TOTP (RFC 6238), enforced at login when enabled |
| Secrets at rest | Tool API keys encrypted with Fernet (`SECRET_ENCRYPTION_KEY`); never returned by the API, masked in the UI |
| SQL injection | SQLAlchemy Core/ORM parameterized queries only |
| Tenancy | `org_id` filter on every query; cross-tenant rows 404 |
| Authorization | Single-role model — every account holds every permission (`app/core/rbac.py`); enforced per route regardless |
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
  logged in plaintext (see `docs/AUTHENTICATION.md`).
- **Installer/ops secrets**: `install.sh`/`run.sh`/`doctor.sh` (see
  `scripts/lib/logging.sh`) redact anything that looks like a password,
  token, API key, or `user:pass@host`-shaped URL before writing to
  `logs/*.log`, and `doctor.sh --report`'s diagnostic archive includes
  configuration *key names* only, never values.
- **Never commit `.env`** — see `.gitignore` and the pre-push secret scan in
  `CHANGELOG.md` / CI (`.github/workflows/ci.yml`'s `secret-scan` job).

## Known limitations (0.9.x)

- The notification-delivery retry queue is in-process (`asyncio`-scheduled
  backoff, not a persisted delayed queue) — a gateway restart mid-retry
  drops that specific pending retry rather than resuming it. See
  `apis/gateway/app/services/notifications.py`.
- Telegram pairing uses long-polling (`getUpdates`), not a webhook — fine
  for a single-gateway deployment, not appropriate to run from more than one
  gateway replica at once (both would compete for the same updates).
- Login rate limiting is IP-keyed and Redis-backed (see above) — an
  attacker behind a large shared NAT/proxy could still exhaust that IP's
  budget for legitimate users behind the same address. Put the gateway
  behind a reverse proxy/WAF with its own rate limiting for an
  internet-facing deployment.
- There is no built-in mechanism to run multiple bootstrap-admin accounts
  with different privilege levels — this is by design for the
  single-operator deployment shape this project targets (see
  `docs/AUTHENTICATION.md`), not a gap to be filled later.
