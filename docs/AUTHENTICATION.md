# Authentication

## Account model — single bootstrap super admin

Argus uses a **single-account model**: there is one role (`super_admin`,
holding every permission — see `apis/gateway/app/core/rbac.py`), created
once by the installer, and no public registration, invite, or
forgot-password flow.

```
./install.sh
      ↓
python -m app.bootstrap_admin   (idempotent — safe to re-run)
      ↓
Creates: one Organization + one User (super_admin) + one Membership
      ↓
Username (email): argus@argus.local
Password:         from ARGUS_DEFAULT_ADMIN_PASSWORD in .env (default: argus)
      ↓
Log in → change the password (Settings → Security → Change Password)
```

**`argus@argus.local` / `argus` is a bootstrap credential for initial
setup, not a secure production password — change it immediately after
first login**, especially for any shared, production, or
internet-facing deployment. Set `ARGUS_DEFAULT_ADMIN_PASSWORD` in `.env`
before running `install.sh` to choose your own bootstrap password instead
of the default.

There is no `/register`, `/api/auth/setup`, or admin-invite endpoint —
`python -m app.bootstrap_admin` (run automatically by `install.sh`) is the
only way an Argus account is ever created. This is a deliberate
simplification for a self-hosted, single-operator tool: no role matrix to
reason about, no "who can invite whom" surface, no email-verification
infrastructure that needs a working SMTP server before the app is usable.

## Rotating/recovering the bootstrap password

```bash
cd apis/gateway && .venv/bin/python -m app.bootstrap_admin --reset-password
```

Generates and prints a fresh password once (or reuses
`ARGUS_DEFAULT_ADMIN_PASSWORD` if set). This is the supported account
-recovery path — there is no self-service "forgot password" email flow.

## Sessions

Each login/refresh issues a JWT access token (short-lived) and a refresh
token (longer-lived, tracked server-side in `refresh_tokens` with the
requesting IP + user agent). `GET /api/auth/sessions` lists active,
non-revoked sessions; revoke one or all of them
(`DELETE /api/auth/sessions/{id}`, `POST /api/auth/sessions/revoke-all`).

## MFA

TOTP-based (RFC 6238), compatible with any standard authenticator app
(Google Authenticator, 1Password, Proton Pass, etc.). Enroll/verify/disable
via `/api/auth/mfa/*`; see Settings → Security in the web UI. Strongly
recommended in addition to changing the bootstrap password.

## What's never exposed

Password hashes (Argon2, via `passlib`), MFA secrets, JWT signing secret,
and session/refresh tokens are never returned by any API response and
never logged.

## Why not multi-role / self-registration?

Earlier versions of Argus had a six-role RBAC matrix
(`super_admin`/`org_admin`/`security_lead`/`security_analyst`/
`researcher`/`viewer`), public self-registration with email verification,
and forgot-password. For the actual deployment shape this project targets
— one operator running their own instance — that added real complexity
(role matrix to maintain and audit, SMTP required just to finish sign-up,
a public registration endpoint that's attack surface on its own) without
a corresponding benefit: nobody was sharing one instance across
differently-privileged users. The single-role bootstrap-admin model
removes that surface entirely; see `apis/gateway/app/core/rbac.py`'s
module docstring and migration `0015_single_role_bootstrap_admin` for the
full rationale and how existing installs are migrated.
