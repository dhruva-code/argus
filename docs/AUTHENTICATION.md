# Authentication

## Account model

Argus uses standard email + password registration with email verification,
TOTP-based MFA (optional, per-user), JWT access tokens + rotating refresh
tokens, and session management. See `apis/gateway/app/routers/auth.py`.

```
User enters email + password
      ↓
Validate syntax (any domain — no provider allowlist)
      ↓
Create pending account (email_verified = false)
      ↓
Send verification email (token, 48h expiry, one-way hashed in the DB)
      ↓
User clicks the link → POST /api/auth/verify-email
      ↓
Account activated — user can now log in
```

A freshly-registered user gets their own personal organization automatically
(so there's somewhere for their projects to live); existing organizations
add members via an admin-issued invite (`POST /api/orgs/members`), which
skips verification since an admin is vouching for a specific address they
typed themselves.

## Proton email addresses — fully supported as a destination

`user@proton.me` and `user@protonmail.com` work exactly like any other email
address for registration, login, verification, password reset, and
notifications. `app/core/types.py`'s `Email` type has **no provider
allowlist** — nothing in registration, login, or notification delivery
special-cases or blocks Proton (or any other provider). Outbound mail goes
through standard SMTP (`app/core/email.py`), which Proton Mail accepts like
any other mail server.

This was verified against the actual code path, not assumed: `Email` is a
regex-based validator with no domain check at all (see
`apis/gateway/app/core/types.py`), and a live registration against a
`@proton.me` address was exercised end-to-end during this work (see
`apis/gateway/tests/test_accounts.py::test_register_verify_login_flow`,
which registers against `@proton.me` specifically).

## Proton as an identity/OAuth provider — not offered, and why

This is a **separate question** from email-address support above, and the
answer is different: **"Sign in with Proton" is not implemented, because
Proton does not currently publish a supported OAuth 2.0 / OpenID Connect
endpoint for third-party applications to integrate against.** Proton's own
products (Mail, Calendar, Drive, Pass) use Proton's internal SSO for
Proton's own apps; there is no public developer-facing "Login with Proton"
program comparable to Google/Microsoft/GitHub OAuth at the time this was
built.

Consequences of that:

- Argus will **not** show a "Sign in with Proton" button, because doing so
  without a real, verified OAuth/OIDC endpoint would mean either faking the
  flow or silently falling back to something else — both of which this
  project's engineering standard explicitly rules out ("never claim a
  feature is complete if it has not actually been implemented").
- If Proton (or any other provider) publishes a supported OIDC discovery
  document in the future, adding it is a contained change: FastAPI's OAuth2
  integrations follow a standard `authorization_endpoint` /
  `token_endpoint` / `jwks_uri` pattern, and `app/routers/auth.py` already
  isolates token issuance behind `_issue_pair()` — a new
  `POST /api/auth/oauth/{provider}/callback` endpoint would plug into that
  same function without touching the rest of the auth system.
- In the meantime, a Proton user gets the exact same experience as a Gmail
  or self-hosted-mail user: register with their `@proton.me` address,
  verify it, and log in with a password (optionally + TOTP MFA, which
  Proton Pass or any other authenticator app can generate).

## Sessions

Each login/refresh issues a JWT access token (short-lived) and a refresh
token (longer-lived, tracked server-side in `refresh_tokens` with the
requesting IP + user agent). `GET /api/auth/sessions` lists active,
non-revoked sessions; a user can revoke one or all of them
(`DELETE /api/auth/sessions/{id}`, `POST /api/auth/sessions/revoke-all`). A
password reset revokes every existing session as a precaution.

## MFA

TOTP-based (RFC 6238), compatible with any standard authenticator app
(including Proton Pass's built-in authenticator, Google Authenticator, 1Password,
etc. — MFA here is a generic TOTP secret, not tied to any specific app).
Enroll/verify/disable via `/api/auth/mfa/*`; see Settings → Security in the
web UI.

## What's never exposed

Password hashes (Argon2, via `passlib`), MFA secrets, JWT signing secret,
session/refresh tokens, and email-verification/password-reset tokens are
never returned by any API response, never logged (see
`apis/gateway/app/routers/auth.py` — tokens are SHA-256 hashed before
storage and compared by hash; the raw token only ever exists in the
one-time email sent to the user), and never rendered in any UI aside from
the one-time MFA enrollment secret shown during setup.
