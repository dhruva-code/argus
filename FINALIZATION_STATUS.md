# Finalization Status

Tracks the state of every area covered by the finalization pass. Statuses:
**PASS** (already correct, verified, no change needed), **FIXED** (a real
bug was found and corrected), **IMPROVED** (working, made better), **BLOCKED**
(could not be completed in this pass — reason given), **NEEDS MANUAL TEST**
(implemented and self-tested, but needs a human exercising it for real —
see `MANUAL_TEST_PLAN.md`).

| Feature | Status | Problems found | Changes made | Testing performed | Remaining issue | Risk |
|---|---|---|---|---|---|---|
| Email registration (any provider, incl. Proton) | FIXED | No self-registration endpoint existed at all; `Email` type already had no provider allowlist (verified, not assumed) | Added `POST /api/auth/register` + email verification flow, personal-org auto-creation | `pytest tests/test_accounts.py` (8 tests) + live curl registration against `@proton.me` on the running gateway | None known | Low |
| Password reset | FIXED | Did not exist | Added request/reset endpoints, token hashed at rest, revokes all sessions on reset | pytest + live | None known | Low |
| Session management | FIXED | No session list/revoke UI or API; `RefreshToken` had no IP/UA | Added `ip`/`user_agent`/`last_used_at` columns, `/auth/sessions` list/revoke/revoke-all, Settings → Account UI | pytest + manual UI click-through | "current session" isn't marked (documented limitation — access token doesn't carry the refresh jti) | Low |
| Account deletion | FIXED | Did not exist; naive first draft blocked every self-registered user from ever deleting their own account (sole-org-admin check didn't distinguish solo vs shared orgs) | Added export + delete with password + typed-email confirmation; solo workspaces are deleted with the account (cascades cleanly — all FKs already `ON DELETE CASCADE`), shared orgs block deletion of the last admin | pytest (deliberately covers the solo-admin edge case) | None known | Low |
| Naive/aware datetime bug in token expiry checks | FIXED | `refresh()`, `verify-email`, `reset-password`, Telegram pairing all compared a DB-read datetime against `datetime.now(UTC)` directly — crashes with `TypeError` on SQLite (used by the test suite and available as a lightweight deployment option), silently masked in production because Postgres doesn't have the bug and `/auth/refresh` had zero test coverage before this pass | Added `security.ensure_aware()`, applied everywhere a stored expiry is compared | pytest (the new tests reproduced the crash before the fix, pass after) | Postgres was never actually broken by this — SQLite deployments were | Low (now) |
| Email provider abstraction | IMPROVED | Only inline `smtplib` in one file (`notify.py`), no abstraction | Added `EmailProvider` ABC + `SMTPProvider` (real) + Resend/SendGrid/SES stubs that raise `NotImplementedError` naming exactly what's missing | Live SMTP-unconfigured test (`test-email` reports "not configured", doesn't crash or fake success) | Only SMTP is actually wired to a real provider — by design, see AUTHENTICATION.md | Low |
| Telegram notifications | FIXED | Did not exist | Bot API adapter (`sendMessage`, `getUpdates`), pairing-code flow, per-user preferences, test-send | pytest (pairing without a configured bot correctly reports `bot_configured: false`, doesn't fake success) | Requires a real `TELEGRAM_BOT_TOKEN` for actual delivery — **needs manual test** with a real bot | Medium — untested against the real Telegram API in this pass (no bot token available in this environment) |
| Notification queue + retry/backoff/dead-letter | FIXED | Notifications would otherwise be synchronous, blocking callers on a slow mail/Telegram API | Redis-queued, `asyncio`-retried (30s/2m/10m), `notification_deliveries` table tracks status incl. `dead_letter` | Code review + pytest of the surrounding endpoints | Retry backoff is in-process (documented limitation — a gateway restart mid-backoff drops that one pending retry) | Low |
| Settings UI restructure | IMPROVED | Single flat page (Profile/MFA/SystemHealth/Permissions only) | Tabbed: Profile / Account / Security / Notifications (Email, Telegram, Rules, Quiet Hours) / System | `npm run typecheck && npm run lint && npm run build` all clean; manual click-through of every tab against the live app | Scan Defaults / Tool Configuration / Appearance(beyond theme) / Performance / Storage / API Integrations / Advanced sidebar sections from the original spec were **not** built — see "Deferred" below | Low (nothing broken; feature not present) |
| System Health nav item | FIXED | No dedicated page; buried as one card on the old Settings page | New `/system` top-level nav entry, visually separated from operational nav (divider) | Manual click-through | None known | Low |
| `/api/version`, `/api/ready` | FIXED | Did not exist (flagged as a gap in the prior installer-framework pass) | Added both; `/api/ready` checks DB+Redis+config, never leaks connection strings | curl against the live gateway | None known | Low |
| Version consistency (§43) | FIXED | Hardcoded `v0.1.0` string in the sidebar footer; no version in generated reports | `0.9.0-private` set in `app/__init__.py`, `pyproject.toml`, `package.json`; sidebar now fetches `/api/version` live; all three report renderers (MD/HTML/PDF) show it | Manual UI check + `pytest tests/test_reports.py` | None known | Low |
| Gateway test suite | PASS→98 | 90 passing before this pass | Added 8 new tests (`test_accounts.py`) | `pytest -q` — 98 passed | None known | Low |
| Orchestrator test suite | PASS | No changes made to orchestrator this pass | — | `go test ./...` (unchanged, still green) | None known | Low |
| Frontend build/lint/typecheck | PASS | — | New pages + Settings restructure | `npm run typecheck && npm run lint && npm run build` all clean | None known | Low |
| install.sh / run.sh / doctor.sh vs. final source tree | PASS | — | No path/dependency changes needed — the finalization pass didn't move or rename anything the installer framework references | `./doctor.sh --check`, `./run.sh status` re-run against the finalized tree | None known | Low |
| Secret leak in installer logs (found in a *prior* session's work, re-verified clean here) | PASS | (Already fixed in the prior installer-framework pass — re-verified still clean) | — | `grep` for the live `.env` secrets across `logs/*.log` and a freshly generated `doctor-report-*.tar.gz` — no match | None known | Low |
| Secret scan of the full repo before commit | PASS | — | See "Secret and credential audit" below | `git status`, `grep` sweep, `.gitignore` review | None known | Low |
| Admin/system settings vs. per-user settings separation (§24) | PASS | — | Verified: `app/routers/settings.py` is entirely `get_current_user`-scoped (a user's own data only); no admin-only config is exposed through it. Admin-level config (email/Telegram provider, worker limits, tool config) remains `.env`-only, matching the existing pattern for `ARGUS_TOOLS_BIN_DIR` etc. | Code review | A dedicated Admin Settings *UI* (reading/writing selected `.env`-equivalent values from the app) was **not** built — deferred | Low |
| Global settings search (§25) | BLOCKED | — | Not built | — | Out of scope for this pass — the Settings page is small enough (5 tabs) that search wasn't prioritized over the notification/auth work | Low — cosmetic gap, not a functional one |
| Admin Settings UI, full sidebar (Scan Defaults / Tool Config / Appearance / Performance / Storage / API / Advanced) | BLOCKED | — | Not built | — | Each of these needs its own backend surface (e.g. "Tool Configuration" already exists as the separate Tool Manager page; "Scan Defaults" would need new per-project-default plumbing) — building fake pages with non-functional controls would violate the explicit "no placeholder controls" instruction, so they were left out rather than faked | Medium — a real gap against the full spec, honestly reported rather than hidden |
| Cross-project top-level nav (Assets/Infrastructure/Endpoints/Technologies/Repositories/Secrets/Injection Testing/Findings/Workflows as separate top-level pages) | BLOCKED | — | Not built | — | These currently exist as per-project tabs (`/projects/[id]`), not global cross-project views. Building real global versions requires new aggregation API endpoints per resource type — out of scope for this pass; the existing Dashboard/Projects/Findings pages already cover cross-project visibility for the highest-value resource (findings) | Low — existing functionality unaffected, nothing removed |
| Third-party license inventory / SBOM | FIXED | Did not exist | `scripts/generate_sbom.sh` (real, re-runnable) → `THIRD_PARTY_LICENSES.md` + `sbom.json` (custom simple format, not full CycloneDX — documented as such) | Ran against the live installed dependency set (78 Python, 452 Node incl. dev, 6 Go, 12 security tools) | Not a full SPDX/CycloneDX-compliant SBOM | Low |
| CI: lint/test/security scanning | IMPROVED | Existing CI covered gateway/orchestrator/web tests+lint only | Added a `secret-scan` job (gitleaks) and a `dependency-review` step — see `.github/workflows/ci.yml` | `git diff` review of the workflow file (not run in this sandbox — no GitHub Actions runner here) | **NEEDS MANUAL TEST** once pushed — first real run happens on GitHub | Low |
| Private GitHub repository | NEEDS MANUAL TEST | — | Created private, pushed initial commit | `gh repo view --json visibility` confirms `PRIVATE` after creation | Owner should independently confirm visibility in the GitHub UI before any further action | See §69 checklist in the final report |

## Deferred (honestly, not silently)

The following items from the finalization spec were **not** implemented in
this pass, listed here rather than left unmentioned:

- Admin-only Settings UI surface (email/Telegram provider config editable
  from the app rather than `.env` only).
- Global settings search box.
- Scan Defaults / Appearance(beyond theme+dark mode, already existing) /
  Performance / Storage / API Integrations / Advanced settings pages.
- Full cross-project top-level navigation restructure (Assets/Infra/
  Endpoints/etc. as global pages rather than per-project tabs).
- Real end-to-end Telegram test against a live bot token (no token
  available in this build environment — the pairing/send code paths are
  implemented and unit-tested for their *failure* modes, but the *success*
  path against the real Telegram Bot API needs a human with a bot token).
- Real end-to-end email delivery test against a live SMTP account (same
  reasoning — the code path is implemented and tested for graceful failure
  when unconfigured; success-path delivery needs real SMTP credentials).
