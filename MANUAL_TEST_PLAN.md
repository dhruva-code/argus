# Manual Test Plan

For the owner to run through by hand before deciding to make the repository
public. Automated coverage (98 gateway pytest cases, the full orchestrator
Go test suite, and `scripts/tests/*.sh`) already exercises the logic paths
below — this plan is about confirming the *real* end-to-end experience,
including things automation can't easily check (actual email delivery,
actual Telegram delivery, actual fresh-OS installation).

Record results directly in this file (copy the table, fill in one row per
test) or in a separate tracking doc — either way, use these statuses:

```
PASS          — worked exactly as described
FAIL          — did not work; describe what happened
NOT TESTED    — skipped (say why)
OBSERVATION   — worked, but something worth noting (UX rough edge, etc.)
```

## 1. Installation

| # | Test | Steps | Expected |
|---|---|---|---|
| 1.1 | Fresh Kali install | `git clone` → `./install.sh` on a clean Kali VM | Completes; `./doctor.sh` shows no `[FAIL]` (dnsutils/apt items aside if sudo is restricted) |
| 1.2 | Fresh Parrot install | Same, on Parrot Security OS | Same |
| 1.3 | Re-run install.sh | `./install.sh` a second time immediately after 1.1 | No unnecessary reinstalls — "already satisfies", "up to date" lines throughout |
| 1.4 | `./install.sh --check` | Run before any install | Reports what's missing, changes nothing |
| 1.5 | `./doctor.sh --deep` | After install | All core checks pass; performance snapshot + recent-errors sections print |

## 2. Startup / shutdown / repair

| # | Test | Steps | Expected |
|---|---|---|---|
| 2.1 | `./run.sh start` | From a stopped state | gateway + orchestrator + web all come up; URLs printed |
| 2.2 | `./run.sh status` | While running | All three show `running` with a PID |
| 2.3 | `./run.sh stop` | While running | Graceful stop, orchestrator first then web then gateway; `ps aux` shows nothing left over (no orphaned `next-server`, etc.) |
| 2.4 | `./run.sh restart` | — | Stops then starts cleanly |
| 2.5 | `./run.sh logs gateway` | While running | Tails `logs/gateway.log` live |
| 2.6 | `./run.sh self-test` | While running | DB/Redis/API/worker/scheduler/tools all PASS; gateway + orchestrator test suites run and pass |
| 2.7 | `./doctor.sh --fix` | After intentionally breaking something safe (e.g. `rm -rf apis/gateway/.venv`) | Detects it, reinstalls, re-checks clean |

## 3. Registration / login / email verification

| # | Test | Steps | Expected |
|---|---|---|---|
| 3.1 | Register (Gmail/etc.) | `/register` with a normal address | Account created message; cannot log in yet |
| 3.2 | **Register with Proton** | `/register` with a real `@proton.me` or `@protonmail.com` address | Same as 3.1 — no special-casing, no rejection |
| 3.3 | Verification email arrives | Check inbox (requires SMTP configured — see §4) | Email received, link works |
| 3.4 | Verify | Click the link / visit `/verify-email?token=...` | Account activated, auto-logged-in |
| 3.5 | Login before verifying | Try logging in before 3.4 | Rejected with a clear "email not verified" message |
| 3.6 | Forgot password | `/forgot-password` → email → `/reset-password` | New password works; old one doesn't; other sessions signed out |
| 3.7 | MFA enroll | Settings → Security → Set up authenticator | QR/secret shown, confirms with a real authenticator app code |
| 3.8 | MFA login | Log out, log back in | Prompted for MFA code, succeeds with a valid one, fails with an invalid one |
| 3.9 | Sessions list | Settings → Account | Shows the current session (and any others) with IP/user agent |
| 3.10 | Revoke a session | Log in from a second browser, revoke it from the first | Second browser's session stops working |
| 3.11 | Account export | Settings → Account → Export account data | Downloads a JSON file with your account data, no other users' data |
| 3.12 | Account deletion (solo workspace) | Settings → Account → Delete account | Requires password + typed email; deletes account and its personal org |
| 3.13 | Account deletion (shared org, sole admin) | Try deleting an account that's the only admin of an org with other members | Blocked with a clear message to promote another admin first |

## 4. Email notifications

Requires a real SMTP account configured in `.env` (`SMTP_HOST` etc. — any
provider works, Proton Mail Bridge/SMTP included if you route through it).

| # | Test | Steps | Expected |
|---|---|---|---|
| 4.1 | Test email | Settings → Notifications → Send test email | Arrives in inbox within a minute |
| 4.2 | Unconfigured SMTP | With `SMTP_HOST` unset, send a test email | UI reports "not configured" — does not claim success |
| 4.3 | Scan completion email | Enable "Scan completed", run a scan against a local test target | Email arrives after the scan finishes, with correct asset/finding counts |
| 4.4 | Critical finding email | Enable "Critical finding", get a scan to surface one (e.g. against OWASP Juice Shop) | Email arrives promptly |
| 4.5 | Disable a notification type | Turn off "New asset" | No email for that event type going forward |
| 4.6 | Quiet hours | Set quiet hours covering "now"; trigger a non-critical event | No email until quiet hours end |
| 4.7 | Quiet hours + critical override | Same, but trigger a critical finding with override enabled | Email arrives immediately despite quiet hours |

## 5. Telegram notifications

Requires a real Telegram bot (`@BotFather` → `/newbot` → token in
`TELEGRAM_BOT_TOKEN`, plus `TELEGRAM_BOT_USERNAME`).

| # | Test | Steps | Expected |
|---|---|---|---|
| 5.1 | Pair | Settings → Notifications → Connect Telegram → open bot → send the code | Status flips to "Connected" within ~20s (poller interval) |
| 5.2 | Test message | Send test Telegram message | Arrives in the chat |
| 5.3 | Scan completion | Enable it, run a scan | Message arrives formatted per §12's example, no secrets/tokens in the text |
| 5.4 | Critical finding | Same as 4.4 but via Telegram | Arrives |
| 5.5 | Disable Telegram | Turn off "Enable Telegram notifications" | No further messages |
| 5.6 | Disconnect | Settings → Notifications → Disconnect | Status flips back to "not linked"; re-pairing works again |
| 5.7 | Pair without a bot configured | Unset `TELEGRAM_BOT_TOKEN`, try "Connect Telegram" | UI clearly states the bot isn't configured server-side, doesn't pretend it will work |

## 6. Core platform (regression — already covered by earlier milestones, spot-check here)

| # | Test | Steps | Expected |
|---|---|---|---|
| 6.1 | Project creation | Create a project, set scope | Works |
| 6.2 | Scan against a local test target | Run "Standard Bug Bounty" against a local vulnerable app (Juice Shop/WebGoat) — **not** a public site without explicit authorization | Recon phases complete; assets/endpoints populate |
| 6.3 | Injection Discovery scan | Run against the same local target with `injection_ack` confirmed | Injection Testing tab populates; findings correlate |
| 6.4 | Worker crash resilience | Kill the orchestrator process mid-scan (`kill -9`), restart via `./run.sh start` | Job shows a clear failed/partial state, not a fake "0 findings" success |
| 6.5 | Report generation | Generate MD/HTML/PDF/CSV/JSON reports | All formats produce output; version number appears in MD/HTML/PDF |
| 6.6 | Project deletion | Settings → Danger Zone → soft delete → permanent delete | Preview shows accurate counts; permanent delete leaves nothing orphaned (spot-check DB) |
| 6.7 | Upgrade path | `git pull` (once there's a newer commit) → `./install.sh --upgrade` | Backup runs first, migrations apply, app restarts working |

## 7. System Health / diagnostics

| # | Test | Steps | Expected |
|---|---|---|---|
| 7.1 | System Health page | Navigate to it in the sidebar | DB/Redis/Orchestrator cells all green when everything's running |
| 7.2 | `/api/ready` | `curl http://localhost:8000/api/ready` | `{"ready": true, ...}` when healthy |
| 7.3 | `/api/version` | `curl http://localhost:8000/api/version` | Returns `0.9.0-private` |
| 7.4 | Diagnostic report | `./doctor.sh --report` | Archive written to `backups/`; skim it — confirm no secrets appear |

---

## Sign-off

Once every row above is PASS or an accepted OBSERVATION (no unresolved
FAILs), proceed to the release checklist in `CHANGELOG.md` /
`FINALIZATION_STATUS.md` before making any decision about public release.
That decision remains the owner's alone — nothing in this codebase changes
repository visibility automatically.
