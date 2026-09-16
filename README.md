# Argus

**Attack Surface Management & authorized bug-bounty reconnaissance platform.**

Argus manages bug-bounty programs and security-assessment engagements: it holds an
explicit authorized scope for every project, runs reconnaissance in clearly
separated phases through a durable job system, correlates and deduplicates the
results into a single normalized asset graph, tracks potential vulnerabilities
through an evidence-based verification workflow, and produces professional
reports.

> **Authorized use only.** Every active operation requires an explicit target
> scope. The orchestration engine rejects any job — and the HTTP engine rejects
> any individual request — that falls outside the configured scope, the SSRF
> policy, or the rate limits. This is a defensive / authorized-assessment
> platform, not an exploitation framework.

---

## Status — Milestones 1–7 (M6 complete, M7 partial)

**Milestones 2–7** deliver the full 12-phase reconnaissance & scanning pipeline
(incl. opt-in active injection fuzzing), the finding priority + verification
engine, assessment reports (MD/JSON/CSV/HTML/PDF), exposure-delta + scheduled
continuous monitoring with notifications, scan-history management, an
attack-surface graph, program analytics, read-only AI-assisted analysis,
Prometheus metrics, a Helm chart, and an optional Vault secret backend.
A `recon.scan` job runs up to twelve phases:

- **Passive & active subdomain enumeration** (Subfinder, assetfinder, DNSX) with
  wildcard detection and permutation bruteforce.
- **Alive-host detection** (HTTPX) — only in-scope hosts whose resolved IPs pass
  the SSRF guard are probed.
- **WAF / CDN & origin intel** — fingerprints the edge (Cloudflare, Akamai,
  CloudFront, Imperva…) from response headers and flags exposed origin IPs that
  bypass it.
- **Infrastructure mapping** — ASN / netblock / cloud provider / PTR for every
  resolved IP (Team Cymru DNS, no API key), building the
  domain → IP → netblock → ASN graph.
- **Virtual-host enumeration** — Host-header probing with baseline comparison and
  default / interesting / potential-internal classification.
- **URL & endpoint discovery** (Katana, gau, the Wayback Machine's CDX
  archive, robots/sitemap/OpenAPI/GraphQL) with URL normalization, **route
  templating** (`/users/123` → `/users/{id}`) and structural deduplication —
  a URL already found by one source is never reprocessed by another. See
  [docs/WAYBACK.md](docs/WAYBACK.md).
- **JavaScript analysis & secret extraction** (TruffleHog, Gitleaks + custom
  detectors) — discovered `*.js` is fetched through the guarded HTTP engine,
  scanned for secrets and mined for endpoints, domains and source maps. The full
  value is shown to authorized operators for validation and is **also encrypted
  at rest**; access is gated by `finding.read` and every triage action is audited.
- **Directory & sensitive-file discovery** (ffuf) with a 15-rule sensitivity
  classifier (`.git` / `.env` / backups / actuator / admin panels → critical…none).
- **Source-code intelligence** — GitHub org repos, IaC detection, TruffleHog over
  non-fork repos, correlated back to the project.
- **Port scan & service fingerprinting** (Naabu connect-scan + nmap `-sV`) of the
  IPs in-scope hosts resolve to, SSRF-guarded and bounded.
- **Automated vulnerability scanning** (Nuclei) with a three-level
  passive / safe-verify / manual-review model — `dos` / `intrusive` / `fuzz` /
  `brute` templates are always excluded — and template-version tracking.
- **False-positive reduction & verification engine** — every match is
  deduplicated and confidence-scored (out-of-band confirmation, matchers,
  extracted values, CVE metadata, template reputation); auto-classified
  confirmed / probable / needs-review; a human triage decision is never
  overwritten by a later scan.
- **Priority engine** — a 0-100 risk score per finding (severity × confidence ×
  triage status × project risk profile) drives the default ranking.
- **Active injection testing** (opt-in `vuln_level: aggressive` + `injection_ack`)
  — Nuclei DAST fuzzes in-scope parameters for SQLi / command injection / CRLF /
  LFI / SSTI / SSRF / open-redirect; `dos` templates stay excluded.

Beyond the pipeline: a **unified finding engine** (secrets, sensitive paths and
dangerously-exposed services become findings too), **professional assessment
reports** (MD/JSON/CSV/HTML, and a multi-section branded **PDF** — cover page,
table of contents, severity chart, full per-finding detail, sanitized
evidence; secret values always excluded — see
[docs/REPORTS.md](docs/REPORTS.md)), **exposure-delta** + **scheduled
monitoring** with Slack/webhook/email **notifications**, **data-retention**
enforcement, **scan-history management**, an interactive **attack-surface graph**,
**program analytics**, optional **AI-assisted analysis** — local (Ollama +
Qwen, installed automatically) or hosted (Anthropic) — covering project
summaries, per-phase strategy notes, and automatic findings/secrets
triage with default-view false-positive suppression (configured under
Settings → AI & Analysis; see [docs/AI.md](docs/AI.md) for installation
and [docs/AI_ANALYSIS.md](docs/AI_ANALYSIS.md) for the pipeline),
`/api/metrics` for Prometheus, a **Helm chart** (`deploy/helm/argus`), and
an optional **Vault Transit** secret backend.

Every discovery flows through the **Asset Identity Engine** — deduplicated by
`(project, type, value)`, with source attribution, first/last-seen and
evidence-based confidence scoring. The project **Assets**, **Infrastructure**
(incl. open ports), **Endpoints**, **Secrets & Source** and **Findings** tabs
present the filterable inventories.

Milestone 1 delivers the platform spine as a working application:

| Area | M1 deliverable |
|---|---|
| Auth | Single bootstrap super-admin account, JWT access/refresh, Argon2 password hashing, optional TOTP MFA, IP-based login rate limiting — see [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) |
| Authorization | Single-role model (every account holds every permission), enforced per route in API middleware regardless |
| Tenancy | Organization → Project isolation on every query |
| Projects | Full project model: program metadata, RoE, risk profile, schedule |
| Scope engine | allow/deny rules — domain, subdomain, wildcard, IPv4/IPv6 CIDR, ASN, URL, regex, port & path scoping. Authoritative Go implementation + mirrored Python implementation, both tested against one shared fixture set. |
| Job system | Durable queue (Redis), state machine, pause/resume/cancel, worker heartbeats, checkpointing, emergency stop-all |
| Orchestrator | Go service: queue consumer, scope guard, SSRF guard, tool plugin runner, log streaming |
| Tool manager | Plugin interface, version detection, health checks, enable/disable, encrypted API-key config |
| Dashboard | Executive dashboard with live cards + charts |
| Frontend | Next.js app: dashboard, projects, scope editor, tool manager, job viewer with live logs, settings, audit log |
| CLI | `argus` — same REST API as the web UI |
| Ops | Docker Compose, Postgres migrations, seed/demo data, OpenAPI docs |

Later milestones add the 13-phase recon/scan pipeline, finding engine,
verification, reporting, continuous monitoring, the asset graph, and AI-assisted
analysis. See [docs/ROADMAP.md](docs/ROADMAP.md).

---

## Architecture

```
                 ┌───────────────┐
   Browser ───►  │  web (Next.js) │
                 └───────┬───────┘
                         │ REST + SSE
                 ┌───────▼────────┐        ┌────────────┐
   argus CLI ──► │ gateway API    │◄──────►│ PostgreSQL │
                 │ (FastAPI)      │        └────────────┘
                 └───┬────────┬───┘        ┌────────────┐
                     │        │  enqueue   │   Redis    │
                     │        └───────────►│  queue+bus │
                     │                     └─────┬──────┘
                     │ artifacts                 │ consume
                 ┌───▼─────┐          ┌──────────▼──────────┐
                 │  MinIO  │◄─────────┤ orchestrator (Go)   │
                 │  (S3)   │          │  scope + SSRF guard │
                 └─────────┘          │  tool plugin runner │
                                      └─────────────────────┘
```

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Quick start

### Native (recommended — Ubuntu Server, Kali Linux, Parrot Security OS)

`install.sh` detects your distro, installs every required language/tool,
sets up PostgreSQL+Redis (Docker if available, native apt otherwise),
generates `.env`, applies migrations, creates the bootstrap admin account,
and installs/configures local AI (Ollama + Qwen). `run.sh` then
starts/stops the three application processes with proper PID tracking and
graceful shutdown. `doctor.sh` diagnoses, and `repair.sh` fixes, anything
that goes wrong; `update.sh` pulls and applies new commits in place.

```bash
git clone https://github.com/<org>/argus.git Argus && cd Argus
./install.sh                  # first-time setup — safe to re-run any time
./run.sh                      # start gateway + orchestrator + web
open http://localhost:3000
```

Log in with the bootstrap credentials (`argus@argus.local` / `argus` by
default — **change this immediately**, see
[docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)). There is no setup
wizard or self-registration.

If something isn't working: `./doctor.sh --deep` (or `./repair.sh` for
automatic fixes). See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md),
[docs/UBUNTU.md](docs/UBUNTU.md), [docs/KALI.md](docs/KALI.md), and
[docs/PARROT.md](docs/PARROT.md).

### Docker Compose

```bash
git clone https://github.com/<org>/argus.git Argus && cd Argus
cp .env.example .env          # review settings — POSTGRES_PASSWORD/ARGUS_DEFAULT_ADMIN_PASSWORD default to "argus", change for anything but local testing
make up                       # postgres, redis, minio, gateway, orchestrator, web
docker compose exec gateway python -m app.bootstrap_admin   # creates the bootstrap admin
make seed                     # optional: demo project + demo data
open http://localhost:3000
```

Bootstrap login is `argus@argus.local` / `ARGUS_DEFAULT_ADMIN_PASSWORD`
(default `argus`) — see [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md).
Demo *project* data (not a demo account) is optionally added by `make seed`
when `ARGUS_ALLOW_SEED=true`.

For local development without rebuilding containers on every change, see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

---

## Documentation

| Doc | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Services, data model, request flow, scope-engine parity |
| [SECURITY.md](docs/SECURITY.md) | Threat model, SSRF layer, command-injection prevention, hardening |
| [INSTALL.md](docs/INSTALL.md) | Native + Docker install, secrets, reverse proxy, backups |
| [AUTHENTICATION.md](docs/AUTHENTICATION.md) | Bootstrap admin model, sessions, MFA, rate limiting |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | `doctor.sh` usage, common failures and fixes |
| [UBUNTU.md](docs/UBUNTU.md) | Ubuntu Server-specific install notes |
| [KALI.md](docs/KALI.md) | Kali Linux-specific install notes |
| [PARROT.md](docs/PARROT.md) | Parrot Security OS-specific install notes |
| [UPGRADING.md](docs/UPGRADING.md) | `install.sh --upgrade`, `update.sh`, backups, rollback |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Local dev loop, running tests, code layout |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Docker Compose, systemd, and Kubernetes deployment |
| [API.md](docs/API.md) | REST API overview; full schema at `/api/docs` |
| [WAYBACK.md](docs/WAYBACK.md) | Wayback Machine URL discovery: how it works, scope, limitations |
| [AI.md](docs/AI.md) | Ollama/Qwen installation, model sizing, health checks |
| [AI_ANALYSIS.md](docs/AI_ANALYSIS.md) | AI pipeline: what's analyzed, when, privacy/redaction, what's sent where |
| [REPORTS.md](docs/REPORTS.md) | Report formats, PDF structure, branding, redaction |
| [ROADMAP.md](docs/ROADMAP.md) | Milestone plan M1–M7 |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Branching, review, plugin authoring |

## License

MIT — see [LICENSE](LICENSE).
