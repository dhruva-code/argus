# Installation (self-hosted, single host)

## Primary, tested path: native (`install.sh` / `run.sh` / `doctor.sh`)

This is the deployment mode this project is actually built, tested, and
supported against: the gateway, orchestrator, and web processes run
natively on the host; PostgreSQL and Redis run via Docker Compose when
Docker is available, falling back automatically to a native apt install
when it isn't (see `scripts/lib/database.sh`/`redis.sh`). **Don't mix**
native app processes with the full `docker compose up` stack (which also
builds `gateway`/`orchestrator`/`web` containers) against the same
`.env`/database — pick one. A secondary, community-usable Docker Compose
path (running the app itself in containers too) is documented below for
those who prefer it, but it receives less day-to-day testing.

### Requirements

- A Debian/Ubuntu-family Linux — **Ubuntu Server**, **Kali Linux**, and
  **Parrot Security OS** are first-class (`install.sh` detects all three
  automatically); Debian/Mint/Pop!_OS and other derivatives work on a
  best-effort basis. See [UBUNTU.md](UBUNTU.md), [KALI.md](KALI.md),
  [PARROT.md](PARROT.md).
- Recommended: 4+ CPU cores, 8+ GB RAM, 250+ GB disk (`install.sh` warns,
  but does not refuse to run, below this — see `--force`). Local AI
  (Ollama + Qwen) is optional and picks a smaller model automatically on
  lower-RAM hosts — see [AI.md](AI.md).
- Outbound internet for tool/package downloads on first install.

### Steps

```bash
git clone https://github.com/<org>/argus.git Argus && cd Argus
./install.sh              # detects OS, installs everything, generates .env, bootstraps the admin account
./run.sh                  # starts gateway + orchestrator + web
```

`install.sh` installation order (deterministic, every time):

```
OS detection → system dependencies → Python/Go/Node → application
dependencies → security tools → PostgreSQL → Redis → database
initialization → database migrations → application configuration →
bootstrap admin → Ollama → Qwen model → health checks → final validation
```

It is fully idempotent — re-run it any time; it only installs/changes
what's actually missing or out of date, and never starts application
workers before Redis/the database are confirmed ready. Flags:

```bash
./install.sh --check            # report only, no changes
./install.sh --repair           # alias for a full install/repair pass
./install.sh --upgrade          # backup, then update an existing install
./install.sh --non-interactive  # never prompt (for scripted/CI use)
./install.sh --production       # ARGUS_ENV=production, tighter defaults
./install.sh --no-ai            # skip Ollama/Qwen (local AI is optional)
./install.sh --force            # proceed despite hardware warnings
```

`run.sh` is the control interface once installed:

```bash
./run.sh                  # same as `start`
./run.sh stop [--force]
./run.sh restart
./run.sh status
./run.sh logs [gateway|orchestrator|web]
./run.sh self-test
```

`doctor.sh` is the diagnostic/repair tool — run it any time something
looks wrong:

```bash
./doctor.sh              # full health check (PostgreSQL, Redis, auth,
                          # workers, scheduler, tools, Ollama/Qwen, ...)
./doctor.sh --deep       # + performance snapshot + recent log errors
./doctor.sh --fix        # safe automatic repairs, then re-checks
```

`repair.sh` fixes common issues safely (never wipes project data), plus
explicit destructive resets for the "database/Redis reachable but rejects
the credentials in `.env`" scenario:

```bash
./repair.sh                    # safe automatic repairs
./repair.sh --reset-database   # DESTRUCTIVE — recreate DB from .env's current creds
./repair.sh --reset-redis      # DESTRUCTIVE — recreate/flush Redis
```

`update.sh` pulls the latest commits and applies them in place — no
re-clone needed:

```bash
./update.sh              # git pull + rebuild what changed + migrate + restart
./update.sh --check      # report what would change, no changes made
```

### First login

`install.sh` creates a bootstrap super-admin account automatically —
there is no setup wizard to click through:

```
Username (email): argus@argus.local
Password:         argus   (or your own, if ARGUS_DEFAULT_ADMIN_PASSWORD
                            was set in .env before installing)
```

**Change this password immediately after first login** (Settings →
Security → Change Password) — see [AUTHENTICATION.md](AUTHENTICATION.md).

Something not working? See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and
run `./doctor.sh --deep`.

## Secondary: Docker Compose (full stack in containers)

### Requirements

- Linux host, 4+ vCPU, 8 GB+ RAM, Docker + Docker Compose.
- Outbound internet for the initial image pull and for the security-tool
  binaries you want the orchestrator to use.

### Steps

```bash
git clone https://github.com/<org>/argus.git Argus && cd Argus
cp .env.example .env
```

Edit `.env` and replace every `CHANGE_ME` (`POSTGRES_PASSWORD` and
`ARGUS_DEFAULT_ADMIN_PASSWORD` already default to `argus` — change those
too for anything beyond local testing):

```bash
# generate strong secrets
openssl rand -hex 32                       # JWT_SECRET, ORCH_INTERNAL_TOKEN
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # SECRET_ENCRYPTION_KEY
```

Set `ARGUS_ENV=production`. Set `NEXT_PUBLIC_API_BASE_URL` and
`ARGUS_CORS_ORIGINS` to the URL users will hit.

```bash
make up          # builds and starts all services; runs migrations automatically
docker compose exec gateway python -m app.bootstrap_admin   # creates the bootstrap admin
```

Optional demo data:

```bash
ARGUS_ALLOW_SEED=true docker compose exec gateway python -m app.seed
```

## Security-tool binaries

The orchestrator looks in `ARGUS_TOOLS_BIN_DIR` (default `~/.local/bin`
native, `/usr/local/bin` in the Docker Compose path) then `$PATH`. For
Docker Compose, mount a directory of release binaries into the
`orchestrator` container, or bake them into a derived image:

```yaml
  orchestrator:
    volumes:
      - /opt/argus-tools:/usr/local/bin:ro
```

Recommended pinned versions are shown per tool in **Tool Manager**; run a
health check there (or `./doctor.sh --tools`) after installing to confirm
each is detected.

## Local AI (Ollama + Qwen)

Optional, installed automatically by `install.sh` unless declined or
`--no-ai` is passed. See [AI.md](AI.md) for model sizing, health checks,
and troubleshooting.

## Reverse proxy / TLS

The gateway and web servers speak plain HTTP. Put them behind a
TLS-terminating proxy (Caddy, nginx, Traefik). Only the `web` service
needs to be public; `gateway` can stay on the internal network (the
browser reaches it through the web app's `/api` proxy).

Example Caddyfile:

```
argus.example.com {
    reverse_proxy web:3000
}
```

## Backups

`./update.sh` and `install.sh --upgrade` both back up automatically
before making changes (`scripts/backup.sh`). Back these up together —
losing the encryption key makes stored tool API keys unrecoverable:

- `postgres` volume (`pgdata`), or the native data directory
- `SECRET_ENCRYPTION_KEY` from `.env`
- `minio` volume (`miniodata`) once evidence/reports exist

```bash
docker compose exec postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > argus-$(date +%F).sql.gz
```

## Upgrading

Native: `./update.sh` (pulls, rebuilds only what changed, migrates,
restarts — see above). Docker Compose:

```bash
git pull
make up      # rebuilds images; entrypoint runs `alembic upgrade head`
```

## Data retention

Per-organization retention (raw scan data, screenshots, audit logs) is
configurable on the organization; the scheduled retention job that
enforces it ships with continuous monitoring.
