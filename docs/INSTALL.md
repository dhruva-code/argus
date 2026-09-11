# Installation (self-hosted, single host)

Two supported paths: **native** (recommended — `install.sh`/`run.sh`, first-
class on Kali Linux and Parrot Security OS) and **Docker Compose**. Don't mix
them against the same `.env`/database — pick one.

## Native — `install.sh` / `run.sh` / `doctor.sh`

### Requirements

- A Debian/Ubuntu-family Linux (Kali, Parrot, Ubuntu, Debian primarily;
  Mint/Pop!_OS and other derivatives on a best-effort basis).
- Recommended: 4+ CPU cores, 8+ GB RAM, 250+ GB disk (`install.sh` warns, but
  does not refuse to run, below this — see `--force`).
- Outbound internet for tool/package downloads on first install.

### Steps

```bash
git clone <repo-url> Argus && cd Argus
./install.sh              # detects your OS, installs what's missing, generates .env
./run.sh                  # starts gateway + orchestrator + web
```

`install.sh` is idempotent — re-run it any time; it only installs/changes
what's actually missing or out of date. Flags:

```bash
./install.sh --check            # report only, no changes
./install.sh --non-interactive  # never prompt (for scripted/CI use)
./install.sh --production       # ARGUS_ENV=production, tighter defaults
./install.sh --upgrade          # backup, then update an existing install
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

First run: open the web URL and complete the setup wizard (creates the first
admin + organization) — same as the Docker path below. Something not
working? See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and run `./doctor.sh`.
Distro-specific notes: [KALI.md](KALI.md), [PARROT.md](PARROT.md).

Architecture reference — what `install.sh`/`run.sh`/`doctor.sh` are actually
built from (shared `scripts/lib/*.sh` modules, `config/tools.yaml`, etc.) is
documented at the top of each script and in the module headers themselves;
there's no separate design doc to keep in sync.

## Docker Compose

### Requirements

- Linux host, 4+ vCPU, 8 GB+ RAM, Docker + Docker Compose.
- Outbound internet for the initial image pull and for the security-tool
  binaries you want the orchestrator to use.

### Steps

```bash
git clone <repo-url> Argus && cd Argus
cp .env.example .env
```

Edit `.env` and replace every `CHANGE_ME`:

```bash
# generate strong secrets
openssl rand -hex 32                       # JWT_SECRET, ORCH_INTERNAL_TOKEN
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # SECRET_ENCRYPTION_KEY
```

Set `ARGUS_ENV=production`. Set `NEXT_PUBLIC_API_BASE_URL` and
`ARGUS_CORS_ORIGINS` to the URL users will hit.

```bash
make up          # builds and starts all services; runs migrations automatically
```

First run: open the web URL and complete the setup wizard (creates the first
admin + organization). The wizard is disabled automatically once a user exists;
you can also set `ARGUS_ALLOW_SETUP=false` afterwards.

Optional demo data:

```bash
ARGUS_ALLOW_SEED=true docker compose exec gateway python -m app.seed
```

## Security-tool binaries

The orchestrator looks in `ARGUS_TOOLS_BIN_DIR` (default `/usr/local/bin`) then
`$PATH`. Mount a directory of release binaries into the `orchestrator`
container, or bake them into a derived image:

```yaml
  orchestrator:
    volumes:
      - /opt/argus-tools:/usr/local/bin:ro
```

Recommended pinned versions are shown per tool in **Tool Manager**; run a health
check there after installing to confirm each is detected.

## Reverse proxy / TLS

The gateway and web servers speak plain HTTP. Put them behind a TLS-terminating
proxy (Caddy, nginx, Traefik). Only the `web` service needs to be public;
`gateway` can stay on the internal network (the browser reaches it through the
web app's `/api` proxy).

Example Caddyfile:

```
argus.example.com {
    reverse_proxy web:3000
}
```

## Backups

Back these up together — losing the encryption key makes stored tool API keys
unrecoverable:

- `postgres` volume (`pgdata`)
- `SECRET_ENCRYPTION_KEY` from `.env`
- `minio` volume (`miniodata`) once evidence/reports exist (M2+)

```bash
docker compose exec postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > argus-$(date +%F).sql.gz
```

## Upgrading

```bash
git pull
make up      # rebuilds images; entrypoint runs `alembic upgrade head`
```

## Data retention

Per-organization retention (raw scan data, screenshots, audit logs) is
configurable on the organization; the scheduled retention job that enforces it
ships with continuous monitoring in M6.
