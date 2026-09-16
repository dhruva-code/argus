# Ubuntu Server

Ubuntu Server (20.04+) is a primary, fully-tested target for
`install.sh`/`run.sh`/`doctor.sh` — this is the platform most of this
project's own install-time testing runs against.

## What to expect

- **A completely bare server is fine.** `install.sh` installs every system
  package it needs (`build-essential`, `bind9-dnsutils`, `python3-venv`,
  etc. — see `scripts/lib/package_manager.sh`), the Go/Node/Python
  runtimes, every security tool, PostgreSQL, Redis, and (optionally)
  Ollama, in one deterministic pass. See [INSTALL.md](INSTALL.md) for the
  exact ordering.
- **`dnsutils` note:** newer Ubuntu releases dropped the `dnsutils`
  transitional package entirely — `install.sh` installs
  `bind9-dnsutils` instead (the real package that actually ships
  `dig`/`nslookup`/`host`). If you're following older third-party Argus
  docs/scripts that reference `dnsutils` directly, use
  `bind9-dnsutils` instead on any recent Ubuntu release.
- **PostgreSQL/Redis via Docker if available, native apt otherwise.**
  `install.sh` offers to install Docker (defaults to yes when
  interactive); if you decline, or you're running `--non-interactive`
  without Docker preinstalled, it falls back to a native
  `apt install postgresql`/`redis-server` automatically — you always end
  up with a working database and queue either way.

## Install

```bash
sudo apt update
git clone https://github.com/<org>/argus.git Argus && cd Argus
./install.sh
./run.sh
```

Cloud images (AWS/GCP/Azure/DigitalOcean Ubuntu Server) work the same way
— just make sure outbound HTTPS (package downloads, Go module proxy,
Docker Hub / GitHub Releases for tool binaries, `ollama.com` if you want
local AI) isn't blocked by an egress firewall/security group before
running `install.sh`.

## First login

`install.sh` creates the bootstrap admin account automatically — there is
no setup wizard. Log in with:

```
Username (email): argus@argus.local
Password:         argus   (or your ARGUS_DEFAULT_ADMIN_PASSWORD, if set)
```

**Change this immediately** (Settings → Security → Change Password) — see
[AUTHENTICATION.md](AUTHENTICATION.md).

## Troubleshooting a fresh-server install

If a fresh install ends with Redis/PostgreSQL authentication failures,
that's almost always a stale Docker volume from an earlier partial
attempt (the official Postgres image only applies `POSTGRES_PASSWORD` on
first init of an *empty* data volume) — `install.sh`/`run.sh` now detect
and clearly report this instead of a raw traceback. Fix:

```bash
./repair.sh --reset-database
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the full diagnosis path
and `./doctor.sh --deep` for a complete health report.

## systemd

Ubuntu Server ships systemd by default; `install.sh` uses it to manage a
natively-installed PostgreSQL/Redis (`systemctl enable --now
postgresql`/`redis-server`) when Docker isn't in play. Argus's own
gateway/orchestrator/web processes are managed by `run.sh` itself
(detached background processes with pid files under `runtime/pids/`), not
systemd units — `run.sh status`/`stop`/`restart` is the control surface.
