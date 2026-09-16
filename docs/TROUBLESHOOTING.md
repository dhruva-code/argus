# Troubleshooting

Start here whenever something isn't working:

```bash
./doctor.sh
```

It runs the full diagnostic pipeline — OS, Python/Node/Go, Docker, database,
Redis, security tools, permissions, workers, ports, and network — and prints
one `[OK]`/`[WARN]`/`[FAIL]` line per check, grouped by category, ending in a
`SUMMARY` that names every failing category. Add `--fix` to have it attempt
the safe repairs on its own (missing pip/npm deps, a stopped Redis, a pending
migration, broken file permissions under the project, a stale PID file, a
stale `runtime/tmp/` file, a broken `__pycache__`), then re-checks:

```bash
./doctor.sh --fix
```

`doctor.sh` never touches project data, never wipes the database, never
disables the firewall, and never kills a process it didn't start itself.
Anything beyond that safe list gets a `[FAIL]` and an explanation instead of
a silent fix.

## Focused checks

```bash
./doctor.sh --tools          # security tool versions/health only
./doctor.sh --database       # Postgres connectivity + migration state
./doctor.sh --ollama         # Ollama service, model, real inference test
./doctor.sh --network        # default route, DNS, db/redis reachability
./doctor.sh --permissions    # ownership/writability of logs/runtime/backups
./doctor.sh --performance    # CPU/RAM/disk + per-service cpu/rss snapshot
./doctor.sh --workers        # is the orchestrator running
./doctor.sh --logs           # recent error lines across logs/*.log
./doctor.sh --deep           # everything above, in one pass
./doctor.sh --report         # writes a sanitized diagnostic archive to backups/
```

`--report` is what to attach when asking for help — it's been redacted of
every value that looks like a secret (passwords, tokens, keys, `user:pass@`
in URLs), but skim it yourself before sharing it anyway.

## Common problems

### "python3 not found" / "python3 X.Y is older than required"

Install Python 3.11+ through your distro's package manager, then re-run
`./install.sh`. It never silently installs a Python version on top of your
system one — for anything on `config/versions.yaml`'s minimum, install it
yourself and re-run.

### "npm ci failed" / frontend won't build

```bash
./doctor.sh --fix     # removes web/node_modules and reinstalls from the lockfile
```

If that doesn't help, check `node --version` against `config/versions.yaml`'s
`node_min` — Argus does not auto-upgrade Node.

### "go: command not found" but you know Go is installed

`install.sh` prefers whatever `go` is already on `$PATH`. If it's installed
somewhere non-standard, add it to `$PATH` yourself, or let `install.sh`
manage its own copy at `~/.local/go` (it never touches a working system Go).

### Postgres/Redis unreachable

```bash
./doctor.sh --database
./doctor.sh --network
```

If you're running the backing services via Docker Compose (the default —
see `make infra`), make sure the containers are up: `docker compose ps`. If
you switched to a natively-installed Postgres/Redis, `./doctor.sh --fix` will
try to start them via `systemctl`. Neither Docker nor a native install
available yet? `install.sh`/`run.sh` fall back to a native
`apt install postgresql`/`redis-server` automatically — you should never
be left with no database path at all.

### "postgres already reachable" immediately followed by a password-authentication traceback

```
[OK]   postgres already reachable at localhost:5432
==> Applying database migrations
...
psycopg.OperationalError: ... FATAL:  password authentication failed for user "argus"
```

This means something is genuinely listening on port 5432, but it rejects
the credentials currently in `.env` — almost always a **stale Docker
volume** from an earlier partial/failed install attempt: the official
Postgres image only applies `POSTGRES_PASSWORD` the first time it
initializes an *empty* data directory, so a volume created with an older
password keeps that password forever, even after `.env` changes.
`db_start`/`run.sh` detect this directly now (real auth check, not just a
TCP probe) and report it clearly instead of letting it surface here. Fix:

```bash
./repair.sh --reset-database
```

**This is destructive** — it recreates the database from `.env`'s current
credentials, discarding whatever was in it. Back up first
(`./scripts/backup.sh`) if this instance has real data you need to keep.
If you'd rather not lose that data, the alternative is finding out what
password actually *is* baked into the volume (check any earlier `.env`
backups under `backups/`) and editing `.env` to match it instead of
resetting.

### "orchestrator binary not built"

```bash
cd orchestrator && go build -o bin/orchestrator ./cmd/orchestrator
```

`run.sh start` does this automatically when Go is available; the message
means Go itself is missing — run `./install.sh`.

### A tool shows `[FAIL]` in `./doctor.sh --tools`

The binary either isn't installed, isn't on `$PATH` / in
`ARGUS_TOOLS_BIN_DIR`, or its version is below `minimum_version` in
`config/tools.yaml`. `./doctor.sh --fix` reinstalls anything unhealthy via
that tool's configured `install_method`. **A scanner failure is never
silently reported as "0 findings"** — the scan job log names the tool and
the reason instead.

### Port already in use

```
[WARN] gateway port 8000 — already in use (pid 1234) and it is not our own gateway service
```

Something else is bound to that port. `run.sh`/`doctor.sh` never kill a
process they don't own — stop whatever's using the port, or change
`ARGUS_API_PORT`/`ARGUS_WEB_PORT` in `.env` and restart.

### `.env still has placeholder values for: ...`

`install.sh` generates fresh random secrets on first run and never
overwrites an existing `.env`. If you see this, either edit those keys by
hand or delete `.env` and re-run `./install.sh` to regenerate one from
scratch (you'll lose any customization you'd made — back it up first with
`./scripts/backup.sh`).

### Disk / memory warnings

```
[WARN] disk usage 82% — above warning threshold (80%)
```

Thresholds live in `config/system.yaml`. At 95% the platform is meant to
pause new artifact-heavy scans rather than run the disk out entirely —
findings are never auto-deleted to make room; free space or expand storage.

### Ollama / Qwen not working

```bash
./doctor.sh --ollama
```

AI is always optional — every check here failing just means AI analysis
falls back to the deterministic heuristic; nothing else in Argus is
affected. See [AI.md](AI.md) for install/model-sizing/inference-timeout
troubleshooting in depth.

### A scan job is stuck / a worker looks alive but isn't progressing

```bash
./doctor.sh --workers
./run.sh logs orchestrator
```

Check the Scan Jobs tab in the web UI for the job's phase and last
heartbeat. A job that's genuinely stuck can be cancelled from there;
`doctor.sh` does not cancel scan jobs itself (that's app-level state, not a
"safe automatic repair").

## Logs

```
logs/install.log     # everything install.sh did
logs/doctor.log       # everything doctor.sh did
logs/runtime.log      # run.sh's own actions (start/stop/status)
logs/gateway.log      # gateway stdout/stderr
logs/orchestrator.log # orchestrator stdout/stderr
logs/web.log          # frontend stdout/stderr
```

Every line is redacted before being written — passwords, tokens, API keys,
cookies, and `user:pass@host`-shaped URLs are replaced with
`***REDACTED***`. If you ever find that untrue, that's a bug — report it.

## Still stuck?

```bash
./run.sh self-test
```

Runs the gateway and orchestrator test suites (against local fixtures — no
public infrastructure is ever touched) plus live infra/tool checks, and
reports pass/fail per component.
