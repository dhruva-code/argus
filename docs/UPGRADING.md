# Upgrading

```bash
git pull
./install.sh --upgrade
```

## What `--upgrade` does

1. **Backup** — `scripts/backup.sh` runs first: a `pg_dump --format=custom`
   of the database plus a copy of `.env` and `docker-compose.yml`, written to
   `backups/<UTC timestamp>/`. If `pg_dump` isn't available or the database
   is unreachable, you get a `[WARN]`, not a silent skip, and the upgrade
   continues with configuration-only backed up.
2. **Compatibility check** — the same checks `install.sh --check` runs:
   Python/Node/Go versions, system packages.
3. **Dependency upgrade** — `pip install -r requirements.txt` and `npm ci`,
   both idempotent (skipped entirely if the lockfile/requirements hash
   hasn't changed since the last install).
4. **Database migration** — `alembic upgrade head`, applied automatically.
5. **Tool validation** — `doctor.sh --tools`-equivalent health check.
6. **Service restart** — if the app was running, `run.sh restart` afterward
   picks up the new code.
7. **Post-upgrade verification** — the same summary `install.sh` always
   prints at the end.

## Rollback

If something goes wrong after an upgrade:

```bash
./run.sh stop
git log --oneline -5            # find the commit you were on before
git checkout <previous-commit>  # or: git reset --hard <previous-commit>

# restore the database from the pre-upgrade backup
pg_restore --clean -h localhost -U argus -d argus backups/<timestamp>/database.dump

./install.sh                    # reconcile the Python/Node environment with the reverted code
./run.sh
```

`.env` is never touched by an upgrade (see `scripts/env_setup.sh` — an
existing `.env` is only ever read from and additively appended to, never
overwritten), so no restore is normally needed there; `backups/<timestamp>/
env.backup` exists anyway in case you edited it since.

## What an upgrade never does automatically

- Overwrite your `.env`.
- Force-upgrade Python, Node, or Go past what's already installed and
  compatible.
- Run a system-wide package upgrade (`apt full-upgrade`).
- Delete scan data, findings, or projects.
- Skip the backup step silently — if it fails, you're told, and asked to
  back up manually before continuing (or to pass `--force` to proceed
  anyway, at your own judgment).

## Checking what will change before you upgrade

```bash
git fetch
git log HEAD..origin/main --oneline          # commits you'd pick up
git diff HEAD..origin/main -- apis/gateway/alembic/versions/   # new migrations
```
