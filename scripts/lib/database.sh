#!/usr/bin/env bash
# scripts/lib/database.sh — PostgreSQL detection, provisioning, migrations,
# and health checks. Works against whatever answers at DATABASE_URL —
# doesn't care whether that's the project's `docker compose` postgres
# service (the default local/dev shape — see Makefile `infra` target) or a
# natively installed one; it only starts/installs Postgres itself when
# nothing is reachable yet.
# shellcheck shell=bash

if [[ -n "${ARGUS_DATABASE_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_DATABASE_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

# shellcheck source=./python.sh
source "${ARGUS_LIB_DIR}/python.sh"   # provides ARGUS_VENV_PY

db_env() {
  # Pulls POSTGRES_* out of .env without exporting the whole file (values may
  # contain characters that upset a naive `source`). Redis's equivalent lives
  # in redis.sh (db_env / redis_env intentionally don't share state). Always
  # exits 0 — an unset key just yields an empty string, never a failure a
  # careless `VAR="$(db_env KEY)"` assignment could abort the caller on.
  [[ -f "$ARGUS_ENV_FILE" ]] || { echo ""; return 0; }
  grep -E "^${1}=" "$ARGUS_ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true
}

DB_HOST=""; DB_PORT=""; DB_USER=""; DB_PASSWORD=""; DB_NAME=""

db_load_config() {
  DB_HOST="$(db_env POSTGRES_HOST || true)"; DB_HOST="${DB_HOST:-localhost}"
  # The .env default is the docker-network hostname "postgres" — from a
  # native process that only resolves inside the compose network, so fall
  # back to localhost when it won't resolve here.
  if [[ "$DB_HOST" == "postgres" ]] && ! getent hosts postgres >/dev/null 2>&1; then
    DB_HOST="localhost"
  fi
  DB_PORT="$(db_env POSTGRES_PORT || true)"; DB_PORT="${DB_PORT:-5432}"
  DB_USER="$(db_env POSTGRES_USER || true)"; DB_USER="${DB_USER:-argus}"
  DB_PASSWORD="$(db_env POSTGRES_PASSWORD || true)"
  DB_NAME="$(db_env POSTGRES_DB || true)"; DB_NAME="${DB_NAME:-argus}"
}

# db_tcp_reachable — pure-bash TCP probe, no client tools required.
db_tcp_reachable() {
  { exec 3<>"/dev/tcp/${DB_HOST}/${DB_PORT}"; } 2>/dev/null && { exec 3>&-; return 0; } || return 1
}

# db_auth_ok — a real connect + auth check using the venv's psycopg (the same
# driver the app uses), not just a TCP probe. Falls back to `pg_isready`/
# `psql` if the venv isn't set up yet.
db_auth_ok() {
  if [[ -x "$ARGUS_VENV_PY" ]]; then
    local errfile rc=0
    errfile="$(mktemp "${ARGUS_TMP_DIR}/db-check.XXXXXX")"
    ARGUS_DB_HOST="$DB_HOST" ARGUS_DB_PORT="$DB_PORT" ARGUS_DB_USER="$DB_USER" \
      ARGUS_DB_PASSWORD="$DB_PASSWORD" ARGUS_DB_NAME="$DB_NAME" \
      "$ARGUS_VENV_PY" -c '
import os, sys
try:
    import psycopg
except ImportError:
    sys.exit(2)
try:
    with psycopg.connect(
        host=os.environ["ARGUS_DB_HOST"], port=os.environ["ARGUS_DB_PORT"],
        user=os.environ["ARGUS_DB_USER"], password=os.environ["ARGUS_DB_PASSWORD"],
        dbname=os.environ["ARGUS_DB_NAME"], connect_timeout=5,
    ) as conn:
        conn.execute("SELECT 1")
except Exception as exc:
    print(str(exc)[:200], file=sys.stderr)
    sys.exit(1)
' 2>"$errfile" || rc=$?
    [[ $rc -ne 0 ]] && cat "$errfile" >&2
    rm -f "$errfile"
    return $rc
  fi
  if has_cmd pg_isready; then
    PGPASSWORD="$DB_PASSWORD" pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1
  else
    db_tcp_reachable
  fi
}

db_check() {
  section "DATABASE"
  db_load_config
  if ! db_tcp_reachable; then
    fail "postgres not reachable at ${DB_HOST}:${DB_PORT}"
    return 1
  fi
  ok "postgres reachable at ${DB_HOST}:${DB_PORT}"
  if db_auth_ok; then
    ok "authentication + database '${DB_NAME}' OK (user '${DB_USER}')"
  else
    fail "connected to postgres but authentication/database check failed"
    return 1
  fi
  if [[ -x "$ARGUS_VENV_PY" && -d "${ARGUS_GATEWAY_DIR}/alembic" ]]; then
    local current head
    current="$(db_alembic current 2>/dev/null | awk '{print $1}' || true)"
    head="$(db_alembic_head || true)"
    if [[ -n "$current" && "$current" == "$head" ]]; then
      ok "migrations up to date ($current)"
    elif [[ -n "$current" ]]; then
      warn "migrations behind: at $current, head is $head — run: ./run.sh (applies pending migrations) or make migrate"
      return 1
    else
      warn "could not determine migration state (database may be empty — first run will initialize it)"
      return 1
    fi
  fi
  return 0
}

db_alembic() {
  ( cd "$ARGUS_GATEWAY_DIR" && DATABASE_URL="$(db_url)" "$ARGUS_VENV_DIR/bin/alembic" "$@" )
}

db_alembic_head() {
  ( cd "$ARGUS_GATEWAY_DIR" && "$ARGUS_VENV_DIR/bin/alembic" heads 2>/dev/null | awk '{print $1}' | head -n1 )
}

db_url() {
  echo "postgresql+asyncpg://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
}

# db_start — bring Postgres up using whatever mechanism is available:
# docker compose (preferred, matches the project's own dev convention), a
# native `systemctl start postgresql` if compose isn't in play, or — if
# neither is even installed yet — a native apt install as a last resort so
# declining/not-having Docker never leaves the app with no database at all.
db_start() {
  step "Starting PostgreSQL"
  db_load_config
  if db_tcp_reachable; then
    # TCP up is not the same as "usable" — a Docker volume initialized by an
    # earlier attempt with a different POSTGRES_PASSWORD keeps that old
    # password forever regardless of what .env says now (the official
    # postgres image only applies POSTGRES_PASSWORD on first init of an
    # empty data directory). Catch that here instead of letting it surface
    # three steps later as a raw psycopg traceback out of alembic.
    if db_auth_ok; then
      ok "postgres already reachable at ${DB_HOST}:${DB_PORT}"
      return 0
    fi
    fail "postgres is reachable at ${DB_HOST}:${DB_PORT} but rejected the credentials in .env for user '${DB_USER}'"
    warn "this almost always means an existing Postgres data volume was initialized with a DIFFERENT password than what's in .env now (e.g. a earlier partial/failed install attempt)."
    warn "fix: ./repair.sh --reset-database   (recreates the database from .env's current credentials — safe on a fresh/broken install; destroys existing DB content, so back up first if this instance has real data)"
    return 1
  fi
  if declare -F docker_detect >/dev/null 2>&1 && docker_detect; then
    info "starting postgres via docker compose…"
    if compose up -d postgres; then
      db_wait_ready && { db_auth_ok || { fail "postgres started but authentication failed — see ./repair.sh --reset-database"; return 1; }; return 0; }
    fi
  fi
  if [[ "$OS_HAS_SYSTEMD" == "1" ]] && systemctl list-unit-files 2>/dev/null | grep -q '^postgresql'; then
    info "starting native postgresql via systemd…"
    sudo_run systemctl start postgresql
    db_wait_ready && return 0
  fi
  # Neither Docker nor an already-installed native postgresql is available —
  # Docker may have been declined (docker_offer_install is interactive-only
  # by design). Rather than leave the app with no database path at all, fall
  # back to a native apt install; this is an unremarkable, expected server
  # admin action (unlike Docker group membership) so it doesn't need the
  # same explicit-confirmation gate.
  if has_cmd apt-get; then
    info "docker/postgresql not available — installing PostgreSQL natively via apt…"
    db_install_native && db_wait_ready && return 0
  fi
  fail "could not start postgres automatically — start it manually (docker compose up -d postgres, or systemctl start postgresql) and re-run"
  return 1
}

db_wait_ready() {
  local i
  for ((i = 0; i < 30; i++)); do
    db_tcp_reachable && return 0
    sleep 1
  done
  return 1
}

# db_install_native — apt-installs PostgreSQL and creates a dedicated,
# non-superuser application role + database (§16 "do not run using the
# postgres superuser"). Only used in --production native (no-Docker) setups.
db_install_native() {
  step "Installing PostgreSQL (native)"
  if has_cmd psql && has_cmd pg_isready; then
    ok "postgresql client/server tools already present"
  else
    pkg_install postgresql postgresql-contrib
  fi
  [[ "$OS_HAS_SYSTEMD" == "1" ]] && sudo_run systemctl enable --now postgresql

  db_load_config
  info "ensuring application role '${DB_USER}' and database '${DB_NAME}' exist (not using the postgres superuser for the app)"
  sudo_run -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | grep -q 1 || \
    sudo_run -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';"
  sudo_run -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1 || \
    sudo_run -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
  ok "postgresql role/database ready"
}

# db_reset_database — DESTRUCTIVE. Recreates the database from .env's
# current credentials, discarding whatever is currently stored. Exists
# specifically for the stale-Docker-volume-password-mismatch scenario
# db_start detects above (and equally for a native install whose role
# password has drifted from .env). Never called automatically — only from
# an explicit, confirm-gated caller (see repair.sh --reset-database).
db_reset_database() {
  step "Resetting PostgreSQL (destructive)"
  db_load_config
  if declare -F docker_detect >/dev/null 2>&1 && docker_detect; then
    info "removing the postgres container and its data volume…"
    ( cd "$ARGUS_ROOT" && $DOCKER_COMPOSE_CMD --env-file "$ARGUS_ENV_FILE" rm -sf postgres ) || true
    ( cd "$ARGUS_ROOT" && $DOCKER_COMPOSE_CMD --env-file "$ARGUS_ENV_FILE" down -v --remove-orphans postgres 2>/dev/null ) || true
    # `down -v` on a single service can leave the named volume behind on
    # older compose versions — remove it explicitly by its compose-computed
    # name so a stale password can never survive this reset.
    local proj vol
    proj="$(basename "$ARGUS_ROOT" | tr -cd 'a-zA-Z0-9_-' | tr '[:upper:]' '[:lower:]')"
    vol="${proj}_pgdata"
    docker volume rm -f "$vol" >/dev/null 2>&1 || true
    info "recreating postgres from current .env credentials…"
    compose up -d postgres || { fail "failed to recreate the postgres container"; return 1; }
    db_wait_ready || { fail "postgres did not come back up after reset"; return 1; }
    db_auth_ok || { fail "postgres still rejects .env credentials after a full volume reset — check POSTGRES_USER/POSTGRES_PASSWORD"; return 1; }
    ok "postgres reset — now using the credentials currently in .env"
    return 0
  fi
  if has_cmd psql; then
    info "recreating native role/database '${DB_USER}'/'${DB_NAME}' from current .env credentials…"
    sudo_run -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME};" || true
    sudo_run -u postgres psql -c "DROP ROLE IF EXISTS ${DB_USER};" || true
    sudo_run -u postgres psql -c "CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';"
    sudo_run -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
    db_auth_ok || { fail "postgres still rejects .env credentials after role/database recreation"; return 1; }
    ok "postgres role/database reset — now using the credentials currently in .env"
    return 0
  fi
  fail "neither docker compose nor a native psql client is available — cannot reset automatically"
  return 1
}

db_migrate() {
  step "Applying database migrations"
  [[ -x "$ARGUS_VENV_PY" ]] || die "Python environment not set up — run python_setup first"
  db_load_config
  # DATABASE_URL (has the DB password embedded) is exported into THIS
  # shell's environment and inherited by the child process normally — it
  # must never be interpolated into a command-line string, since run_cmd
  # logs the argv it ran (redacted best-effort, but env-var inheritance is
  # the only way that's guaranteed to never touch a log line at all).
  local prev_url="${DATABASE_URL:-}"
  export DATABASE_URL="$(db_url)"
  ( cd "$ARGUS_GATEWAY_DIR" && run_cmd_or_die "alembic upgrade head" -- "$ARGUS_VENV_DIR/bin/alembic" upgrade head )
  local rc=$?
  if [[ -n "$prev_url" ]]; then export DATABASE_URL="$prev_url"; else unset DATABASE_URL; fi
  [[ $rc -eq 0 ]] && ok "migrations applied"
  return $rc
}

db_repair() {
  step "Repairing database"
  db_load_config
  if ! db_tcp_reachable; then
    fix "postgres unreachable — attempting to start it"
    db_start
  fi
  if [[ -x "$ARGUS_VENV_PY" ]]; then
    fix "applying any pending migrations"
    db_migrate || warn "migration repair failed — inspect ${ARGUS_LOG_DIR}/install.log"
  fi
}
