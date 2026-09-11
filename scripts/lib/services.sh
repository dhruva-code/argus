#!/usr/bin/env bash
# scripts/lib/services.sh — native-mode process management for the three
# Argus processes (gateway, orchestrator, web). PID-tracked, log-redirected,
# graceful-SIGTERM-then-SIGKILL shutdown — not a bare `cmd &`.
#
# The gateway's FastAPI lifespan and the orchestrator's signal.NotifyContext
# already do the real graceful-shutdown work (stop consuming new jobs,
# checkpoint in-flight ones, close cleanly) when sent SIGTERM — this module's
# job is just to track PIDs reliably and give that shutdown time to finish
# before escalating.
#
# "workers" and "scheduler" are not separate OS processes in this
# architecture: the orchestrator's worker pool is goroutines inside the
# orchestrator process, and the scheduler is an asyncio task inside the
# gateway process (see app/services/scheduler.py) — so there is no separate
# service entry for either; status output says so explicitly rather than
# implying a process that doesn't exist.
# shellcheck shell=bash

if [[ -n "${ARGUS_SERVICES_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_SERVICES_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"
# shellcheck source=./python.sh
source "${ARGUS_LIB_DIR}/python.sh"

ARGUS_SERVICE_ORDER=(gateway orchestrator web)

_service_env() {
  # Export every KEY=value from .env into the current shell (used only for
  # the subprocess we're about to launch — does not leak into the parent).
  [[ -f "$ARGUS_ENV_FILE" ]] || return 0
  set -a
  # shellcheck disable=SC1090
  source "$ARGUS_ENV_FILE"
  set +a
}

_service_native_url_fixups() {
  # .env's defaults point at docker-network hostnames (postgres/redis/minio)
  # for the docker-mode services. When these processes run natively they need
  # localhost instead — mirrors what database.sh/redis.sh already do for
  # their own checks.
  [[ "${POSTGRES_HOST:-}" == "postgres" ]] && export POSTGRES_HOST="localhost"
  if [[ "${DATABASE_URL:-}" == *"@postgres:"* ]]; then
    export DATABASE_URL="${DATABASE_URL/@postgres:/@localhost:}"
  fi
  if [[ "${REDIS_URL:-}" == *"//redis:"* ]]; then
    export REDIS_URL="${REDIS_URL/\/\/redis:/\/\/localhost:}"
  fi
  export ORCH_GATEWAY_URL="${ORCH_GATEWAY_URL/gateway:/localhost:}"
}

service_log_file() { echo "${ARGUS_LOG_DIR}/$1.log"; }

service_is_running() { is_running "$1"; }

service_pid() {
  local pf; pf="$(pid_file "$1")"
  [[ -f "$pf" ]] && cat "$pf" 2>/dev/null
}

# Every service is launched detached into its own session/process group via
# `setsid`, with the REAL final PID (after exec, so PID == PGID == SID)
# written to the pid file by the child itself — not `$!` from `setsid cmd &`,
# which captures setsid's own wrapper PID; that wrapper immediately exits
# once it has forked+detached the real process, so a PID file built from `$!`
# there would already be stale by the time anything reads it. service_stop
# signals the whole process group (`kill -- -PID`), not just the one PID —
# a plain `cmd &` + `kill $pid` is exactly how the orphaned-child problem in
# §20/§26/§40 happens (a wrapper shell dies, its already-exec'd child
# silently survives and keeps the port bound).
_spawn_detached() {
  local pidfile="$1"; shift
  setsid bash -c 'echo $$ >"$1"; shift; exec "$@"' _ "$pidfile" "$@" \
    >>"$(service_log_file "$(basename "$pidfile" .pid)")" 2>&1 &
  disown
  local i
  for ((i = 0; i < 50; i++)); do
    [[ -s "$pidfile" ]] && return 0
    sleep 0.1
  done
  return 1
}

_start_gateway() {
  _service_env; _service_native_url_fixups
  ( cd "$ARGUS_GATEWAY_DIR" && _spawn_detached "$(pid_file gateway)" \
      "$ARGUS_VENV_DIR/bin/uvicorn" app.main:app \
      --host "${ARGUS_API_HOST:-0.0.0.0}" --port "${ARGUS_API_PORT:-8000}" )
}

_start_orchestrator() {
  local bin="${ARGUS_ORCH_DIR}/bin/orchestrator"
  [[ -x "$bin" ]] || die "orchestrator binary not built — run: (cd orchestrator && go build -o bin/orchestrator ./cmd/orchestrator)"
  _service_env; _service_native_url_fixups
  ( cd "$ARGUS_ORCH_DIR" && _spawn_detached "$(pid_file orchestrator)" "$bin" )
}

_start_web() {
  [[ -d "${ARGUS_WEB_DIR}/node_modules" ]] || die "web/node_modules missing — run ./install.sh first"
  local next_bin="${ARGUS_WEB_DIR}/node_modules/.bin/next"
  [[ -x "$next_bin" ]] || die "next.js binary missing at $next_bin — run ./install.sh first"
  _service_env
  ( cd "$ARGUS_WEB_DIR" && _spawn_detached "$(pid_file web)" "$next_bin" start -p "${ARGUS_WEB_PORT:-3000}" )
}

# service_start <name> — no-op (idempotent) if already running.
service_start() {
  local name="$1"
  if service_is_running "$name"; then
    ok "$name already running (pid $(service_pid "$name"))"
    return 0
  fi
  rm -f "$(pid_file "$name")"
  case "$name" in
    gateway) _start_gateway ;;
    orchestrator) _start_orchestrator ;;
    web) _start_web ;;
    *) die "unknown service: $name" ;;
  esac
  sleep 1
  if service_is_running "$name"; then
    ok "$name started (pid $(service_pid "$name")) — log: $(service_log_file "$name")"
  else
    fail "$name failed to start — see $(service_log_file "$name")"
    return 1
  fi
}

# service_stop <name> [--force] — SIGTERM, wait up to 20s for a clean exit
# (giving the gateway/orchestrator time to checkpoint in-flight work), then
# SIGKILL only with --force or after the grace period expires.
service_stop() {
  local name="$1" force="${2:-}"
  if ! service_is_running "$name"; then
    info "$name not running"
    rm -f "$(pid_file "$name")"
    return 0
  fi
  local pid; pid="$(service_pid "$name")"
  # Each service is its own process-group leader (see _spawn_detached), so
  # signalling the negative PID hits the whole group — the leader plus any
  # subprocess it forked — not just the single recorded PID.
  if [[ "$force" == "--force" ]]; then
    warn "$name: force-killing pid $pid (SIGKILL, whole process group)"
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  else
    info "$name: stopping pid $pid (SIGTERM, waiting up to 20s)…"
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    local i
    for ((i = 0; i < 20; i++)); do
      service_is_running "$name" || break
      sleep 1
    done
    if service_is_running "$name"; then
      warn "$name did not stop within 20s — sending SIGKILL"
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      sleep 1
    fi
  fi
  rm -f "$(pid_file "$name")"
  if service_is_running "$name"; then
    fail "$name still running after stop attempt"
    return 1
  fi
  ok "$name stopped"
}

service_status_line() {
  local name="$1"
  if service_is_running "$name"; then
    local pid; pid="$(service_pid "$name")"
    local up=""
    if [[ -r "/proc/$pid" ]]; then
      local start; start="$(stat -c%Y "/proc/$pid" 2>/dev/null || echo '')"
      [[ -n "$start" ]] && up=" up $(( ($(date +%s) - start) / 60 ))m"
    fi
    ok "$name — running (pid $pid${up})"
  else
    warn "$name — stopped"
  fi
}

services_status() {
  section "SERVICES"
  local n
  for n in "${ARGUS_SERVICE_ORDER[@]}"; do service_status_line "$n"; done
  info "workers — in-process with orchestrator (ORCH_WORKER_CONCURRENCY=${ORCH_WORKER_CONCURRENCY:-4})"
  info "scheduler — in-process with gateway (set ARGUS_SCHEDULER=off to disable continuous monitoring)"
}

services_start_all() {
  step "Starting services"
  local n
  for n in "${ARGUS_SERVICE_ORDER[@]}"; do service_start "$n" || return 1; done
}

# services_stop_all — reverse order: stop the frontend first (no new user
# requests), then the orchestrator (stop accepting/finish in-flight jobs),
# then the gateway (stop accepting new scan requests) last, so in-flight
# orchestrator work still has a gateway to report events to while it winds
# down (§26).
services_stop_all() {
  local force="${1:-}"
  step "Stopping services"
  local n idx
  for ((idx = ${#ARGUS_SERVICE_ORDER[@]} - 1; idx >= 0; idx--)); do
    n="${ARGUS_SERVICE_ORDER[$idx]}"
    [[ "$n" == "orchestrator" ]] && service_stop "orchestrator" "$force"
  done
  for ((idx = ${#ARGUS_SERVICE_ORDER[@]} - 1; idx >= 0; idx--)); do
    n="${ARGUS_SERVICE_ORDER[$idx]}"
    [[ "$n" == "orchestrator" ]] && continue
    service_stop "$n" "$force"
  done
}

services_logs() {
  local name="${1:-}"
  if [[ -n "$name" ]]; then
    tail -n "${LOG_LINES:-100}" -f "$(service_log_file "$name")"
  else
    tail -n "${LOG_LINES:-50}" -f "${ARGUS_LOG_DIR}"/{gateway,orchestrator,web}.log 2>/dev/null
  fi
}
