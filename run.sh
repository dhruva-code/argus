#!/usr/bin/env bash
# run.sh — primary control interface for the Argus application. Starts,
# stops, and reports on the gateway/orchestrator/web processes; runs pending
# migrations first; performs a fast startup health check.
#
# Usage:
#   ./run.sh [start]      validate environment, apply migrations, start everything
#   ./run.sh stop         graceful stop (checkpoints in-flight jobs)
#   ./run.sh stop --force emergency stop (SIGKILL, whole process group)
#   ./run.sh restart
#   ./run.sh status
#   ./run.sh logs [service]
#   ./run.sh doctor        alias for ./doctor.sh
#   ./run.sh self-test     runs the application self-test (§59)
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=runtime
# shellcheck source=scripts/lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
log_init runtime
reject_sudo_wrapper "$@"

for arg in "$@"; do
  case "$arg" in
    --no-color) ARGUS_NO_COLOR=1 ;;
    --quiet) ARGUS_QUIET=1 ;;
    --verbose) ARGUS_VERBOSE=1 ;;
  esac
done
export ARGUS_NO_COLOR ARGUS_QUIET ARGUS_VERBOSE

# shellcheck source=scripts/lib/os_detection.sh
source "${ARGUS_LIB_DIR}/os_detection.sh"
os_detect
# shellcheck source=scripts/lib/python.sh
source "${ARGUS_LIB_DIR}/python.sh"
# shellcheck source=scripts/lib/node.sh
source "${ARGUS_LIB_DIR}/node.sh"
# shellcheck source=scripts/lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=scripts/lib/redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=scripts/lib/tools.sh
source "${ARGUS_LIB_DIR}/tools.sh"
# shellcheck source=scripts/lib/services.sh
source "${ARGUS_LIB_DIR}/services.sh"
# shellcheck source=scripts/lib/health.sh
source "${ARGUS_LIB_DIR}/health.sh"

CMD="${1:-start}"
[[ $# -gt 0 ]] && shift || true
FORCE_FLAG=""
[[ "${1:-}" == "--force" ]] && FORCE_FLAG="--force"

cmd_validate_env() {
  section "ENVIRONMENT"
  if [[ ! -f "$ARGUS_ENV_FILE" ]]; then
    fail ".env not found — run ./install.sh first"
    return 1
  fi
  ok ".env present"
  if [[ ! -x "$ARGUS_VENV_PY" ]]; then
    fail "Python virtual environment missing — run ./install.sh first"
    return 1
  fi
  ok "Python environment present"
  if [[ -d "$ARGUS_WEB_DIR" && ! -d "${ARGUS_WEB_DIR}/node_modules" ]]; then
    fail "web/node_modules missing — run ./install.sh first"
    return 1
  fi
  ok "Node environment present"
  if [[ ! -x "${ARGUS_ORCH_DIR}/bin/orchestrator" ]]; then
    warn "orchestrator binary not built — building it now…"
    ( cd "$ARGUS_ORCH_DIR" && go build -o bin/orchestrator ./cmd/orchestrator ) || {
      fail "failed to build the orchestrator — install Go and re-run ./install.sh"
      return 1
    }
    ok "orchestrator binary built"
  else
    ok "orchestrator binary present"
  fi
  return 0
}

argus_version() {
  grep -oE '"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.-]*"' "${ARGUS_GATEWAY_DIR}/app/__init__.py" 2>/dev/null | tr -d '"' | head -n1 || true
}

cmd_start() {
  step "Argus startup — v$(argus_version)"
  cmd_validate_env || die "environment validation failed — see above"

  db_start || die "postgres is required and could not be started"
  redis_start || die "redis is required and could not be started"

  if db_tcp_reachable; then
    db_migrate
  else
    die "database unreachable — cannot start"
  fi

  services_start_all

  sleep 2
  health_quick
  echo ""
  services_status
  echo ""
  ok "web:       http://localhost:${ARGUS_WEB_PORT:-3000}"
  ok "api docs:  http://localhost:${ARGUS_API_PORT:-8000}/api/docs"
}

cmd_stop() {
  services_stop_all "$FORCE_FLAG"
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  services_status
  echo ""
  health_ports || true
}

cmd_logs() {
  local svc="${1:-}"
  if [[ -n "$svc" ]]; then
    services_logs "$svc"
  else
    info "tailing gateway + orchestrator + web (ctrl-C to stop) — pass a service name for just one"
    services_logs
  fi
}

cmd_self_test() {
  "${SCRIPT_DIR}/scripts/self_test.sh" "$@"
}

case "$CMD" in
  start|"") cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs) cmd_logs "${1:-}" ;;
  doctor) exec "${SCRIPT_DIR}/doctor.sh" "$@" ;;
  self-test) cmd_self_test "$@" ;;
  -h|--help)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown command: $CMD (usage: ./run.sh [start|stop|restart|status|logs|doctor|self-test])"
    ;;
esac
