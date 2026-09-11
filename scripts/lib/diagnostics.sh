#!/usr/bin/env bash
# scripts/lib/diagnostics.sh — the full doctor.sh pipeline (§28-30): runs
# every check module in order, classifies what fails, and produces the
# categorized report doctor.sh prints (and, with --report, archives).
# shellcheck shell=bash

if [[ -n "${ARGUS_DIAGNOSTICS_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_DIAGNOSTICS_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"
for _m in os_detection package_manager python node go docker database redis tools \
          permissions services health performance; do
  # shellcheck disable=SC1090
  source "${ARGUS_LIB_DIR}/${_m}.sh"
done
unset _m

# Issue classification buckets (§30). Each check module appends its own
# category name here when it reports a failure, so the final summary can
# group "what kind of problem is this" without every module needing to know
# about every other one.
declare -a DIAG_FAILED_CATEGORIES=()

_diag_run() {
  local category="$1"; shift
  if ! "$@"; then
    DIAG_FAILED_CATEGORIES+=("$category")
    return 1
  fi
  return 0
}

# diagnostics_run <scope> — scope is "all" or one of the --tools/--workers/
# --database/--network/--permissions/--performance/--logs flag names (minus
# the --).
diagnostics_run() {
  local scope="${1:-all}"
  DIAG_FAILED_CATEGORIES=()
  os_detect
  os_print_summary

  case "$scope" in
    all|system)
      check_system_packages || DIAG_FAILED_CATEGORIES+=("Installation")
      ;;&
    all|python)
      _diag_run "Dependency" python_check
      ;;&
    all|node)
      _diag_run "Dependency" node_check
      ;;&
    all|go)
      _diag_run "Dependency" go_check
      ;;&
    all|docker)
      docker_check || true   # optional component — never fails the run (§39)
      ;;&
    all|database)
      _diag_run "Database" db_check
      ;;&
    all|redis)
      _diag_run "Redis" redis_check
      ;;&
    all|tools)
      _diag_run "Tool Version" tools_check
      ;;&
    all|permissions)
      _diag_run "Permission" permissions_check
      ;;&
    all|workers)
      section "WORKERS"
      if service_is_running orchestrator; then
        ok "orchestrator running (pid $(service_pid orchestrator))"
      else
        fail "orchestrator not running"
        DIAG_FAILED_CATEGORIES+=("Worker")
      fi
      ;;&
    all|network)
      _diag_run "Port Conflict" health_ports
      section "NETWORK"
      _diag_network_checks
      ;;&
    all|performance)
      _diag_run "Disk" health_disk
      _diag_run "Memory" health_memory
      [[ "$scope" == "performance" ]] && performance_snapshot
      ;;&
    all|logs)
      [[ "$scope" == "logs" ]] && _diag_show_recent_errors
      ;;&
  esac

  section "SUMMARY"
  if [[ "${#DIAG_FAILED_CATEGORIES[@]}" -eq 0 ]]; then
    ok "no problems detected"
    return 0
  fi
  local cat counts="" seen=""
  for cat in "${DIAG_FAILED_CATEGORIES[@]}"; do
    [[ "$seen" == *"|$cat|"* ]] && continue
    seen="${seen}|$cat|"
    fail "issue category: $cat"
  done
  echo ""
  info "run: ./doctor.sh --fix   to attempt safe automatic repair"
  return 1
}

# _diag_network_checks — only the infrastructure this app actually needs
# (§46), never a third-party site.
_diag_network_checks() {
  if ip route show default >/dev/null 2>&1 || route -n 2>/dev/null | grep -q '^0.0.0.0'; then
    ok "default route present"
  else
    warn "no default route detected"
  fi
  if getent hosts localhost >/dev/null 2>&1; then
    ok "DNS resolution (localhost)"
  else
    warn "DNS resolution failed for localhost"
  fi
  db_load_config
  db_tcp_reachable && ok "database connectivity" || warn "database not reachable"
  redis_load_config
  redis_tcp_reachable && ok "redis connectivity" || warn "redis not reachable"
}

_diag_show_recent_errors() {
  section "RECENT ERRORS"
  local f found=0
  for f in "${ARGUS_LOG_DIR}"/*.log; do
    [[ -e "$f" ]] || continue
    # `grep -c` always prints a numeric count (even 0) but exits 1 when that
    # count is 0 — a fallback `|| echo 0` here would double-print "0\n0" on
    # a clean log; `|| true` just prevents that exit status from tripping
    # `set -e` without adding any extra output.
    local hits; hits="$(grep -c "error\|ERROR\|FAIL" "$f" 2>/dev/null || true)"
    if [[ "$hits" -gt 0 ]]; then
      found=1
      info "$(basename "$f"): $hits error line(s) — last 3:"
      grep -i "error\|fail" "$f" 2>/dev/null | tail -n 3 | sed 's/^/    /'
    fi
  done
  [[ "$found" == "0" ]] && ok "no errors found in recent logs"
}
