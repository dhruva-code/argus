#!/usr/bin/env bash
# scripts/lib/repair.sh — safe automatic repairs only (§31). Composes the
# *_repair functions each lib module already exposes; never touches
# anything this file doesn't explicitly name.
#
# Deliberately absent from this file, on purpose, forever: database wipes,
# deleting project/user data, deleting files this installer didn't create,
# disabling the firewall, touching SSH config, overwriting secrets in .env,
# or killing a process this framework didn't start.
# shellcheck shell=bash

if [[ -n "${ARGUS_REPAIR_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_REPAIR_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"
# shellcheck source=./python.sh
source "${ARGUS_LIB_DIR}/python.sh"
# shellcheck source=./node.sh
source "${ARGUS_LIB_DIR}/node.sh"
# shellcheck source=./database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=./redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=./tools.sh
source "${ARGUS_LIB_DIR}/tools.sh"
# shellcheck source=./permissions.sh
source "${ARGUS_LIB_DIR}/permissions.sh"
# shellcheck source=./services.sh
source "${ARGUS_LIB_DIR}/services.sh"

# repair_stale_pids — a pid file whose process no longer exists is safe to
# remove; it only ever points at something this framework itself started.
repair_stale_pids() {
  local pf name
  for pf in "${ARGUS_PID_DIR}"/*.pid; do
    [[ -e "$pf" ]] || continue
    name="$(basename "$pf" .pid)"
    if ! is_running "$name"; then
      fix "removing stale pid file: $pf"
      rm -f "$pf"
    fi
  done
}

# repair_runtime_tmp — only removes files *this app* wrote under its own
# runtime/tmp/ directory, and only ones older than 24h (never mid-scan
# artifacts) — never a broad `rm -rf` outside that one directory (§43).
repair_runtime_tmp() {
  [[ -d "$ARGUS_TMP_DIR" ]] || return 0
  local n
  n="$(find "$ARGUS_TMP_DIR" -mindepth 1 -mmin +1440 2>/dev/null | wc -l || true)"
  if [[ "$n" -gt 0 ]]; then
    fix "removing $n stale file(s) from runtime/tmp/ older than 24h"
    find "$ARGUS_TMP_DIR" -mindepth 1 -mmin +1440 -delete 2>/dev/null || true
  else
    verbose "runtime/tmp/ has no stale files"
  fi
}

# repair_python_cache — __pycache__/.pyc under the gateway app only; a
# "broken application cache" per §31, not a general filesystem sweep.
repair_python_cache() {
  [[ -d "${ARGUS_GATEWAY_DIR}/app" ]] || return 0
  local n; n="$(find "${ARGUS_GATEWAY_DIR}/app" -name '__pycache__' -type d 2>/dev/null | wc -l || true)"
  if [[ "$n" -gt 0 ]]; then
    fix "clearing $n __pycache__ director(y/ies)"
    find "${ARGUS_GATEWAY_DIR}/app" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
  fi
}

# doctor_repair_all — the --fix entry point. Order matters: infra first
# (db/redis), then language environments, then tools, then process/file
# hygiene last (so a repaired service has somewhere to write logs to).
doctor_repair_all() {
  step "Running safe automatic repairs"
  permissions_repair
  db_repair
  redis_repair
  [[ -x "$ARGUS_VENV_PY" ]] || python_repair
  [[ -d "${ARGUS_WEB_DIR}/node_modules" ]] || node_repair
  tools_repair
  repair_stale_pids
  repair_runtime_tmp
  repair_python_cache
  ok "repair pass complete — re-run ./doctor.sh --check to confirm"
}
