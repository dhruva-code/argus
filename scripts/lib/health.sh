#!/usr/bin/env bash
# scripts/lib/health.sh — composite health checks shared by run.sh's fast
# startup self-test (§39) and doctor.sh's deeper pipeline (§28).
# shellcheck shell=bash

if [[ -n "${ARGUS_HEALTH_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_HEALTH_SH_LOADED=1

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
# shellcheck source=./services.sh
source "${ARGUS_LIB_DIR}/services.sh"

DISK_WARN_PCT="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" disk_warn_pct 70)"
DISK_HIGH_PCT="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" disk_high_pct 80)"
DISK_CRITICAL_PCT="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" disk_critical_pct 90)"
DISK_PAUSE_PCT="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" disk_pause_pct 95)"
MEM_WARN_PCT="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" mem_warn_pct 80)"
MEM_CRITICAL_PCT="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" mem_critical_pct 92)"

disk_usage_pct() {
  df -P "$ARGUS_ROOT" 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}'
}

mem_usage_pct() {
  awk '
    /^MemTotal:/ {total=$2}
    /^MemAvailable:/ {avail=$2}
    END { if (total>0) printf "%d", (100*(total-avail))/total }
  ' /proc/meminfo 2>/dev/null
}

health_disk() {
  local pct; pct="$(disk_usage_pct || true)"
  [[ -z "$pct" ]] && { warn "could not determine disk usage for $ARGUS_ROOT"; return 1; }
  if [[ "$pct" -ge "$DISK_PAUSE_PCT" ]]; then
    fail "disk usage ${pct}% — CRITICAL: at the pause threshold ($DISK_PAUSE_PCT%). New artifact-heavy scans should not be started until space is freed. Findings are never auto-deleted."
    return 1
  elif [[ "$pct" -ge "$DISK_CRITICAL_PCT" ]]; then
    fail "disk usage ${pct}% — above critical threshold ($DISK_CRITICAL_PCT%)"
    return 1
  elif [[ "$pct" -ge "$DISK_HIGH_PCT" ]]; then
    warn "disk usage ${pct}% — above warning threshold ($DISK_HIGH_PCT%)"
    return 1
  elif [[ "$pct" -ge "$DISK_WARN_PCT" ]]; then
    info "disk usage ${pct}% (informational threshold $DISK_WARN_PCT%)"
  else
    ok "disk usage ${pct}%"
  fi
  return 0
}

health_memory() {
  local pct; pct="$(mem_usage_pct || true)"
  [[ -z "$pct" ]] && { warn "could not determine memory usage"; return 1; }
  if [[ "$pct" -ge "$MEM_CRITICAL_PCT" ]]; then
    fail "memory usage ${pct}% — above critical threshold ($MEM_CRITICAL_PCT%)"
    return 1
  elif [[ "$pct" -ge "$MEM_WARN_PCT" ]]; then
    warn "memory usage ${pct}% — above warning threshold ($MEM_WARN_PCT%)"
    return 1
  else
    ok "memory usage ${pct}%"
  fi
  return 0
}

# Only the ports THIS app binds itself (gateway, web) are checked for
# conflicts here — "something is listening" is a problem for those, but the
# opposite for postgres/redis, where we're a client, not the listener; their
# reachability is already covered by db_check/redis_check, not a port-
# ownership question, so they're intentionally not in this table (§34).
health_ports() {
  section "PORTS"
  local problems=0
  local -A want=(
    [gateway]="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" port_gateway 8000)"
    [web]="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" port_web 3000)"
  )
  local svc port owned_by_us
  for svc in "${!want[@]}"; do
    port="${want[$svc]}"
    if ! port_in_use "$port"; then
      info "$svc port $port — free"
      continue
    fi
    owned_by_us=0
    service_is_running "$svc" && owned_by_us=1
    if [[ "$owned_by_us" == "1" ]]; then
      ok "$svc port $port — in use by our own $svc service"
    else
      local owner; owner="$(port_owner "$port" || true)"
      warn "$svc port $port — already in use${owner:+ (pid ${owner})} and it is not our own $svc service"
      problems=1
    fi
  done
  return $((problems > 0 ? 1 : 0))
}

# health_quick — the fast, always-run-on-startup summary (§39). Never blocks
# startup for an optional integration (external API keys etc.) — only core
# infra (db/redis) and required tools matter here.
health_quick() {
  section "STARTUP HEALTH CHECK"
  local problems=0

  if [[ -x "$ARGUS_VENV_PY" ]]; then ok "Environment (Python venv present)"; else warn "Environment — Python venv missing"; problems=1; fi

  redis_load_config
  if redis_tcp_reachable && redis_ping_ok; then ok "Redis"; else warn "Redis unreachable"; problems=1; fi

  db_load_config
  if db_tcp_reachable && db_auth_ok; then ok "Database"; else warn "Database unreachable/auth failed"; problems=1; fi

  if service_is_running orchestrator; then ok "Workers (orchestrator running)"; else warn "Workers — orchestrator not running"; problems=1; fi

  local missing_required=0 name
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    local optional; optional="$(tools_yaml_get "$name" optional)"
    [[ "$optional" == "true" ]] && continue
    tool_installed_version "$name" >/dev/null 2>&1 || missing_required=$((missing_required + 1))
  done < <(tools_yaml_names)
  if [[ "$missing_required" -eq 0 ]]; then
    ok "Required tools"
  else
    warn "Required tools — $missing_required missing/unhealthy"
    problems=1
  fi

  if [[ "$problems" -gt 0 ]]; then
    warn "issue(s) detected — run: ./doctor.sh"
  fi
  return 0   # startup is never blocked by this summary — see §39
}
