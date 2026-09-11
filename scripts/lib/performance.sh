#!/usr/bin/env bash
# scripts/lib/performance.sh — a point-in-time resource/queue snapshot for
# `doctor.sh --performance` (§61). The in-app Scan Performance Dashboard
# (per-phase/per-tool timings, historical graphs) lives in the web UI — this
# is the host-level, always-available CLI complement to it.
# shellcheck shell=bash

if [[ -n "${ARGUS_PERFORMANCE_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_PERFORMANCE_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"
# shellcheck source=./redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=./database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=./services.sh
source "${ARGUS_LIB_DIR}/services.sh"

_proc_rss_mb() {
  local pid="$1"
  [[ -r "/proc/$pid/status" ]] || { echo "?"; return; }
  awk '/^VmRSS:/ {printf "%d", $2/1024}' "/proc/$pid/status" 2>/dev/null
}

_proc_cpu_pct() {
  # Cheap instantaneous estimate via /proc/<pid>/stat deltas over 200ms.
  local pid="$1"
  [[ -r "/proc/$pid/stat" ]] || { echo "?"; return; }
  local hz; hz="$(getconf CLK_TCK 2>/dev/null || echo 100)"
  local t1 t2 c1 c2
  read -r -a t1 <"/proc/$pid/stat" 2>/dev/null || { echo "?"; return; }
  c1=$(( ${t1[13]} + ${t1[14]} ))
  sleep 0.2
  read -r -a t2 <"/proc/$pid/stat" 2>/dev/null || { echo "?"; return; }
  c2=$(( ${t2[13]} + ${t2[14]} ))
  awk -v c1="$c1" -v c2="$c2" -v hz="$hz" 'BEGIN { printf "%.1f", ((c2-c1)/hz)/0.2*100 }'
}

performance_snapshot() {
  section "PERFORMANCE"

  local load; load="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo '?')"
  local cores; cores="$(nproc 2>/dev/null || echo '?')"
  info "load average: $load (${cores} cores)"

  local memline; memline="$(free -m 2>/dev/null | awk '/^Mem:/ {printf "%s/%s MB used", $3, $2}' || true)"
  [[ -n "$memline" ]] && info "memory: $memline"

  local disk; disk="$(df -h "$ARGUS_ROOT" 2>/dev/null | awk 'NR==2 {printf "%s used of %s (%s)", $3, $2, $5}' || true)"
  [[ -n "$disk" ]] && info "disk ($ARGUS_ROOT): $disk"

  echo ""
  echo "  ${C_BOLD}service        pid      cpu%    rss(MB)${C_RESET}"
  local n
  for n in "${ARGUS_SERVICE_ORDER[@]}"; do
    if service_is_running "$n"; then
      local pid; pid="$(service_pid "$n")"
      printf "  %-14s %-8s %-7s %-7s\n" "$n" "$pid" "$(_proc_cpu_pct "$pid")" "$(_proc_rss_mb "$pid")"
    else
      printf "  %-14s %-8s %-7s %-7s\n" "$n" "-" "-" "-"
    fi
  done

  redis_load_config
  if redis_tcp_reachable && has_cmd redis-cli; then
    echo ""
    local queued processing
    queued="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" llen argus:jobs:queued 2>/dev/null || echo '?')"
    processing="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" llen argus:jobs:processing 2>/dev/null || echo '?')"
    info "queue: ${queued} queued, ${processing} processing"
  fi

  if [[ -x "$ARGUS_VENV_PY" ]]; then
    local latency
    latency="$(db_measure_latency_ms 2>/dev/null || true)"
    [[ -n "$latency" ]] && info "database round-trip: ${latency}ms"
  fi
}

# db_measure_latency_ms — a single SELECT 1 round-trip, timed. Reuses the
# same psycopg connection path as db_auth_ok in database.sh.
db_measure_latency_ms() {
  db_load_config
  local start end
  start="$(date +%s%N)"
  db_auth_ok >/dev/null 2>&1 || return 1
  end="$(date +%s%N)"
  echo $(( (end - start) / 1000000 ))
}
