#!/usr/bin/env bash
# scripts/lib/redis.sh — Redis detection, start, and health checks. Redis is
# the job queue + event bus between the gateway and the orchestrator.
# shellcheck shell=bash

if [[ -n "${ARGUS_REDIS_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_REDIS_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

REDIS_HOST=""; REDIS_PORT=""; REDIS_DB="0"

redis_load_config() {
  local url=""
  [[ -f "$ARGUS_ENV_FILE" ]] && url="$(grep -E '^REDIS_URL=' "$ARGUS_ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  url="${url:-redis://localhost:6379/0}"
  # redis://[:password@]host:port[/db]
  local hostport dbpart
  hostport="$(sed -E 's#^redis://([^@]*@)?([^/]+).*#\2#' <<<"$url")"
  REDIS_HOST="${hostport%%:*}"
  REDIS_PORT="${hostport##*:}"
  [[ "$REDIS_HOST" == "$REDIS_PORT" ]] && REDIS_PORT="6379"
  if [[ "$REDIS_HOST" == "redis" ]] && ! getent hosts redis >/dev/null 2>&1; then
    REDIS_HOST="localhost"
  fi
  dbpart="$(sed -E 's#^redis://[^/]+/?##' <<<"$url")"
  REDIS_DB="${dbpart:-0}"
}

redis_tcp_reachable() {
  { exec 3<>"/dev/tcp/${REDIS_HOST}/${REDIS_PORT}"; } 2>/dev/null && { exec 3>&-; return 0; } || return 1
}

redis_ping_ok() {
  if has_cmd redis-cli; then
    [[ "$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>/dev/null || true)" == "PONG" ]]
  else
    redis_tcp_reachable
  fi
}

redis_check() {
  section "REDIS"
  redis_load_config
  if ! redis_tcp_reachable; then
    fail "redis not reachable at ${REDIS_HOST}:${REDIS_PORT}"
    return 1
  fi
  ok "redis reachable at ${REDIS_HOST}:${REDIS_PORT}"
  if redis_ping_ok; then
    ok "PING -> PONG"
  else
    fail "redis is listening but did not respond to PING (auth required? wrong port?)"
    return 1
  fi
  if has_cmd redis-cli; then
    local queued processing
    queued="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" llen argus:jobs:queued 2>/dev/null || echo '?')"
    processing="$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" llen argus:jobs:processing 2>/dev/null || echo '?')"
    info "queue: ${queued} queued, ${processing} processing"
  fi
  return 0
}

redis_start() {
  step "Starting Redis"
  redis_load_config
  if redis_tcp_reachable; then
    if redis_ping_ok; then
      ok "redis already reachable at ${REDIS_HOST}:${REDIS_PORT}"
      return 0
    fi
    fail "redis is reachable at ${REDIS_HOST}:${REDIS_PORT} but did not respond to PING (something else may be bound to that port, or REDIS_URL's password doesn't match)"
    return 1
  fi
  if declare -F docker_detect >/dev/null 2>&1 && docker_detect; then
    info "starting redis via docker compose…"
    if compose up -d redis; then
      redis_wait_ready && return 0
    fi
  fi
  if [[ "$OS_HAS_SYSTEMD" == "1" ]] && systemctl list-unit-files 2>/dev/null | grep -q '^redis'; then
    info "starting native redis-server via systemd…"
    sudo_run systemctl start redis-server 2>/dev/null || sudo_run systemctl start redis
    redis_wait_ready && return 0
  fi
  # Same rationale as db_start's native fallback: Docker may not be
  # installed/declined, so fall back to an apt-installed redis-server
  # rather than leaving the app with no queue/event bus at all.
  if has_cmd apt-get; then
    info "docker/redis-server not available — installing Redis natively via apt…"
    redis_install_native && redis_wait_ready && return 0
  fi
  fail "could not start redis automatically — start it manually (docker compose up -d redis, or systemctl start redis-server) and re-run"
  return 1
}

redis_wait_ready() {
  local i
  for ((i = 0; i < 20; i++)); do
    redis_tcp_reachable && return 0
    sleep 1
  done
  return 1
}

redis_install_native() {
  step "Installing Redis (native)"
  has_cmd redis-server || pkg_install redis-server redis-tools
  [[ "$OS_HAS_SYSTEMD" == "1" ]] && sudo_run systemctl enable --now redis-server
  ok "redis-server ready"
}

# redis_reset — DESTRUCTIVE. Drops the queue/event-bus data (FLUSHALL) and,
# for the docker-managed case, recreates the container + volume from
# scratch. Never called automatically — only from an explicit, confirm-
# gated caller (see repair.sh --reset-redis). Losing this data is much
# lower-stakes than the database (queued/in-flight scan jobs, not project
# history — that all lives in Postgres), but it's still a real action a
# user should ask for explicitly, not have happen as a side effect of a
# routine health check.
redis_reset() {
  step "Resetting Redis (destructive)"
  redis_load_config
  if declare -F docker_detect >/dev/null 2>&1 && docker_detect; then
    info "removing the redis container and its data volume…"
    ( cd "$ARGUS_ROOT" && $DOCKER_COMPOSE_CMD --env-file "$ARGUS_ENV_FILE" rm -sf redis ) || true
    local proj vol
    proj="$(basename "$ARGUS_ROOT" | tr -cd 'a-zA-Z0-9_-' | tr '[:upper:]' '[:lower:]')"
    vol="${proj}_redisdata"
    docker volume rm -f "$vol" >/dev/null 2>&1 || true
    compose up -d redis || { fail "failed to recreate the redis container"; return 1; }
    redis_wait_ready || { fail "redis did not come back up after reset"; return 1; }
    ok "redis reset"
    return 0
  fi
  if has_cmd redis-cli && redis_tcp_reachable; then
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" FLUSHALL >/dev/null 2>&1
    ok "redis FLUSHALL complete"
    return 0
  fi
  fail "redis is not reachable to reset"
  return 1
}

redis_repair() {
  step "Repairing Redis"
  redis_load_config
  if ! redis_tcp_reachable; then
    fix "redis unreachable — attempting to start it"
    redis_start
  fi
}
