#!/usr/bin/env bash
# scripts/lib/docker.sh — optional Docker/Compose detection (Docker deployment
# mode, §19/§54/§55). Never auto-installs Docker or grants group membership
# without an explicit confirmation — that changes privileged system access.
# shellcheck shell=bash

if [[ -n "${ARGUS_DOCKER_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_DOCKER_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

DOCKER_AVAILABLE=0
DOCKER_COMPOSE_CMD=""   # "docker compose" or "docker-compose"

docker_detect() {
  DOCKER_AVAILABLE=0
  DOCKER_COMPOSE_CMD=""
  has_cmd docker || return 1
  if docker info >/dev/null 2>&1; then
    DOCKER_AVAILABLE=1
  else
    return 1
  fi
  if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
  elif has_cmd docker-compose; then
    DOCKER_COMPOSE_CMD="docker-compose"
  fi
  [[ -n "$DOCKER_COMPOSE_CMD" ]]
}

docker_check() {
  section "DOCKER"
  if ! has_cmd docker; then
    info "docker not installed (optional — only needed for Docker deployment mode)"
    return 0
  fi
  if docker info >/dev/null 2>&1; then
    ok "docker $(docker version --format '{{.Client.Version}}' 2>/dev/null || echo '?') — daemon reachable"
  else
    warn "docker is installed but the daemon is not reachable (permissions? not running?)"
    return 1
  fi
  if docker compose version >/dev/null 2>&1; then
    ok "docker compose $(docker compose version --short 2>/dev/null || echo '?')"
  elif has_cmd docker-compose; then
    ok "docker-compose $(docker-compose version --short 2>/dev/null || echo '?') (legacy standalone binary)"
  else
    warn "docker compose plugin not found"
    return 1
  fi
  return 0
}

# docker_offer_install — interactive-only; never runs unattended. Uses the
# distro's own convenience script only after explicit confirmation, and never
# silently adds the current user to the docker group (that's a privileged
# change — §19 "do not automatically modify privileged system access without
# warning").
docker_offer_install() {
  if has_cmd docker; then return 0; fi
  if [[ "$ARGUS_NON_INTERACTIVE" == "1" ]]; then
    info "docker not installed — skipping (non-interactive mode); Postgres/Redis will be installed natively instead"
    return 0
  fi
  if ! confirm "Docker is not installed. Install it now via apt (Docker Engine + Compose plugin)?" y; then
    info "skipping Docker install — Postgres/Redis will be installed natively instead"
    return 0
  fi
  pkg_install ca-certificates curl gnupg
  sudo_run install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL "https://download.docker.com/linux/${OS_ID:-debian}/gpg" | sudo_run gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  fi
  local arch; arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID:-debian} ${OS_CODENAME:-stable} stable" |
    sudo_run tee /etc/apt/sources.list.d/docker.list >/dev/null
  apt_update_once
  sudo_run apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  warn "docker was installed. To run it without sudo, add yourself to the docker group yourself:"
  warn "  sudo usermod -aG docker \$USER   (then log out and back in)"
  warn "Argus does not do this automatically — that grants root-equivalent access."
}

# compose — thin wrapper so callers don't care whether it's the plugin or
# the legacy standalone binary.
compose() {
  [[ -n "$DOCKER_COMPOSE_CMD" ]] || die "docker compose is not available"
  ( cd "$ARGUS_ROOT" && $DOCKER_COMPOSE_CMD --env-file "$ARGUS_ENV_FILE" "$@" )
}
