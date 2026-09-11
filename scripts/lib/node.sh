#!/usr/bin/env bash
# scripts/lib/node.sh — Node.js/npm detection and dependency install for web/.
# shellcheck shell=bash

if [[ -n "${ARGUS_NODE_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_NODE_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

NODE_MIN_VERSION="${NODE_MIN_VERSION:-18.0.0}"
ARGUS_WEB_LOCKFILE="${ARGUS_WEB_DIR}/package-lock.json"
ARGUS_WEB_PACKAGE_JSON="${ARGUS_WEB_DIR}/package.json"
ARGUS_WEB_NODE_MODULES="${ARGUS_WEB_DIR}/node_modules"
ARGUS_WEB_STAMP="${ARGUS_WEB_NODE_MODULES}/.argus-lockfile.sha256"

node_installed_version() {
  has_cmd node || { echo ""; return 1; }
  node --version 2>/dev/null | sed 's/^v//'
}

node_required_version() {
  if [[ -f "${ARGUS_WEB_DIR}/.nvmrc" ]]; then
    tr -d 'v \n' <"${ARGUS_WEB_DIR}/.nvmrc"
    return 0
  fi
  echo "$NODE_MIN_VERSION"
}

node_check() {
  section "NODE"
  if [[ ! -d "$ARGUS_WEB_DIR" ]]; then
    info "no web/ directory — frontend not applicable"
    return 0
  fi
  local nv; nv="$(node_installed_version || true)"
  if [[ -z "$nv" ]]; then
    fail "node not found"
    return 1
  fi
  local req; req="$(node_required_version)"
  if version_ge "$nv" "$req"; then
    ok "node $nv (>= $req required)"
  else
    fail "node $nv is older than the required $req"
    return 1
  fi
  has_cmd npm && ok "npm $(npm --version 2>/dev/null)" || { fail "npm not found"; return 1; }

  if [[ -d "$ARGUS_WEB_NODE_MODULES" ]]; then
    ok "node_modules present"
  else
    warn "node_modules missing"
    return 1
  fi
  if [[ -f "$ARGUS_WEB_STAMP" && -f "$ARGUS_WEB_LOCKFILE" ]]; then
    local want have
    want="$(sha256sum "$ARGUS_WEB_LOCKFILE" | awk '{print $1}')"
    have="$(cat "$ARGUS_WEB_STAMP" 2>/dev/null || true)"
    if [[ "$want" == "$have" ]]; then
      ok "dependencies up to date with package-lock.json"
    else
      warn "package-lock.json changed since the last install"
      return 1
    fi
  else
    warn "dependencies not verified yet (no install stamp)"
    return 1
  fi
  return 0
}

# node_setup — idempotent: `npm ci` only runs when the lockfile changed (or
# node_modules is missing/incomplete). Never silently upgrades Node itself.
node_setup() {
  step "Node.js environment"
  if [[ ! -d "$ARGUS_WEB_DIR" ]]; then
    info "no web/ directory — skipping frontend setup"
    return 0
  fi
  local nv; nv="$(node_installed_version || true)"
  if [[ -z "$nv" ]]; then
    die "node not found — install Node.js $NODE_MIN_VERSION+ first (nodejs.org, nvm, or your package manager)"
  fi
  local req; req="$(node_required_version)"
  if ! version_ge "$nv" "$req"; then
    die "node $nv is older than the required $req — this project does not auto-upgrade Node; install $req+ manually"
  fi
  ok "node $nv / npm $(npm --version 2>/dev/null || echo '?')"

  if [[ ! -f "$ARGUS_WEB_PACKAGE_JSON" ]]; then
    warn "no package.json at $ARGUS_WEB_PACKAGE_JSON — skipping"
    return 0
  fi

  local want="" have=""
  if [[ -f "$ARGUS_WEB_LOCKFILE" ]]; then
    want="$(sha256sum "$ARGUS_WEB_LOCKFILE" | awk '{print $1}')"
  fi
  [[ -f "$ARGUS_WEB_STAMP" ]] && have="$(cat "$ARGUS_WEB_STAMP" 2>/dev/null || true)"

  if [[ -d "$ARGUS_WEB_NODE_MODULES" && -n "$want" && "$want" == "$have" && "$ARGUS_FORCE" != "1" ]]; then
    ok "dependencies already match package-lock.json — skipping reinstall"
    return 0
  fi

  (
    cd "$ARGUS_WEB_DIR"
    if [[ -f "$ARGUS_WEB_LOCKFILE" ]]; then
      info "npm ci (compatible lockfile found)…"
      run_cmd_or_die "npm ci" -- npm ci --no-audit --no-fund
    else
      warn "no package-lock.json — falling back to 'npm install' (not reproducible)"
      run_cmd_or_die "npm install" -- npm install --no-audit --no-fund
    fi
  )
  [[ -n "$want" ]] && echo "$want" >"$ARGUS_WEB_STAMP"
  ok "Node dependencies installed"
}

node_repair() {
  step "Repairing Node environment"
  if [[ ! -d "$ARGUS_WEB_DIR" ]]; then return 0; fi
  fix "removing node_modules and reinstalling from lockfile"
  rm -rf "$ARGUS_WEB_NODE_MODULES"
  node_setup
}
