#!/usr/bin/env bash
# scripts/lib/python.sh — the gateway's Python virtualenv, created/validated
# idempotently. Application code never uses the global interpreter.
# shellcheck shell=bash

if [[ -n "${ARGUS_PYTHON_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_PYTHON_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

PYTHON_MIN_VERSION="${PYTHON_MIN_VERSION:-3.11}"
ARGUS_REQUIREMENTS_FILE="${ARGUS_GATEWAY_DIR}/requirements.txt"
ARGUS_VENV_PY="${ARGUS_VENV_DIR}/bin/python"
ARGUS_VENV_PIP="${ARGUS_VENV_DIR}/bin/pip"
# Stamp recording the requirements.txt hash last installed into .venv — lets
# every rerun skip `pip install` entirely when nothing changed (idempotent).
ARGUS_VENV_STAMP="${ARGUS_VENV_DIR}/.argus-requirements.sha256"

python_system_version() {
  has_cmd python3 || { echo ""; return 1; }
  python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null
}

python_check() {
  section "PYTHON"
  local sysver; sysver="$(python_system_version || true)"
  if [[ -z "$sysver" ]]; then
    fail "python3 not found"
    return 1
  fi
  if version_ge "$sysver" "$PYTHON_MIN_VERSION"; then
    ok "python3 $sysver (>= $PYTHON_MIN_VERSION required)"
  else
    fail "python3 $sysver is older than the required $PYTHON_MIN_VERSION"
    return 1
  fi

  if [[ -x "$ARGUS_VENV_PY" ]]; then
    ok "virtual environment present ($ARGUS_VENV_DIR)"
  else
    warn "virtual environment missing"
    return 1
  fi

  if [[ -f "$ARGUS_VENV_STAMP" && -f "$ARGUS_REQUIREMENTS_FILE" ]]; then
    local want have
    want="$(sha256sum "$ARGUS_REQUIREMENTS_FILE" | awk '{print $1}')"
    have="$(cat "$ARGUS_VENV_STAMP" 2>/dev/null || true)"
    if [[ "$want" == "$have" ]]; then
      ok "dependencies up to date with requirements.txt"
    else
      warn "requirements.txt changed since the last install"
      return 1
    fi
  else
    warn "dependencies not verified yet (no install stamp)"
    return 1
  fi
  return 0
}

# python_setup — idempotent: creates .venv only if missing/broken, (re)installs
# requirements.txt only if it changed since the last successful install.
python_setup() {
  step "Python environment"
  local sysver; sysver="$(python_system_version || true)"
  if [[ -z "$sysver" ]]; then
    die "python3 not found — install it first (e.g. apt-get install python3 python3-venv)"
  fi
  if ! version_ge "$sysver" "$PYTHON_MIN_VERSION"; then
    die "python3 $sysver is older than the required $PYTHON_MIN_VERSION"
  fi
  ok "python3 $sysver"

  if [[ ! -x "$ARGUS_VENV_PY" ]]; then
    info "creating virtual environment at $ARGUS_VENV_DIR"
    run_cmd_or_die "create venv" -- python3 -m venv "$ARGUS_VENV_DIR"
  else
    verbose "venv already present, reusing"
  fi
  ok "virtual environment ready"

  run_cmd "upgrade pip" -- "$ARGUS_VENV_PIP" install --quiet --upgrade pip || \
    warn "could not upgrade pip in the venv (continuing with the existing version)"

  if [[ ! -f "$ARGUS_REQUIREMENTS_FILE" ]]; then
    warn "no requirements.txt at $ARGUS_REQUIREMENTS_FILE — skipping dependency install"
    return 0
  fi

  local want have=""
  want="$(sha256sum "$ARGUS_REQUIREMENTS_FILE" | awk '{print $1}')"
  [[ -f "$ARGUS_VENV_STAMP" ]] && have="$(cat "$ARGUS_VENV_STAMP" 2>/dev/null || true)"

  if [[ "$want" == "$have" && "$ARGUS_FORCE" != "1" ]]; then
    ok "dependencies already match requirements.txt — skipping reinstall"
    return 0
  fi

  info "installing Python dependencies (requirements.txt changed or first install)…"
  if run_cmd "pip install -r requirements.txt" -- "$ARGUS_VENV_PIP" install --quiet -r "$ARGUS_REQUIREMENTS_FILE"; then
    echo "$want" >"$ARGUS_VENV_STAMP"
    ok "Python dependencies installed"
  else
    die "pip install failed — see ${ARGUS_LOG_DIR}/install.log"
  fi
}

python_repair() {
  step "Repairing Python environment"
  if [[ ! -x "$ARGUS_VENV_PY" ]]; then
    fix "recreating missing virtual environment"
    rm -rf "$ARGUS_VENV_DIR"
  else
    # A venv whose interpreter no longer runs is broken beyond repair-in-place.
    if ! "$ARGUS_VENV_PY" -c 'pass' >/dev/null 2>&1; then
      fix "virtual environment is broken — recreating"
      rm -rf "$ARGUS_VENV_DIR"
    fi
  fi
  rm -f "$ARGUS_VENV_STAMP"
  python_setup
}
