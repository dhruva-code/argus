#!/usr/bin/env bash
# scripts/env_setup.sh — generates .env from .env.example on first install,
# with real random secrets. NEVER overwrites an existing .env — an existing
# file is only ever checked for lingering CHANGE_ME placeholders and, purely
# additively, has any brand-new keys .env.example gained since it was last
# updated appended (with safe non-secret defaults, clearly commented) so an
# upgrade never silently loses a variable the running app now reads (§21/§22).
# shellcheck shell=bash

if [[ -n "${ARGUS_ENV_SETUP_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_ENV_SETUP_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"
# shellcheck source=./lib/python.sh
source "${ARGUS_LIB_DIR}/python.sh"

_gen_hex32() {
  if has_cmd openssl; then openssl rand -hex 32
  else "$ARGUS_VENV_PY" -c 'import secrets; print(secrets.token_hex(32))' 2>/dev/null || \
       python3 -c 'import secrets; print(secrets.token_hex(32))'
  fi
}

_gen_fernet_key() {
  if [[ -x "$ARGUS_VENV_PY" ]] && "$ARGUS_VENV_PY" -c 'import cryptography' >/dev/null 2>&1; then
    "$ARGUS_VENV_PY" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
  else
    # base64url(32 random bytes) — the same shape a Fernet key is, usable
    # even before the venv has `cryptography` installed yet.
    openssl rand -base64 32 2>/dev/null | tr '+/' '-_' | tr -d '=\n'
  fi
}

_gen_password() {
  if has_cmd openssl; then openssl rand -hex 16
  else "$ARGUS_VENV_PY" -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null || \
       python3 -c 'import secrets; print(secrets.token_hex(16))'
  fi
}

# Predictable, documented defaults (matches POSTGRES_USER=argus already in
# .env.example) — deliberately NOT random. A self-hosted single-operator
# tool where the installer and the operator are the same person gains far
# more from "the credentials are always argus/argus, written down in the
# README" than from a random value that, once lost, means diagnosing a
# real bug (a stale Docker volume, a genuine misconfiguration) looks
# identical to "I don't remember what I generated." Anyone deploying this
# somewhere less trusted should change both immediately — see README.
ARGUS_DEFAULT_DB_PASSWORD="argus"
ARGUS_DEFAULT_ADMIN_PASSWORD_VALUE="argus"

# _env_set <file> <key> <value> — in-place substitution of a `KEY=...` line.
# Escapes the replacement for sed safely (values are hex/base64, but be safe
# regardless — this touches a secrets file).
_env_set() {
  local file="$1" key="$2" value="$3"
  local esc; esc="$(printf '%s' "$value" | sed -e 's/[\/&]/\\&/g' || true)"
  sed -i "s|^${key}=.*|${key}=${esc}|" "$file"
}

env_setup_run() {
  local profile="${1:-dev}"
  step "Environment configuration (.env)"

  if [[ ! -f "$ARGUS_ENV_EXAMPLE" ]]; then
    warn "no .env.example found — skipping .env generation"
    return 0
  fi

  if [[ -f "$ARGUS_ENV_FILE" ]]; then
    ok ".env already exists — leaving it untouched"
    _env_check_placeholders
    _env_append_missing_keys
    return 0
  fi

  info "generating .env from .env.example with fresh random secrets…"
  cp "$ARGUS_ENV_EXAMPLE" "$ARGUS_ENV_FILE"
  chmod 600 "$ARGUS_ENV_FILE"

  local db_pass jwt_secret orch_token fernet_key minio_secret
  db_pass="$ARGUS_DEFAULT_DB_PASSWORD"
  jwt_secret="$(_gen_hex32)"
  orch_token="$(_gen_hex32)"
  fernet_key="$(_gen_fernet_key)"
  minio_secret="$(_gen_password)"

  _env_set "$ARGUS_ENV_FILE" POSTGRES_PASSWORD "$db_pass"
  _env_set "$ARGUS_ENV_FILE" DATABASE_URL "postgresql+asyncpg://argus:${db_pass}@postgres:5432/argus"
  _env_set "$ARGUS_ENV_FILE" JWT_SECRET "$jwt_secret"
  _env_set "$ARGUS_ENV_FILE" SECRET_ENCRYPTION_KEY "$fernet_key"
  _env_set "$ARGUS_ENV_FILE" ORCH_INTERNAL_TOKEN "$orch_token"
  _env_set "$ARGUS_ENV_FILE" S3_SECRET_KEY "$minio_secret"
  if grep -q '^ARGUS_DEFAULT_ADMIN_PASSWORD=' "$ARGUS_ENV_FILE" 2>/dev/null; then
    _env_set "$ARGUS_ENV_FILE" ARGUS_DEFAULT_ADMIN_PASSWORD "$ARGUS_DEFAULT_ADMIN_PASSWORD_VALUE"
  else
    {
      echo ""
      echo "# Default web-login password for the bootstrap admin account"
      echo "# (ashborn-admin@ashborn.local). Predictable on purpose — see"
      echo "# POSTGRES_PASSWORD above. Change after first login."
      echo "ARGUS_DEFAULT_ADMIN_PASSWORD=${ARGUS_DEFAULT_ADMIN_PASSWORD_VALUE}"
    } >>"$ARGUS_ENV_FILE"
  fi

  if [[ "$profile" == "production" ]]; then
    _env_set "$ARGUS_ENV_FILE" ARGUS_ENV "production"
    _env_set "$ARGUS_ENV_FILE" ARGUS_ALLOW_SEED "false"
    _env_set "$ARGUS_ENV_FILE" ARGUS_TOOLS_BIN_DIR "${ARGUS_TOOLS_BIN_DIR:-$HOME/.local/bin}"
  fi

  ok ".env generated with fresh secrets (never logged, never printed)"
  if _env_check_placeholders; then :; fi
}

# _env_check_placeholders — never prints values, only which KEYs still need
# manual attention.
_env_check_placeholders() {
  [[ -f "$ARGUS_ENV_FILE" ]] || return 0
  # Only real `KEY=CHANGE_ME...` value assignments count — the file's own
  # header comment says the word "CHANGE_ME" too and isn't a real finding.
  local keys; keys="$(grep -E '^[A-Za-z_][A-Za-z0-9_]*=CHANGE_ME' "$ARGUS_ENV_FILE" 2>/dev/null | cut -d= -f1 | tr '\n' ' ' || true)"
  if [[ -n "$keys" ]]; then
    warn ".env still has placeholder values for: $keys"
    return 1
  fi
  ok "no CHANGE_ME placeholders remain in .env"
  return 0
}

# _env_append_missing_keys — additive-only: any KEY present in .env.example
# but absent from .env gets appended with .env.example's own default (never
# a secret value — those keys are always already in .env.example pre-filled
# with CHANGE_ME, which this function intentionally does NOT auto-fill; run
# doctor.sh to be told about those explicitly instead).
_env_append_missing_keys() {
  local added=0 line key
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]] || continue
    key="${BASH_REMATCH[1]}"
    if ! grep -q "^${key}=" "$ARGUS_ENV_FILE" 2>/dev/null; then
      echo "$line" >>"$ARGUS_ENV_FILE"
      added=$((added + 1))
    fi
  done <"$ARGUS_ENV_EXAMPLE"
  if [[ "$added" -gt 0 ]]; then
    fix "appended $added new configuration key(s) to .env that .env.example has gained since — review them (secrets, if any, are still CHANGE_ME placeholders)"
  fi
}
