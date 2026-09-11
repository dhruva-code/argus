#!/usr/bin/env bash
# scripts/lib/permissions.sh — least-privilege checks. Only ever touches
# directories inside ARGUS_ROOT; never anything system-wide (§20).
# shellcheck shell=bash

if [[ -n "${ARGUS_PERMISSIONS_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_PERMISSIONS_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

ARGUS_OWNED_DIRS=("$ARGUS_LOG_DIR" "$ARGUS_RUNTIME_DIR" "$ARGUS_TMP_DIR" "$ARGUS_PID_DIR" "$ARGUS_BACKUP_DIR")

permissions_check() {
  section "PERMISSIONS"
  local problems=0
  if [[ "$(id -u)" -eq 0 ]]; then
    warn "running as root — the application itself should not run as root; installer tasks needing root use sudo per-command"
    problems=1
  else
    ok "not running as root (uid=$(id -u))"
  fi

  local d
  for d in "${ARGUS_OWNED_DIRS[@]}"; do
    if [[ ! -d "$d" ]]; then
      warn "$d missing"
      problems=1
      continue
    fi
    if [[ -w "$d" ]]; then
      ok "$d writable"
    else
      fail "$d is not writable by $(whoami)"
      problems=1
    fi
  done

  if [[ -f "$ARGUS_ENV_FILE" ]]; then
    local mode; mode="$(stat -c '%a' "$ARGUS_ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ARGUS_ENV_FILE" 2>/dev/null || echo '')"
    if [[ -n "$mode" && "$mode" != "600" && "$mode" != "640" ]]; then
      warn ".env is mode $mode — contains secrets, consider 'chmod 600 .env'"
    else
      ok ".env permissions ($mode)"
    fi
  fi
  return $((problems > 0 ? 1 : 0))
}

# permissions_repair — only ever chmod/chown paths under ARGUS_ROOT that this
# installer itself created. Never touches anything else on the system.
permissions_repair() {
  step "Repairing permissions"
  local d
  for d in "${ARGUS_OWNED_DIRS[@]}"; do
    mkdir -p "$d"
    if [[ "$(id -u)" -eq 0 || -O "$d" ]]; then
      chmod u+rwX "$d" 2>/dev/null && fix "restored permissions on $d" || true
    else
      warn "$d is owned by another user — not touching it (run as that user, or chown it yourself)"
    fi
  done
  if [[ -f "$ARGUS_ENV_FILE" ]]; then
    chmod 600 "$ARGUS_ENV_FILE" 2>/dev/null && fix "set .env to mode 600" || true
  fi
}
