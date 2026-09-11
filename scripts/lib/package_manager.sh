#!/usr/bin/env bash
# scripts/lib/package_manager.sh — apt-based system package installation.
#
# Deliberately apt-only for now (§10/§47/§48: Kali, Parrot, Ubuntu, Debian and
# every listed compatibility distro are all apt-based). Never runs a
# system-wide upgrade — only ever installs the specific packages this
# project needs, and only the ones actually missing.
# shellcheck shell=bash

if [[ -n "${ARGUS_PACKAGE_MANAGER_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_PACKAGE_MANAGER_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

# The complete set of system packages Argus needs. Kept centralized here
# rather than scattered across the codebase (§10).
ARGUS_SYSTEM_PACKAGES=(
  curl wget git jq unzip zip tar make gcc g++ pkg-config
  build-essential ca-certificates dnsutils net-tools
  python3 python3-venv python3-pip
)

_apt_updated=0

apt_update_once() {
  [[ "$OS_PKG_MANAGER" == "apt" ]] || return 0
  [[ "$_apt_updated" == "1" ]] && return 0
  info "refreshing apt package index…"
  if sudo_run apt-get update -qq; then
    _apt_updated=1
  else
    warn "apt-get update failed — package installs below may use a stale index"
  fi
}

pkg_installed() {
  # dpkg -s is a metadata check only — no network, no root needed.
  dpkg -s "$1" >/dev/null 2>&1
}

# pkg_install <pkg...> — installs only the packages not already present.
# Never runs `apt-get upgrade`/`dist-upgrade`/`full-upgrade`.
pkg_install() {
  [[ "$OS_PKG_MANAGER" == "apt" ]] || { warn "package manager '$OS_PKG_MANAGER' is not apt — install manually: $*"; return 1; }
  local missing=() p
  for p in "$@"; do
    pkg_installed "$p" || missing+=("$p")
  done
  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi
  apt_update_once
  info "installing: ${missing[*]}"
  if sudo_run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"; then
    ok "installed: ${missing[*]}"
    return 0
  fi
  fail "apt-get install failed for: ${missing[*]}"
  return 1
}

# check_system_packages — report-only pass used by install.sh --check and
# doctor.sh (no installation attempted).
check_system_packages() {
  section "SYSTEM PACKAGES"
  local p all_ok=0
  for p in "${ARGUS_SYSTEM_PACKAGES[@]}"; do
    if pkg_installed "$p"; then
      ok "$p"
    else
      warn "$p missing"
      all_ok=1
    fi
  done
  return $all_ok
}

install_system_packages() {
  step "System packages"
  pkg_install "${ARGUS_SYSTEM_PACKAGES[@]}"
}

# Preflight-only command checks (curl/wget/unzip/tar/git/build tools) — a
# thin wrapper the preflight step in install.sh uses before it decides
# whether package installation is even necessary.
preflight_check_commands() {
  section "PRE-FLIGHT: required commands"
  local missing=0
  local c
  for c in git curl wget unzip tar make gcc; do
    if has_cmd "$c"; then
      ok "$c"
    else
      warn "$c not found"
      missing=1
    fi
  done
  return $missing
}
