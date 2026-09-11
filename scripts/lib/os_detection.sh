#!/usr/bin/env bash
# scripts/lib/os_detection.sh — OS/arch/package-manager/init-system detection.
#
# Reads /etc/os-release rather than assuming Ubuntu. Gives Kali and Parrot
# first-class identities (both are Debian derivatives but must not be
# silently treated as "debian" — their tool ecosystem and package sources
# differ, see §47/§48).
# shellcheck shell=bash

if [[ -n "${ARGUS_OS_DETECTION_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_OS_DETECTION_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

# Populated by os_detect(). Empty until called.
OS_ID=""            # kali | parrot | ubuntu | debian | linuxmint | pop | unknown
OS_ID_LIKE=""        # raw ID_LIKE from os-release
OS_NAME=""           # pretty name
OS_VERSION=""        # VERSION_ID
OS_CODENAME=""
OS_ARCH=""           # x86_64 | aarch64 | ...
OS_KERNEL=""
OS_PKG_MANAGER=""    # apt | dnf | pacman | unsupported
OS_HAS_SYSTEMD=0
OS_SHELL=""
OS_IS_KALI=0
OS_IS_PARROT=0
OS_IS_DEBIAN_FAMILY=0
OS_SUPPORTED=0       # 1 = primary/compat supported, 0 = best-effort only

os_detect() {
  OS_ARCH="$(uname -m)"
  OS_KERNEL="$(uname -r)"
  OS_SHELL="$(basename "${SHELL:-unknown}")"

  if has_cmd systemctl && [[ -d /run/systemd/system ]]; then OS_HAS_SYSTEMD=1; fi

  if [[ -r /etc/os-release ]]; then
    local rel; rel="$(
      # shellcheck disable=SC1091
      . /etc/os-release
      printf 'ID=%s\nID_LIKE=%s\nNAME=%s\nVERSION_ID=%s\nVERSION_CODENAME=%s\n' \
        "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-${NAME:-Unknown Linux}}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}"
    )"
    OS_ID="$(grep '^ID=' <<<"$rel" | cut -d= -f2-)"
    OS_ID_LIKE="$(grep '^ID_LIKE=' <<<"$rel" | cut -d= -f2-)"
    OS_NAME="$(grep '^NAME=' <<<"$rel" | cut -d= -f2-)"
    OS_VERSION="$(grep '^VERSION_ID=' <<<"$rel" | cut -d= -f2-)"
    OS_CODENAME="$(grep '^VERSION_CODENAME=' <<<"$rel" | cut -d= -f2-)"
  else
    OS_ID="unknown"; OS_NAME="Unknown (no /etc/os-release)"
  fi

  case "$OS_ID" in
    kali) OS_IS_KALI=1; OS_IS_DEBIAN_FAMILY=1; OS_SUPPORTED=1 ;;
    parrot) OS_IS_PARROT=1; OS_IS_DEBIAN_FAMILY=1; OS_SUPPORTED=1 ;;
    ubuntu|debian) OS_IS_DEBIAN_FAMILY=1; OS_SUPPORTED=1 ;;
    linuxmint|pop) OS_IS_DEBIAN_FAMILY=1; OS_SUPPORTED=1 ;;
    *)
      # Debian/Ubuntu derivative not explicitly listed — best-effort support
      # if ID_LIKE says so (covers most other *buntu/debian spins).
      if [[ "$OS_ID_LIKE" == *debian* || "$OS_ID_LIKE" == *ubuntu* ]]; then
        OS_IS_DEBIAN_FAMILY=1; OS_SUPPORTED=1
      fi
      ;;
  esac

  if has_cmd apt-get; then OS_PKG_MANAGER="apt"
  elif has_cmd dnf; then OS_PKG_MANAGER="dnf"
  elif has_cmd pacman; then OS_PKG_MANAGER="pacman"
  else OS_PKG_MANAGER="unsupported"
  fi

  export OS_ID OS_ID_LIKE OS_NAME OS_VERSION OS_CODENAME OS_ARCH OS_KERNEL \
    OS_PKG_MANAGER OS_HAS_SYSTEMD OS_SHELL OS_IS_KALI OS_IS_PARROT \
    OS_IS_DEBIAN_FAMILY OS_SUPPORTED
}

os_label() {
  case "$OS_ID" in
    kali) echo "Kali Linux" ;;
    parrot) echo "Parrot Security OS" ;;
    *) echo "$OS_NAME" ;;
  esac
}

os_print_summary() {
  section "SYSTEM"
  if [[ "$OS_SUPPORTED" == "1" ]]; then
    ok "$(os_label) ${OS_VERSION:+($OS_VERSION)}"
  else
    warn "$(os_label) — not a recognized Debian/Ubuntu derivative; best-effort only"
  fi
  [[ "$OS_ARCH" == "x86_64" || "$OS_ARCH" == "aarch64" ]] && ok "architecture $OS_ARCH" || warn "architecture $OS_ARCH (untested)"
  ok "kernel $OS_KERNEL"
  [[ "$OS_PKG_MANAGER" == "apt" ]] && ok "package manager: apt" || warn "package manager: $OS_PKG_MANAGER (only apt is fully supported)"
  [[ "$OS_HAS_SYSTEMD" == "1" ]] && ok "systemd available" || info "systemd not available — run.sh will manage processes directly"
  ok "shell: $OS_SHELL"
}

# Kali/Parrot ship many security tools preinstalled at /usr/bin, while
# go-installed tools this project manages land in ARGUS_TOOLS_BIN_DIR
# (typically /usr/local/bin or ~/.local/bin). Both can legitimately be on
# PATH at once; report it so the operator can pick which one wins rather
# than silently shadowing one.
os_report_duplicate_binaries() {
  local bin="$1" found=() p
  local -a search_dirs=(/usr/bin /usr/local/bin /usr/sbin "$HOME/.local/bin" "$HOME/go/bin")
  for p in "${search_dirs[@]}"; do
    [[ -x "$p/$bin" ]] && found+=("$p/$bin")
  done
  if [[ "${#found[@]}" -gt 1 ]]; then
    warn "multiple '$bin' binaries found on this system:"
    local f
    for f in "${found[@]}"; do
      local v=""
      v="$("$f" --version 2>&1 | head -n1 || true)"
      echo "    ${C_GRAY}$f${C_RESET}  ${v}"
    done
    local active; active="$(command -v "$bin" 2>/dev/null || true)"
    [[ -n "$active" ]] && info "PATH currently resolves '$bin' -> $active"
    return 1
  fi
  return 0
}
