#!/usr/bin/env bash
# scripts/lib/go.sh — Go toolchain detection and, only if missing/incompatible,
# a controlled install to ~/.local/go (never touches an existing distro Go
# install, never overwrites a working one).
# shellcheck shell=bash

if [[ -n "${ARGUS_GO_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_GO_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

GO_MIN_VERSION="${GO_MIN_VERSION:-1.23.0}"
ARGUS_GO_INSTALL_DIR="${ARGUS_GO_INSTALL_DIR:-$HOME/.local/go}"
ARGUS_GOBIN="${ARGUS_TOOLS_BIN_DIR:-$HOME/.local/bin}"

go_required_version() {
  local gomod="${ARGUS_ORCH_DIR}/go.mod"
  if [[ -f "$gomod" ]]; then
    grep -E '^go [0-9]' "$gomod" | head -n1 | awk '{print $2}'
  else
    echo "$GO_MIN_VERSION"
  fi
}

go_installed_version() {
  has_cmd go || { echo ""; return 1; }
  go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1 | sed 's/^go//'
}

go_check() {
  section "GO"
  if [[ ! -d "$ARGUS_ORCH_DIR" ]]; then
    info "no orchestrator/ directory — Go not applicable"
    return 0
  fi
  local gv; gv="$(go_installed_version || true)"
  if [[ -z "$gv" ]]; then
    fail "go not found"
    return 1
  fi
  local req; req="$(go_required_version)"
  if version_ge "$gv" "$req"; then
    ok "go $gv (>= $req required) — $(command -v go)"
  else
    fail "go $gv is older than the required $req"
    return 1
  fi
  return 0
}

# go_setup — installs Go to a controlled, user-owned directory ONLY when no
# compatible `go` is already on PATH. Never touches /usr/lib/go or any
# distro-managed installation.
go_setup() {
  step "Go toolchain"
  if [[ ! -d "$ARGUS_ORCH_DIR" ]]; then
    info "no orchestrator/ directory — skipping Go setup"
    return 0
  fi
  local req; req="$(go_required_version)"
  local gv; gv="$(go_installed_version || true)"

  if [[ -n "$gv" ]] && version_ge "$gv" "$req"; then
    ok "go $gv already satisfies >= $req — leaving existing installation untouched"
    return 0
  fi

  if [[ -n "$gv" ]]; then
    warn "go $gv found but is older than required $req"
  else
    info "go not found"
  fi

  if [[ -x "${ARGUS_GO_INSTALL_DIR}/bin/go" ]]; then
    local managed_v; managed_v="$("${ARGUS_GO_INSTALL_DIR}/bin/go" version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/^go//')"
    if version_ge "$managed_v" "$req"; then
      info "using existing Argus-managed Go at $ARGUS_GO_INSTALL_DIR"
      path_add_once "${ARGUS_GO_INSTALL_DIR}/bin"
      ok "go $managed_v"
      return 0
    fi
  fi

  local arch=""
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *) die "unsupported architecture for automatic Go install: $(uname -m) — install Go $req+ manually" ;;
  esac

  # Pin a known-good release line matching go.mod's major.minor; patch level
  # tracks upstream's latest for that line at time of writing.
  local goline; goline="$(cut -d. -f1,2 <<<"$req")"
  local gotag="${goline}.4"
  local url="https://go.dev/dl/go${gotag}.linux-${arch}.tar.gz"
  info "installing Go ${gotag} to ${ARGUS_GO_INSTALL_DIR} (does not touch any existing system Go)…"
  local tmp; tmp="$(mktemp -d "${ARGUS_TMP_DIR}/go-install.XXXXXX")"
  if ! curl -fsSL "$url" -o "$tmp/go.tar.gz"; then
    rm -rf "$tmp"
    die "failed to download Go from $url — install Go $req+ manually and re-run"
  fi
  rm -rf "$ARGUS_GO_INSTALL_DIR"
  mkdir -p "$(dirname "$ARGUS_GO_INSTALL_DIR")"
  tar -C "$(dirname "$ARGUS_GO_INSTALL_DIR")" -xzf "$tmp/go.tar.gz"
  mv "$(dirname "$ARGUS_GO_INSTALL_DIR")/go" "$ARGUS_GO_INSTALL_DIR" 2>/dev/null || true
  rm -rf "$tmp"

  if [[ ! -x "${ARGUS_GO_INSTALL_DIR}/bin/go" ]]; then
    die "Go install to $ARGUS_GO_INSTALL_DIR did not produce a working binary"
  fi
  path_add_once "${ARGUS_GO_INSTALL_DIR}/bin"
  ok "go $("${ARGUS_GO_INSTALL_DIR}/bin/go" version | grep -oE 'go[0-9.]+') installed"
}

# go_bin_dir — where `go install` puts binaries. Argus-managed tools always
# install here (matches ARGUS_TOOLS_BIN_DIR, the same directory the
# orchestrator itself looks in first — see tool_manifest in tools.sh).
go_bin_dir() {
  mkdir -p "$ARGUS_GOBIN"
  echo "$ARGUS_GOBIN"
}
