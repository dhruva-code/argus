#!/usr/bin/env bash
# scripts/lib/tools.sh — the Tool Manager: reads config/tools.yaml (§11),
# detects/installs/health-checks each security tool (§12-14), and is
# Kali/Parrot-aware about preinstalled duplicates (§47/§48).
#
# Tools always install into ARGUS_TOOLS_BIN_DIR (default ~/.local/bin, or
# whatever the app's own ARGUS_TOOLS_BIN_DIR is set to) — the same directory
# the orchestrator itself checks first, before $PATH. That keeps every tool
# path centralized in one place instead of hard-coded through the codebase.
# shellcheck shell=bash

if [[ -n "${ARGUS_TOOLS_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_TOOLS_SH_LOADED=1

: "${ARGUS_ROOT:?common.sh must be sourced first}"

ARGUS_TOOLS_MANIFEST="${ARGUS_CONFIG_DIR}/tools.yaml"
ARGUS_TOOLS_BIN_DIR="${ARGUS_TOOLS_BIN_DIR:-$HOME/.local/bin}"

_yaml_strip_quotes() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"  # trim
  if [[ "$v" == \"*\" || "$v" == \'*\' ]]; then v="${v:1:${#v}-2}"; fi
  printf '%s' "$v"
}

# tools_yaml_get <tool> <field> — reads config/tools.yaml. Pure bash, no
# external YAML parser dependency (none of Kali/Parrot/Ubuntu/Debian ship
# `yq` by default).
tools_yaml_get() {
  local tool="$1" field="$2" in_block=0 cur_name=""
  local line key v
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+name:[[:space:]]*(.*)$ ]]; then
      cur_name="$(_yaml_strip_quotes "${BASH_REMATCH[1]}")"
      in_block=0
      [[ "$cur_name" == "$tool" ]] && in_block=1
      if [[ "$in_block" == "1" && "$field" == "name" ]]; then echo "$cur_name"; return 0; fi
      continue
    fi
    [[ "$in_block" == "1" ]] || continue
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    if [[ "$line" =~ ^[[:space:]]+([A-Za-z_]+):[[:space:]]?(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
      if [[ "$key" == "$field" ]]; then echo "$(_yaml_strip_quotes "$v")"; return 0; fi
    fi
  done <"$ARGUS_TOOLS_MANIFEST"
  echo ""
  return 0   # "field absent / tool unknown" is a normal empty result, not a shell-level failure
}

tools_yaml_names() {
  grep -E '^[[:space:]]*-[[:space:]]+name:' "$ARGUS_TOOLS_MANIFEST" 2>/dev/null |
    sed -E 's/^[[:space:]]*-[[:space:]]+name:[[:space:]]*//'
}

# tool_installed_version <tool> — resolves the binary (ARGUS_TOOLS_BIN_DIR
# first, then $PATH — matching the orchestrator's own lookup order) and runs
# its version command. Empty output means "not found" or "no version output
# could be parsed" — never treated as healthy either way (§14).
tool_installed_version() {
  local tool="$1"
  local bin; bin="$(tools_yaml_get "$tool" binary_path)"
  [[ -z "$bin" ]] && bin="$tool"
  local path=""
  [[ -x "${ARGUS_TOOLS_BIN_DIR}/${bin}" ]] && path="${ARGUS_TOOLS_BIN_DIR}/${bin}"
  [[ -z "$path" ]] && path="$(command -v "$bin" 2>/dev/null || true)"
  [[ -z "$path" ]] && return 1

  local vcmd; vcmd="$(tools_yaml_get "$tool" version_command)"
  if [[ -z "$vcmd" ]]; then
    echo "present"   # presence-only tool (e.g. assetfinder has no version flag)
    return 0
  fi
  local out; out="$("$path" "$vcmd" 2>&1 || true)"
  local re; re="$(tools_yaml_get "$tool" version_regex)"
  if [[ -n "$re" ]] && [[ "$out" =~ $re ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  extract_semver "$out"
}

tool_binary_path() {
  local tool="$1"
  local bin; bin="$(tools_yaml_get "$tool" binary_path)"
  [[ -z "$bin" ]] && bin="$tool"
  [[ -x "${ARGUS_TOOLS_BIN_DIR}/${bin}" ]] && { echo "${ARGUS_TOOLS_BIN_DIR}/${bin}"; return 0; }
  command -v "$bin" 2>/dev/null
}

# tool_health <tool> — prints a [PASS]/[FAIL]/[WARN] line. Never treats "the
# binary exists" as "healthy" on its own — the version must be readable and
# meet minimum_version (§14).
tool_health() {
  local tool="$1"
  local display; display="$(tools_yaml_get "$tool" display_name)"; display="${display:-$tool}"
  local optional; optional="$(tools_yaml_get "$tool" optional)"
  local minv; minv="$(tools_yaml_get "$tool" minimum_version)"
  local path; path="$(tool_binary_path "$tool" || true)"

  if [[ -z "$path" ]]; then
    if [[ "$optional" == "true" ]]; then
      warn "$display — not installed (optional)"
      return 0
    fi
    fail "$display — not installed"
    return 1
  fi

  local v; v="$(tool_installed_version "$tool" || true)"
  if [[ -z "$v" ]]; then
    warn "$display — installed at $path but version could not be determined"
    return 1
  fi
  if [[ "$v" == "present" ]]; then
    ok "$display — installed ($path, no version command)"
    return 0
  fi
  if [[ -n "$minv" ]] && ! version_ge "$v" "$minv"; then
    fail "$display $v — below minimum supported $minv ($path)"
    return 1
  fi
  ok "$display $v ($path)"
  return 0
}

# tools_check — the doctor.sh / install.sh --check pass over every manifest
# entry, plus a Kali/Parrot duplicate-binary report (§47/§48).
tools_check() {
  section "TOOLS"
  local failures=0 name
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    tool_health "$name" || failures=$((failures + 1))
  done < <(tools_yaml_names)

  if [[ "${OS_IS_KALI:-0}" == "1" || "${OS_IS_PARROT:-0}" == "1" ]]; then
    section "DUPLICATE BINARIES ($(os_label))"
    local any=0
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      local bin; bin="$(tools_yaml_get "$name" binary_path)"; bin="${bin:-$name}"
      os_report_duplicate_binaries "$bin" || any=1
    done < <(tools_yaml_names)
    [[ "$any" == "0" ]] && ok "no conflicting duplicate tool binaries found"
  fi
  return $((failures > 0 ? 1 : 0))
}

# tool_install <tool> — installs/updates via the manifest's install_method.
# Never blindly runs `go install tool@latest` for its own sake — only when
# the tool is missing or below minimum_version (§13).
tool_install() {
  local tool="$1"
  local display; display="$(tools_yaml_get "$tool" display_name)"; display="${display:-$tool}"
  local method; method="$(tools_yaml_get "$tool" install_method)"
  local minv; minv="$(tools_yaml_get "$tool" minimum_version)"

  local have; have="$(tool_installed_version "$tool" || true)"
  if [[ -n "$have" && "$have" != "present" ]] && { [[ -z "$minv" ]] || version_ge "$have" "$minv"; } && [[ "$ARGUS_FORCE" != "1" ]]; then
    ok "$display $have already satisfies minimum ($minv) — skipping"
    return 0
  fi
  if [[ "$have" == "present" ]]; then
    ok "$display already installed (presence-only tool)"
    return 0
  fi

  mkdir -p "$ARGUS_TOOLS_BIN_DIR"
  case "$method" in
    go)
      local pkg; pkg="$(tools_yaml_get "$tool" go_package)"
      [[ -z "$pkg" ]] && { fail "$display: no go_package configured"; return 1; }
      has_cmd go || { fail "$display: go toolchain not available"; return 1; }
      info "installing $display via 'go install $pkg'…"
      if GOBIN="$ARGUS_TOOLS_BIN_DIR" run_cmd "go install $pkg" -- go install -v "$pkg"; then
        ok "$display installed to $ARGUS_TOOLS_BIN_DIR"
      else
        fail "$display: go install failed"
        return 1
      fi
      ;;
    apt)
      local pkg; pkg="$(tools_yaml_get "$tool" apt_package)"
      [[ -z "$pkg" ]] && { fail "$display: no apt_package configured"; return 1; }
      pkg_install "$pkg" || { fail "$display: apt install failed"; return 1; }
      ;;
    script)
      local url; url="$(tools_yaml_get "$tool" script_url)"
      [[ -z "$url" ]] && { fail "$display: no script_url configured"; return 1; }
      info "installing $display via upstream install script…"
      if curl -fsSL "$url" | run_cmd "run install script" -- sh -s -- -b "$ARGUS_TOOLS_BIN_DIR"; then
        ok "$display installed to $ARGUS_TOOLS_BIN_DIR"
      else
        fail "$display: install script failed"
        return 1
      fi
      ;;
    binary_archive)
      _tool_install_binary_archive "$tool" "$display" || return 1
      ;;
    *)
      warn "$display: no automatic install method ($method) — install manually"
      return 1
      ;;
  esac

  local newv; newv="$(tool_installed_version "$tool" || true)"
  if [[ -z "$newv" ]]; then
    fail "$display: installed but health check still fails — see ${ARGUS_LOG_DIR}/install.log"
    return 1
  fi
  ok "$display $newv verified after install"
}

_tool_install_binary_archive() {
  local tool="$1" display="$2"
  local tmpl; tmpl="$(tools_yaml_get "$tool" binary_url_template)"
  local version; version="$(tools_yaml_get "$tool" recommended_version)"
  [[ -z "$tmpl" || -z "$version" ]] && { fail "$display: binary_url_template/recommended_version not configured"; return 1; }
  local arch=""
  case "$(uname -m)" in
    x86_64) arch="x64" ;;
    aarch64) arch="arm64" ;;
    *) fail "$display: unsupported architecture $(uname -m)"; return 1 ;;
  esac
  local url="${tmpl//\{version\}/$version}"
  url="${url//\{arch\}/$arch}"
  local bin; bin="$(tools_yaml_get "$tool" binary_path)"; bin="${bin:-$tool}"

  info "downloading $display $version…"
  local tmp; tmp="$(mktemp -d "${ARGUS_TMP_DIR}/tool-install.XXXXXX")"
  if ! curl -fsSL "$url" -o "$tmp/archive.tar.gz"; then
    rm -rf "$tmp"
    fail "$display: download failed from $url"
    return 1
  fi
  tar -C "$tmp" -xzf "$tmp/archive.tar.gz" 2>/dev/null || true
  local found; found="$(find "$tmp" -maxdepth 2 -type f -name "$bin" | head -n1 || true)"
  if [[ -z "$found" ]]; then
    rm -rf "$tmp"
    fail "$display: archive did not contain a '$bin' binary"
    return 1
  fi
  install -m 0755 "$found" "${ARGUS_TOOLS_BIN_DIR}/${bin}"
  rm -rf "$tmp"
  ok "$display installed to ${ARGUS_TOOLS_BIN_DIR}/${bin}"
}

# tools_install_all — installs/updates every non-optional tool, then
# optional ones on a best-effort basis (a failed optional tool is a WARN,
# not a blocker for the rest of install.sh).
tools_install_all() {
  step "Security tools"
  path_add_once "$ARGUS_TOOLS_BIN_DIR"
  local name failures=0
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    local optional; optional="$(tools_yaml_get "$name" optional)"
    if tool_install "$name"; then
      :
    elif [[ "$optional" == "true" ]]; then
      warn "$name: optional tool install failed — continuing"
    else
      failures=$((failures + 1))
    fi
  done < <(tools_yaml_names)
  if [[ "$failures" -gt 0 ]]; then
    warn "$failures required tool(s) failed to install — run './doctor.sh --tools' for details"
  fi
  return 0
}

tools_repair() {
  step "Repairing tools"
  local name
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    local v; v="$(tool_installed_version "$name" || true)"
    local minv; minv="$(tools_yaml_get "$name" minimum_version)"
    if [[ -z "$v" ]] || { [[ -n "$minv" ]] && ! version_ge "$v" "$minv"; }; then
      fix "reinstalling $name"
      tool_install "$name" || true
    fi
  done < <(tools_yaml_names)
}
