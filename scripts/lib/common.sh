#!/usr/bin/env bash
# scripts/lib/common.sh — shared foundation for install.sh / run.sh / doctor.sh.
#
# Every top-level script and every other lib/*.sh file sources this first.
# It must never assume the caller's current working directory — ARGUS_ROOT is
# always derived from this file's own location on disk.
#
# shellcheck shell=bash

# Guard against being sourced twice (each lib file also guards itself).
if [[ -n "${ARGUS_COMMON_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_COMMON_SH_LOADED=1

set -Eeuo pipefail

# ── Project root & standard directories ─────────────────────────────────────
_argus_common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARGUS_ROOT="$(cd "${_argus_common_dir}/../.." && pwd)"
unset _argus_common_dir

ARGUS_LIB_DIR="${ARGUS_ROOT}/scripts/lib"
ARGUS_CONFIG_DIR="${ARGUS_ROOT}/config"
ARGUS_LOG_DIR="${ARGUS_ROOT}/logs"
ARGUS_RUNTIME_DIR="${ARGUS_ROOT}/runtime"
ARGUS_TMP_DIR="${ARGUS_RUNTIME_DIR}/tmp"
ARGUS_PID_DIR="${ARGUS_RUNTIME_DIR}/pids"
ARGUS_BACKUP_DIR="${ARGUS_ROOT}/backups"
ARGUS_GATEWAY_DIR="${ARGUS_ROOT}/apis/gateway"
ARGUS_ORCH_DIR="${ARGUS_ROOT}/orchestrator"
ARGUS_WEB_DIR="${ARGUS_ROOT}/web"
ARGUS_VENV_DIR="${ARGUS_GATEWAY_DIR}/.venv"
ARGUS_ENV_FILE="${ARGUS_ROOT}/.env"
ARGUS_ENV_EXAMPLE="${ARGUS_ROOT}/.env.example"

mkdir -p "$ARGUS_LOG_DIR" "$ARGUS_TMP_DIR" "$ARGUS_PID_DIR" "$ARGUS_BACKUP_DIR"

# ── CLI-wide flags (top-level scripts parse args into these before use) ────
ARGUS_NO_COLOR="${ARGUS_NO_COLOR:-0}"
ARGUS_QUIET="${ARGUS_QUIET:-0}"
ARGUS_VERBOSE="${ARGUS_VERBOSE:-0}"
ARGUS_NON_INTERACTIVE="${ARGUS_NON_INTERACTIVE:-0}"
ARGUS_FORCE="${ARGUS_FORCE:-0}"

# Auto-disable color when not attached to a terminal or output is redirected.
if [[ ! -t 1 ]]; then ARGUS_NO_COLOR=1; fi

# ── Colors ───────────────────────────────────────────────────────────────
if [[ "$ARGUS_NO_COLOR" == "1" ]]; then
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_GRAY=""
else
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_GRAY=$'\033[90m'
fi

# ── Print helpers ────────────────────────────────────────────────────────
# All of these also go to logs/*.log via logging.sh once it's loaded (it
# defines log_line; before that they just print).
_argus_emit() {
  local stream="$1"; shift
  if [[ "$ARGUS_QUIET" == "1" && "$stream" == "stdout" ]]; then return 0; fi
  if [[ "$stream" == "stderr" ]]; then echo -e "$*" >&2; else echo -e "$*"; fi
  if declare -F log_line >/dev/null 2>&1; then log_line "$*"; fi
}

ok()    { _argus_emit stdout "${C_GREEN}[OK]${C_RESET}   $*"; }
info()  { _argus_emit stdout "${C_BLUE}[INFO]${C_RESET} $*"; }
warn()  { _argus_emit stderr "${C_YELLOW}[WARN]${C_RESET} $*"; }
fail()  { _argus_emit stderr "${C_RED}[FAIL]${C_RESET} $*"; }
fix()   { _argus_emit stdout "${C_CYAN}[FIX]${C_RESET}  $*"; }
step()  { _argus_emit stdout "${C_BOLD}==>${C_RESET} $*"; }
verbose() { [[ "$ARGUS_VERBOSE" == "1" ]] && _argus_emit stdout "${C_GRAY}[DEBUG] $*${C_RESET}"; return 0; }

die() {
  fail "$*"
  exit 1
}

# ── Confirmation prompt (skipped/auto-yes in non-interactive mode) ─────────
confirm() {
  local prompt="${1:-Continue?}" default="${2:-n}"
  if [[ "$ARGUS_NON_INTERACTIVE" == "1" ]]; then
    verbose "non-interactive: auto-answering '$default' to: $prompt"
    [[ "$default" == "y" ]] && return 0 || return 1
  fi
  local suffix="[y/N]"
  [[ "$default" == "y" ]] && suffix="[Y/n]"
  local reply=""
  read -r -p "$prompt $suffix " reply || true
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy] ]]
}

# ── Command existence / version helpers ─────────────────────────────────────
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Extract the first x.y.z-shaped token from arbitrary tool --version output.
extract_semver() {
  grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$1" | head -n1
}

# version_ge A B -> true if version A >= version B (lenient dotted-integer compare)
version_ge() {
  local a="$1" b="$2"
  [[ -z "$b" ]] && return 0
  [[ -z "$a" ]] && return 1
  local IFS=.
  local -a av=($a) bv=($b)
  local i
  for ((i = 0; i < 3; i++)); do
    local x="${av[i]:-0}" y="${bv[i]:-0}"
    x="${x//[^0-9]/}"; y="${y//[^0-9]/}"
    x="${x:-0}"; y="${y:-0}"
    if ((10#$x > 10#$y)); then return 0; fi
    if ((10#$x < 10#$y)); then return 1; fi
  done
  return 0
}

# ── Safe command execution with logging ─────────────────────────────────────
# run_cmd <description> -- <command...>
# Logs the command + exit code; does not abort the caller on failure (caller
# checks the return code) unless run_cmd_or_die is used instead.
run_cmd() {
  local desc="$1"; shift
  [[ "${1:-}" == "--" ]] && shift
  verbose "$desc: $*"
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if declare -F log_cmd >/dev/null 2>&1; then log_cmd "$desc" "$*" "$rc" "$out"; fi
  if [[ $rc -ne 0 ]]; then
    verbose "command failed ($rc): $out"
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
  return $rc
}

run_cmd_or_die() {
  local desc="$1"; shift
  # Caller already passes its own "--" (run_cmd_or_die "desc" -- cmd args...);
  # forward as-is rather than adding a second one.
  run_cmd "$desc" "$@" || die "$desc failed — see ${ARGUS_LOG_DIR}/install.log"
}

# sudo_run: use sudo only when not already root, and only for the one command.
#
# Special-cases a leading "-u <user>" the same way `sudo -u <user> cmd...`
# does: "run this specific command as <user>", not "run this as root". When
# already root, `"$@"` can't just be exec'd directly in that case — "-u" is
# a sudo-specific flag, meaningless as a literal command name (confirmed by
# a real failure: `sudo_run -u postgres psql ...` invoked from a script
# already running as root, via `sudo ./repair.sh`, tried to execute a
# program literally named "-u" and failed with "-u: command not found").
# runuser (util-linux, present on every Debian/Ubuntu derivative this
# project supports) is root's direct equivalent of `sudo -u`.
sudo_run() {
  if [[ "$(id -u)" -eq 0 ]]; then
    if [[ "${1:-}" == "-u" ]]; then
      local target_user="$2"
      shift 2
      runuser -u "$target_user" -- "$@"
    else
      "$@"
    fi
  elif has_cmd sudo; then
    sudo "$@"
  else
    die "root privileges required for: $* (sudo not available — re-run as root)"
  fi
}

# reject_sudo_wrapper — call once from each top-level script (install.sh,
# run.sh, doctor.sh, repair.sh, update.sh) right after logging is set up.
#
# These scripts already self-elevate only the specific commands that need
# root (sudo_run, above) — running the *whole* script via `sudo` is never
# required and actively breaks things: $HOME silently becomes /root, which
# moves every ~/.local-scoped path this project uses (ARGUS_TOOLS_BIN_DIR,
# the managed Go install, and — the specific failure this was written for
# — Docker's own per-user context under ~/.docker) out from under the
# account that actually set them up. A real run reproduced exactly this:
# `sudo ./repair.sh --reset-database` couldn't find Docker at all and fell
# through to a broken native-Postgres path instead.
#
# Only refuses the *sudo-elevated-from-a-regular-user* case ($SUDO_USER
# set) — a box where the login account genuinely is root (common on
# minimal cloud VM images, no sudo involved at all) is left alone.
reject_sudo_wrapper() {
  if [[ "$(id -u)" -eq 0 && -n "${SUDO_USER:-}" ]]; then
    fail "don't run this with sudo — it already elevates only the specific commands that need root."
    fail "running the whole script as root via sudo changes \$HOME from ${SUDO_USER}'s to /root's, which moves"
    fail "every ~/.local-scoped path this project uses (installed tools, the managed Go toolchain, Docker's"
    fail "own per-user context) out from under the account that actually set them up — this is exactly what"
    fail "caused a real 'Docker not detected, fell back to a broken native Postgres path' failure."
    die "re-run as: ${SUDO_USER}\$ $0 $* (no sudo — you'll be prompted for a password only for the specific steps that need it)"
  fi
}

# ── Idempotent PATH management (never appends duplicate entries) ───────────
# Adds a directory to the *current* shell's PATH (for this script run) and,
# only if not already present, to the user's shell rc file so future shells
# pick it up too. Safe to call repeatedly.
path_add_once() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  case ":$PATH:" in
    *":$dir:"*) ;;
    *) export PATH="$dir:$PATH" ;;
  esac
  local rc=""
  if [[ -n "${BASH_VERSION:-}" && -f "$HOME/.bashrc" ]]; then rc="$HOME/.bashrc"
  elif [[ -f "$HOME/.profile" ]]; then rc="$HOME/.profile"
  fi
  [[ -z "$rc" ]] && return 0
  local marker="# added by Argus install.sh"
  if ! grep -qF "$dir" "$rc" 2>/dev/null; then
    { echo ""; echo "$marker"; echo "export PATH=\"$dir:\$PATH\""; } >>"$rc"
    verbose "added $dir to PATH in $rc"
  fi
}

# ── Runtime directory ownership (application-owned dirs only — never touches
#    anything outside ARGUS_ROOT) ───────────────────────────────────────────
ensure_owned_dir() {
  local dir="$1"
  mkdir -p "$dir"
  if [[ -O "$dir" || "$(id -u)" -eq 0 ]]; then
    chmod u+rwX "$dir" 2>/dev/null || true
  fi
}

# ── PID file helpers (used by services.sh) ──────────────────────────────────
pid_file() { echo "${ARGUS_PID_DIR}/$1.pid"; }

is_running() {
  local pf; pf="$(pid_file "$1")"
  [[ -f "$pf" ]] || return 1
  local pid; pid="$(cat "$pf" 2>/dev/null || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

# ── Port helper ──────────────────────────────────────────────────────────
# Prints "PID PROCESS" for whatever is listening on $1, or nothing. Never
# raises under `set -e` (pipe stages finding no match are expected, not
# errors) — always returns 0.
port_owner() {
  local port="$1" pid=""
  if has_cmd ss; then
    pid="$( (ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {print $0}' | grep -oE 'pid=[0-9]+' | head -n1 | cut -d= -f2) || true )"
  fi
  [[ -z "$pid" ]] && return 0
  local proc=""
  [[ -r "/proc/$pid/comm" ]] && proc="$(cat "/proc/$pid/comm" 2>/dev/null || true)"
  echo "$pid ${proc:-unknown}"
  return 0
}

port_in_use() {
  local port="$1"
  if has_cmd ss; then
    ss -ltn 2>/dev/null | awk -v p=":$port" '$4 ~ p"$"' | grep -q .
  elif has_cmd lsof; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    { exec 3<>"/dev/tcp/127.0.0.1/$port"; } 2>/dev/null && { exec 3>&-; return 0; } || return 1
  fi
}

# ── Minimal YAML-lite reader (flat key: value files — config/versions.yaml,
#    config/system.yaml). No nesting, no lists. Comments (#) and blank lines
#    are ignored. See tools.sh for the list-of-blocks reader used by
#    config/tools.yaml. ──────────────────────────────────────────────────
yaml_flat_get() {
  local file="$1" key="$2" default="${3:-}"
  [[ -f "$file" ]] || { echo "$default"; return 0; }
  local val
  val="$(grep -E "^${key}:" "$file" 2>/dev/null | head -n1 | sed -E "s/^${key}:[[:space:]]*//" || true)"
  val="${val%\"}"; val="${val#\"}"
  val="${val%\'}"; val="${val#\'}"
  val="$(sed -E 's/[[:space:]]+#.*$//' <<<"$val")"
  val="$(sed -E 's/[[:space:]]+$//' <<<"$val")"
  echo "${val:-$default}"
}

# ── Section header (used by doctor.sh's categorized output) ────────────────
section() {
  [[ "$ARGUS_QUIET" == "1" ]] && return 0
  echo ""
  echo "${C_BOLD}${C_CYAN}$*${C_RESET}"
}

export ARGUS_ROOT ARGUS_LIB_DIR ARGUS_CONFIG_DIR ARGUS_LOG_DIR ARGUS_RUNTIME_DIR \
  ARGUS_TMP_DIR ARGUS_PID_DIR ARGUS_BACKUP_DIR ARGUS_GATEWAY_DIR ARGUS_ORCH_DIR \
  ARGUS_WEB_DIR ARGUS_VENV_DIR ARGUS_ENV_FILE ARGUS_ENV_EXAMPLE
