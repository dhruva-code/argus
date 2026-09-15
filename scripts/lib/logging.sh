#!/usr/bin/env bash
# scripts/lib/logging.sh — structured file logging for install/run/doctor.
#
# Never logs secrets: any line containing one of the sensitive key names
# below has its value redacted before being written to disk.
# shellcheck shell=bash

if [[ -n "${ARGUS_LOGGING_SH_LOADED:-}" ]]; then return 0 2>/dev/null || exit 0; fi
ARGUS_LOGGING_SH_LOADED=1

: "${ARGUS_LOG_DIR:?common.sh must be sourced before logging.sh}"

# Which file this process' plain log lines go to. Top-level scripts set this
# before doing real work (e.g. LOG_TARGET=install in install.sh).
LOG_TARGET="${LOG_TARGET:-runtime}"

_log_file_for() {
  case "$1" in
    install) echo "${ARGUS_LOG_DIR}/install.log" ;;
    doctor) echo "${ARGUS_LOG_DIR}/doctor.log" ;;
    repair) echo "${ARGUS_LOG_DIR}/repair.log" ;;
    update) echo "${ARGUS_LOG_DIR}/update.log" ;;
    worker) echo "${ARGUS_LOG_DIR}/worker.log" ;;
    scanner) echo "${ARGUS_LOG_DIR}/scanner.log" ;;
    *) echo "${ARGUS_LOG_DIR}/runtime.log" ;;
  esac
}

# Patterns whose value gets replaced with "***REDACTED***" before logging.
# Matches `KEY=value`, `KEY: value`, and `--key value` shapes case-insensitively.
_SECRET_KEY_RE='(pass(word)?|secret|token|api[_-]?key|jwt|fernet|cookie|authorization|credential)'

redact_secrets() {
  local s="$1"
  # `Authorization: Bearer <token>` / `Basic <token>` — must run BEFORE the
  # generic KEY=value pass below, which would otherwise consume just the
  # "Bearer"/"Basic" scheme word as the "value" and leave the actual token
  # (the next token) exposed.
  s="$(sed -E "s/(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+\/=-]+/\1 ***REDACTED***/Ig" <<<"$s")"
  # scheme://user:password@host — connection-string-shaped credentials
  # (postgresql://, redis://, https://, ...). Must also run before the
  # generic KEY=value pass, since "postgresql+asyncpg://user:pass@host" has
  # no key name at all for that pass to key off of.
  s="$(sed -E 's#(://[A-Za-z0-9._-]*:)[^@[:space:]]+(@)#\1***REDACTED***\2#g' <<<"$s")"
  # KEY=value / KEY: "value" style (env vars, JSON, config dumps).
  s="$(sed -E "s/([A-Za-z0-9_.-]*${_SECRET_KEY_RE}[A-Za-z0-9_.-]*[[:space:]]*[:=][[:space:]]*)[^[:space:]\"']+/\1***REDACTED***/Ig" <<<"$s")"
  printf '%s' "$s"
}

log_init() {
  local target="${1:-$LOG_TARGET}"
  local f; f="$(_log_file_for "$target")"
  mkdir -p "$(dirname "$f")"
  : >>"$f"
  # Rotate if a log has grown past 10MB — keep one previous copy.
  local size=0
  if [[ -f "$f" ]]; then size="$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)"; fi
  if [[ "$size" -gt 10485760 ]]; then
    mv -f "$f" "${f}.1" 2>/dev/null || true
    : >"$f"
  fi
}

# log_line <message> — plain line to the current target's log, timestamped.
log_line() {
  local target="$LOG_TARGET"
  local f; f="$(_log_file_for "$target")"
  mkdir -p "$(dirname "$f")" 2>/dev/null || return 0
  local msg; msg="$(redact_secrets "$1")"
  # strip ANSI color codes before writing to disk
  msg="$(sed -E 's/\x1b\[[0-9;]*m//g' <<<"$msg")"
  printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$msg" >>"$f" 2>/dev/null || true
}

# log_cmd <description> <command> <exit_code> <output> — structured command
# record, used by common.sh's run_cmd. Always redacted.
log_cmd() {
  local desc="$1" cmd="$2" rc="$3" out="$4"
  local f; f="$(_log_file_for "$LOG_TARGET")"
  {
    printf '%s component=%s command=%q exit_code=%s\n' \
      "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$(redact_secrets "$desc")" "$(redact_secrets "$cmd")" "$rc"
    if [[ "$rc" != "0" && -n "$out" ]]; then
      printf '  error: %s\n' "$(redact_secrets "$out" | tail -n 20)"
    fi
  } >>"$f" 2>/dev/null || true
}

# log_error <component> <phase> <error> [retryable] — the structured error
# format §46 asks for (Component/Phase/Timestamp/Error/Retryable). Stack
# traces (if any get passed in $3) stay in the log file only — never printed
# to the terminal for normal users; callers print a short `fail` line instead.
log_error() {
  local component="$1" phase="$2" error="$3" retryable="${4:-unknown}"
  local f; f="$(_log_file_for "$LOG_TARGET")"
  {
    printf '%s component=%s phase=%s retryable=%s\n' \
      "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$component" "$phase" "$retryable"
    printf '  error: %s\n' "$(redact_secrets "$error")"
  } >>"$f" 2>/dev/null || true
}
