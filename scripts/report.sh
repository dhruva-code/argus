#!/usr/bin/env bash
# scripts/report.sh — `doctor.sh --report` (§33). Builds a sanitized
# diagnostic archive: OS/version info, service + tool status, configuration
# *structure* (key names only, never values), error summaries, redacted
# logs, and a performance snapshot. Never includes credentials or secrets.
set -Eeuo pipefail

: "${ARGUS_ROOT:?common.sh must be sourced first}"
# shellcheck source=lib/diagnostics.sh
source "${ARGUS_LIB_DIR}/diagnostics.sh"
# shellcheck source=lib/performance.sh
source "${ARGUS_LIB_DIR}/performance.sh"

report_generate() {
  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local staging; staging="$(mktemp -d "${ARGUS_TMP_DIR}/doctor-report.XXXXXX")"
  local out="${ARGUS_BACKUP_DIR}/doctor-report-${stamp}.tar.gz"

  step "Generating diagnostic report"

  {
    echo "Argus diagnostic report — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "This archive contains no secret values — only configuration key"
    echo "names, service/tool status, and redacted log excerpts."
  } >"${staging}/README.txt"

  ARGUS_NO_COLOR=1 diagnostics_run all >"${staging}/diagnostics.txt" 2>&1 || true
  ARGUS_NO_COLOR=1 performance_snapshot >"${staging}/performance.txt" 2>&1 || true

  if [[ -f "$ARGUS_ENV_FILE" ]]; then
    grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$ARGUS_ENV_FILE" 2>/dev/null | sed 's/=$//' \
      >"${staging}/env_keys.txt" || true
  fi

  {
    echo "python: $(has_cmd python3 && python3 --version 2>&1 || echo 'not found')"
    echo "node:   $(has_cmd node && node --version 2>&1 || echo 'not found')"
    echo "go:     $(has_cmd go && go version 2>&1 || echo 'not found')"
    echo "docker: $(has_cmd docker && docker --version 2>&1 || echo 'not found')"
    echo "git:    $(has_cmd git && git --version 2>&1 || echo 'not found')"
  } >"${staging}/versions.txt"

  mkdir -p "${staging}/logs"
  local f
  for f in "${ARGUS_LOG_DIR}"/*.log; do
    [[ -e "$f" ]] || continue
    # Redact secrets line-by-line, then keep only the last 500 lines per log
    # to keep the archive small.
    while IFS= read -r line; do redact_secrets "$line"; done < <(tail -n 500 "$f") \
      >"${staging}/logs/$(basename "$f")" 2>/dev/null || true
  done

  {
    echo "Recent error lines (redacted, last 20 per log):"
    for f in "${ARGUS_LOG_DIR}"/*.log; do
      [[ -e "$f" ]] || continue
      echo "--- $(basename "$f") ---"
      grep -i "error\|fail" "$f" 2>/dev/null | tail -n 20 | while IFS= read -r line; do redact_secrets "$line"; echo; done
    done
  } >"${staging}/error_summary.txt" 2>/dev/null || true

  mkdir -p "$ARGUS_BACKUP_DIR"
  tar -C "$staging" -czf "$out" .
  rm -rf "$staging"

  ok "report written: $out"
  info "share this file for support — it has been checked for secrets, but always skim it yourself first"
}
