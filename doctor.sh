#!/usr/bin/env bash
# doctor.sh — one-stop troubleshooting and repair utility for the Argus
# platform. Runs the full diagnostic pipeline (§28) and, with --fix, applies
# only the safe automatic repairs (§31) — it never touches project data.
#
# Usage:
#   ./doctor.sh                 full check (same as --check)
#   ./doctor.sh --check
#   ./doctor.sh --fix           safe automatic repair pass, then re-checks
#   ./doctor.sh --deep          --check plus a performance snapshot + recent errors
#   ./doctor.sh --report        writes a sanitized diagnostic archive
#   ./doctor.sh --tools --workers --database --ollama --network --permissions
#   ./doctor.sh --performance --logs
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=doctor
# shellcheck source=scripts/lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
log_init doctor
reject_sudo_wrapper "$@"
# shellcheck source=scripts/lib/diagnostics.sh
source "${ARGUS_LIB_DIR}/diagnostics.sh"
# shellcheck source=scripts/lib/repair.sh
source "${ARGUS_LIB_DIR}/repair.sh"
# shellcheck source=scripts/lib/performance.sh
source "${ARGUS_LIB_DIR}/performance.sh"

ACTION="check"
SCOPE="all"

for arg in "$@"; do
  case "$arg" in
    --check) ACTION="check" ;;
    --fix) ACTION="fix" ;;
    --deep) ACTION="deep" ;;
    --report) ACTION="report" ;;
    --tools) SCOPE="tools" ;;
    --workers) SCOPE="workers" ;;
    --database) SCOPE="database" ;;
    --ollama) SCOPE="ollama" ;;
    --network) SCOPE="network" ;;
    --permissions) SCOPE="permissions" ;;
    --performance) SCOPE="performance" ;;
    --logs) SCOPE="logs" ;;
    --no-color) ARGUS_NO_COLOR=1 ;;
    --quiet) ARGUS_QUIET=1 ;;
    --verbose) ARGUS_VERBOSE=1 ;;
    -h|--help)
      sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) warn "unknown flag: $arg (ignored)" ;;
  esac
done
export ARGUS_NO_COLOR ARGUS_QUIET ARGUS_VERBOSE

echo "${C_BOLD}Argus doctor${C_RESET}"

case "$ACTION" in
  check)
    rc=0
    diagnostics_run "$SCOPE" || rc=$?
    exit "$rc"
    ;;
  deep)
    rc=0
    diagnostics_run all || rc=$?
    performance_snapshot
    _diag_show_recent_errors
    exit "$rc"
    ;;
  fix)
    doctor_repair_all
    echo ""
    step "Re-checking after repair"
    rc=0
    diagnostics_run all || rc=$?
    exit "$rc"
    ;;
  report)
    # shellcheck source=scripts/report.sh
    source "${SCRIPT_DIR}/scripts/report.sh"
    report_generate
    ;;
esac
