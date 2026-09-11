#!/usr/bin/env bash
# install.sh — single entry point for installing/preparing the Argus
# reconnaissance platform. Detects the OS, installs required languages,
# system packages and security tools, sets up the Python/Node environments,
# provisions Postgres/Redis if needed, applies migrations, and generates a
# working .env. Safe to re-run — every step is idempotent.
#
# Usage:
#   ./install.sh                 full install/repair pass (interactive)
#   ./install.sh --check         report-only, no changes
#   ./install.sh --repair        alias for --fix-oriented full pass
#   ./install.sh --upgrade       backup + upgrade existing install
#   ./install.sh --dev           dev-mode install (skips some hardening)
#   ./install.sh --production    production-mode install
#   ./install.sh --non-interactive   never prompt; safe defaults / env vars
#   ./install.sh --force         ignore hardware warnings, force reinstalls
#   ./install.sh --no-color --quiet --verbose
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=install
# shellcheck source=scripts/lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
log_init install

trap 'log_error "install.sh" "unhandled" "aborted at line $LINENO" "unknown"; fail "install.sh aborted — see logs/install.log"' ERR
trap 'true' EXIT

MODE="check_and_install"   # check_and_install | check | upgrade
INSTALL_PROFILE="dev"      # dev | production

for arg in "$@"; do
  case "$arg" in
    --check) MODE="check" ;;
    --repair) MODE="check_and_install" ;;
    --upgrade) MODE="upgrade" ;;
    --dev) INSTALL_PROFILE="dev" ;;
    --production) INSTALL_PROFILE="production" ;;
    --non-interactive) ARGUS_NON_INTERACTIVE=1 ;;
    --force) ARGUS_FORCE=1 ;;
    --no-color) ARGUS_NO_COLOR=1 ;;
    --quiet) ARGUS_QUIET=1 ;;
    --verbose) ARGUS_VERBOSE=1 ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) warn "unknown flag: $arg (ignored)" ;;
  esac
done
export ARGUS_NON_INTERACTIVE ARGUS_FORCE ARGUS_NO_COLOR ARGUS_QUIET ARGUS_VERBOSE

# shellcheck source=scripts/lib/os_detection.sh
source "${ARGUS_LIB_DIR}/os_detection.sh"
# shellcheck source=scripts/lib/package_manager.sh
source "${ARGUS_LIB_DIR}/package_manager.sh"
# shellcheck source=scripts/lib/python.sh
source "${ARGUS_LIB_DIR}/python.sh"
# shellcheck source=scripts/lib/node.sh
source "${ARGUS_LIB_DIR}/node.sh"
# shellcheck source=scripts/lib/go.sh
source "${ARGUS_LIB_DIR}/go.sh"
# shellcheck source=scripts/lib/docker.sh
source "${ARGUS_LIB_DIR}/docker.sh"
# shellcheck source=scripts/lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=scripts/lib/redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=scripts/lib/tools.sh
source "${ARGUS_LIB_DIR}/tools.sh"
# shellcheck source=scripts/lib/permissions.sh
source "${ARGUS_LIB_DIR}/permissions.sh"

os_detect
echo "${C_BOLD}Argus installer${C_RESET} — mode=${MODE} profile=${INSTALL_PROFILE}"
os_print_summary

if [[ "$OS_SUPPORTED" != "1" ]]; then
  warn "$(os_label) is not a recognized Debian/Ubuntu derivative — continuing on a best-effort basis"
fi
if [[ "${OS_IS_KALI:-0}" == "1" ]]; then
  info "Kali Linux detected — preinstalled security tools are respected; nothing in /usr/bin is touched. See docs/KALI.md."
fi
if [[ "${OS_IS_PARROT:-0}" == "1" ]]; then
  info "Parrot Security OS detected — see docs/PARROT.md."
fi

# ── Pre-flight ───────────────────────────────────────────────────────────
section "PRE-FLIGHT"
cpu_count="$(nproc 2>/dev/null || echo '?')"
mem_gb="$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 / 1024 ))"
disk_gb="$(df -BG --output=avail "$ARGUS_ROOT" 2>/dev/null | tail -n1 | tr -dc '0-9' || true)"
min_cpu="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" min_cpu_cores 4)"
min_ram="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" min_ram_gb 8)"
min_disk="$(yaml_flat_get "${ARGUS_CONFIG_DIR}/system.yaml" min_disk_gb 250)"

info "CPU: ${cpu_count} core(s) (recommended: ${min_cpu}+)"
info "RAM: ${mem_gb} GB (recommended: ${min_ram}+)"
info "Disk free: ${disk_gb:-?} GB (recommended: ${min_disk}+)"

hw_warn=0
[[ "${cpu_count:-0}" -lt "$min_cpu" ]] 2>/dev/null && { warn "CPU below recommended minimum ($min_cpu cores)"; hw_warn=1; }
[[ "${mem_gb:-0}" -lt "$min_ram" ]] 2>/dev/null && { warn "RAM below recommended minimum (${min_ram}GB)"; hw_warn=1; }
[[ -n "${disk_gb:-}" && "${disk_gb}" -lt "$min_disk" ]] 2>/dev/null && { warn "free disk below recommended minimum (${min_disk}GB)"; hw_warn=1; }
if [[ "$hw_warn" == "1" && "$ARGUS_FORCE" != "1" ]]; then
  warn "hardware is below the recommended configuration — this is a warning, not a blocker (use --force to silence it)"
fi

if ! has_cmd curl || ! has_cmd wget; then
  warn "internet connectivity tools (curl/wget) missing — will be installed"
fi
if getent hosts github.com >/dev/null 2>&1 || host github.com >/dev/null 2>&1 || curl -fsS --max-time 3 -o /dev/null https://github.com 2>/dev/null; then
  ok "internet connectivity / DNS resolution OK"
else
  warn "could not confirm internet connectivity — tool/package downloads may fail"
fi
preflight_check_commands || true

if [[ "$MODE" == "check" ]]; then
  section "CHECK-ONLY MODE — no changes will be made"
  check_system_packages || true
  python_check || true
  node_check || true
  go_check || true
  docker_check || true
  tools_check || true
  permissions_check || true
  echo ""
  info "run without --check to install/repair what's missing"
  exit 0
fi

# ── Upgrade: backup first ───────────────────────────────────────────────
if [[ "$MODE" == "upgrade" ]]; then
  step "Backing up before upgrade"
  "${SCRIPT_DIR}/scripts/backup.sh" || warn "backup step failed — continuing anyway (see docs/UPGRADING.md to back up manually first)"
fi

# ── System packages ──────────────────────────────────────────────────────
install_system_packages || warn "some system packages could not be installed automatically — see ${ARGUS_LOG_DIR}/install.log"

# ── Language runtimes ────────────────────────────────────────────────────
go_setup || true
python_setup
node_setup

# ── .env ──────────────────────────────────────────────────────────────────
# shellcheck source=scripts/env_setup.sh
source "${SCRIPT_DIR}/scripts/env_setup.sh"
env_setup_run "$INSTALL_PROFILE"

# ── Docker (optional) ────────────────────────────────────────────────────
docker_check >/dev/null 2>&1 || docker_offer_install

# ── Backing services ─────────────────────────────────────────────────────
db_start || warn "postgres did not start automatically — start it manually and re-run"
redis_start || warn "redis did not start automatically — start it manually and re-run"

# ── Database ──────────────────────────────────────────────────────────────
if db_tcp_reachable; then
  db_migrate
else
  warn "skipping migrations — database not reachable"
fi

# ── Security tools ───────────────────────────────────────────────────────
tools_install_all

# ── Final validation ─────────────────────────────────────────────────────
section "FINAL VALIDATION"
final_problems=0
python_check || final_problems=1
node_check || final_problems=1
db_check || final_problems=1
redis_check || final_problems=1
tools_check || final_problems=1
permissions_check || true

echo ""
if [[ "$final_problems" -eq 0 ]]; then
  ok "install complete"
else
  warn "install finished with some unresolved issues — run ./doctor.sh for details"
fi
echo ""
echo "Next steps:"
echo "  ./run.sh              start the application"
echo "  ./run.sh status       check what's running"
echo "  ./doctor.sh           full diagnostics"
