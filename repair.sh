#!/usr/bin/env bash
# repair.sh — top-level entry point for fixing a broken Argus install.
#
# By default runs only the safe automatic repairs (scripts/lib/repair.sh —
# stale pid files, cache dirs, restarting a service that's down, reinstalling
# a missing/outdated tool). Never touches project/user data on its own.
#
# The --reset-database / --reset-redis flags are separate and DESTRUCTIVE —
# they exist specifically for the "Postgres/Redis is reachable but rejects
# the credentials in .env" scenario (almost always a stale Docker volume
# from an earlier partial install attempt initialized with a different
# password). They require confirmation unless --force/--non-interactive.
#
# Usage:
#   ./repair.sh                    safe automatic repairs, then re-checks
#   ./repair.sh --reset-database   DESTRUCTIVE: recreate the database from
#                                   .env's current credentials
#   ./repair.sh --reset-redis      DESTRUCTIVE: recreate/flush redis
#   ./repair.sh --force             skip confirmation prompts
#   ./repair.sh --non-interactive   never prompt; safe defaults
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=repair
# shellcheck source=scripts/lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
log_init repair

RESET_DATABASE=0
RESET_REDIS=0

for arg in "$@"; do
  case "$arg" in
    --reset-database) RESET_DATABASE=1 ;;
    --reset-redis) RESET_REDIS=1 ;;
    --force) ARGUS_FORCE=1 ;;
    --non-interactive) ARGUS_NON_INTERACTIVE=1 ;;
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
os_detect
# shellcheck source=scripts/lib/package_manager.sh
source "${ARGUS_LIB_DIR}/package_manager.sh"
# shellcheck source=scripts/lib/python.sh
source "${ARGUS_LIB_DIR}/python.sh"
# shellcheck source=scripts/lib/node.sh
source "${ARGUS_LIB_DIR}/node.sh"
# shellcheck source=scripts/lib/docker.sh
source "${ARGUS_LIB_DIR}/docker.sh"
docker_detect || true
# shellcheck source=scripts/lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=scripts/lib/redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=scripts/lib/tools.sh
source "${ARGUS_LIB_DIR}/tools.sh"
# shellcheck source=scripts/lib/permissions.sh
source "${ARGUS_LIB_DIR}/permissions.sh"
# shellcheck source=scripts/lib/services.sh
source "${ARGUS_LIB_DIR}/services.sh"
# shellcheck source=scripts/lib/diagnostics.sh
source "${ARGUS_LIB_DIR}/diagnostics.sh"
# shellcheck source=scripts/lib/repair.sh
source "${ARGUS_LIB_DIR}/repair.sh"

echo "${C_BOLD}Argus repair${C_RESET}"

if [[ "$RESET_DATABASE" == "1" ]]; then
  section "RESET DATABASE (DESTRUCTIVE)"
  warn "this deletes all data currently stored in Postgres (projects, scans, findings, secrets, everything) and recreates it from .env's current credentials."
  if confirm "Really reset the database?" n; then
    step "Backing up before the reset"
    "${SCRIPT_DIR}/scripts/backup.sh" || warn "backup step failed — continuing anyway (the whole point of this reset is that the current database is broken; see docs/TROUBLESHOOTING.md to back up manually first if that's not the case for you)"
    db_reset_database || die "database reset failed — see ${ARGUS_LOG_DIR}/repair.log"
    db_migrate || die "reset succeeded but migrations failed — see ${ARGUS_LOG_DIR}/repair.log"
    ok "database reset and migrated"
  else
    info "skipped — database not reset"
  fi
fi

if [[ "$RESET_REDIS" == "1" ]]; then
  section "RESET REDIS (DESTRUCTIVE)"
  warn "this clears all queued/in-flight job state in Redis."
  if confirm "Really reset redis?" n; then
    redis_reset || die "redis reset failed — see ${ARGUS_LOG_DIR}/repair.log"
  else
    info "skipped — redis not reset"
  fi
fi

if [[ "$RESET_DATABASE" == "0" && "$RESET_REDIS" == "0" ]]; then
  doctor_repair_all
fi

echo ""
step "Re-checking"
rc=0
diagnostics_run all || rc=$?
exit "$rc"
