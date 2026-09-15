#!/usr/bin/env bash
# scripts/tests/database_tests.sh — regression tests for the "postgres is
# TCP-reachable but rejects .env's credentials" scenario (a stale Docker
# volume initialized with a different password than what's in .env now).
# db_start used to treat TCP-reachable as good enough and report success,
# letting a real mismatch surface three steps later as a raw psycopg
# traceback out of alembic instead of a clear diagnostic here.
#
# Requires a real reachable Postgres (./run.sh start first) — tests are
# skipped, not failed, if it isn't running.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=runtime
# shellcheck source=../lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
# shellcheck source=../lib/os_detection.sh
source "${ARGUS_LIB_DIR}/os_detection.sh"
os_detect
# shellcheck source=../lib/python.sh
source "${ARGUS_LIB_DIR}/python.sh"
# shellcheck source=../lib/docker.sh
source "${ARGUS_LIB_DIR}/docker.sh"
docker_detect || true
# shellcheck source=../lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=_harness.sh
source "${SCRIPT_DIR}/scripts/tests/_harness.sh"

db_load_config

if ! db_tcp_reachable; then
  echo "  [SKIP] database not reachable — start it first (./run.sh start)"
  test_summary
  exit 0
fi

echo "=== db_auth_ok distinguishes right password from wrong ==="
assert_true "correct .env credentials authenticate" db_auth_ok

WRONG_ENV="$(mktemp "${ARGUS_TMP_DIR}/db-test-wrong.XXXXXX.env")"
cp "$ARGUS_ENV_FILE" "$WRONG_ENV"
sed -i 's/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=deliberately-wrong-password-for-testing/' "$WRONG_ENV"

echo "=== db_start reports failure (not silent success) on a credential mismatch ==="
# Run in a fresh bash -c, not a `(...)` subshell — _harness.sh's
# TEST_PASS/TEST_FAIL counters are plain shell variables, and a subshell's
# increments to them would never be visible to this script's test_summary.
# common.sh unconditionally sets ARGUS_ENV_FILE="${ARGUS_ROOT}/.env" (an
# exported override from outside is clobbered), so the reassignment has to
# happen after sourcing it, as a plain variable, same as any other caller.
out="$(bash -c '
  source "'"${SCRIPT_DIR}"'/scripts/lib/common.sh"
  ARGUS_ENV_FILE="'"${WRONG_ENV}"'"
  source "${ARGUS_LIB_DIR}/logging.sh"
  source "${ARGUS_LIB_DIR}/os_detection.sh"; os_detect
  source "${ARGUS_LIB_DIR}/python.sh"
  source "${ARGUS_LIB_DIR}/docker.sh"; docker_detect || true
  source "${ARGUS_LIB_DIR}/database.sh"
  db_start
' 2>&1)" && rc=0 || rc=$?
assert_true "db_start returns non-zero on auth mismatch" test "$rc" -ne 0
assert_contains "diagnostic names the actual cause (credentials rejected)" "$out" "rejected the credentials"
assert_contains "diagnostic points at the fix" "$out" "reset-database"
assert_not_contains "does NOT falsely report success" "$out" "already reachable"

rm -f "$WRONG_ENV"

test_summary
