#!/usr/bin/env bash
# scripts/tests/repair_tests.sh — exercises the safe-repair functions against
# synthetic fixtures created and destroyed by this script. Never touches
# anything under runtime/ or logs/ that it didn't create itself.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
# shellcheck source=../lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
LOG_TARGET=runtime
# shellcheck source=../lib/repair.sh
source "${ARGUS_LIB_DIR}/repair.sh"
# shellcheck source=_harness.sh
source "${SCRIPT_DIR}/scripts/tests/_harness.sh"

echo "=== repair_stale_pids ==="
fake_pid_file="${ARGUS_PID_DIR}/argus-test-fixture.pid"
# PID 99999999 is guaranteed not to exist (max PID on Linux is far lower).
echo "99999999" >"$fake_pid_file"
repair_stale_pids
assert_true "stale pid file for a dead process was removed" bash -c "[[ ! -f '$fake_pid_file' ]]"
rm -f "$fake_pid_file"   # in case the assertion above failed, clean up anyway

echo "=== repair_runtime_tmp ==="
old_file="${ARGUS_TMP_DIR}/argus-test-fixture-old.txt"
fresh_file="${ARGUS_TMP_DIR}/argus-test-fixture-fresh.txt"
echo "old" >"$old_file"
echo "fresh" >"$fresh_file"
# Back-date the "old" fixture past the 24h staleness window (1440 minutes).
touch -d "2 days ago" "$old_file" 2>/dev/null || touch -t "$(date -d '2 days ago' +%Y%m%d%H%M 2>/dev/null)" "$old_file" 2>/dev/null || true
repair_runtime_tmp
assert_true  "stale (>24h) tmp file was removed" bash -c "[[ ! -f '$old_file' ]]"
assert_true  "fresh tmp file was NOT touched" bash -c "[[ -f '$fresh_file' ]]"
rm -f "$old_file" "$fresh_file"

echo "=== repair_python_cache (idempotent no-op when nothing to clean) ==="
assert_true "runs cleanly with no __pycache__ present" repair_python_cache

test_summary
