#!/usr/bin/env bash
# scripts/tests/health_tests.sh — exercises the diagnostic checks against
# whatever is actually running right now. Some assertions are skipped (not
# failed) when a component genuinely isn't up — this is meant to be run
# after `./run.sh start`, not as an isolated unit test.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
# shellcheck source=../lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
LOG_TARGET=runtime
# shellcheck source=../lib/os_detection.sh
source "${ARGUS_LIB_DIR}/os_detection.sh"
os_detect
# shellcheck source=../lib/health.sh
source "${ARGUS_LIB_DIR}/health.sh"
# shellcheck source=_harness.sh
source "${SCRIPT_DIR}/scripts/tests/_harness.sh"

echo "=== os_detect ==="
assert_true "OS_ID is non-empty" test -n "$OS_ID"
assert_true "OS_ARCH is non-empty" test -n "$OS_ARCH"
assert_true "OS_PKG_MANAGER detected" test -n "$OS_PKG_MANAGER"

echo "=== disk/memory thresholds parse as integers ==="
pct="$(disk_usage_pct)"
assert_matches "disk_usage_pct returns a number" "$pct" '^[0-9]+$'
assert_true "disk_usage_pct in [0,100]" test "$pct" -ge 0 -a "$pct" -le 100

echo "=== database ==="
db_load_config
if db_tcp_reachable; then
  assert_true "database authentication" db_auth_ok
else
  echo "  [SKIP] database not reachable — start it first (./run.sh start)"
fi

echo "=== redis ==="
redis_load_config
if redis_tcp_reachable; then
  assert_true "redis PING" redis_ping_ok
else
  echo "  [SKIP] redis not reachable — start it first (./run.sh start)"
fi

echo "=== services (only meaningful once ./run.sh start has run) ==="
if service_is_running gateway; then
  assert_true "gateway API responds" curl -fsS --max-time 5 -o /dev/null "http://localhost:${ARGUS_API_PORT:-8000}/api/health"
else
  echo "  [SKIP] gateway not running"
fi

test_summary
