#!/usr/bin/env bash
# scripts/self_test.sh — `./run.sh self-test` (§59). Exercises database,
# Redis, the API, the worker/orchestrator, tool health, the frontend, and
# report generation against local fixtures only — the gateway's own pytest
# suite (apis/gateway/tests/) runs against an in-memory sqlite database and
# is what actually covers report generation, findings, scope, and auth end
# to end, so this reuses it rather than re-implementing a shallower copy.
# Never touches third-party/public infrastructure.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
LOG_TARGET=runtime
# shellcheck source=lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
# shellcheck source=lib/database.sh
source "${ARGUS_LIB_DIR}/database.sh"
# shellcheck source=lib/redis.sh
source "${ARGUS_LIB_DIR}/redis.sh"
# shellcheck source=lib/tools.sh
source "${ARGUS_LIB_DIR}/tools.sh"
# shellcheck source=lib/services.sh
source "${ARGUS_LIB_DIR}/services.sh"

RESULTS=()
_record() { RESULTS+=("$1:$2"); }   # name:pass|fail|skip

section "SELF-TEST"

# ── database ────────────────────────────────────────────────────────────
db_load_config
if db_tcp_reachable && db_auth_ok; then ok "database"; _record database pass
else fail "database"; _record database fail; fi

# ── redis / queue ───────────────────────────────────────────────────────
redis_load_config
if redis_tcp_reachable && redis_ping_ok; then ok "redis / queue"; _record redis pass
else fail "redis / queue"; _record redis fail; fi

# ── API ─────────────────────────────────────────────────────────────────
if curl -fsS --max-time 5 "http://localhost:${ARGUS_API_PORT:-8000}/api/health" >/dev/null 2>&1; then
  ok "API (/api/health)"; _record api pass
else
  fail "API (/api/health) — is the gateway running? try ./run.sh start"; _record api fail
fi

# ── worker / orchestrator ───────────────────────────────────────────────
if service_is_running orchestrator; then ok "worker (orchestrator running)"; _record worker pass
else fail "worker — orchestrator not running"; _record worker fail; fi

# scheduler is in-process with the gateway — covered by the API check above.
if curl -fsS --max-time 5 "http://localhost:${ARGUS_API_PORT:-8000}/api/health" >/dev/null 2>&1; then
  ok "scheduler (in-process with gateway)"; _record scheduler pass
else
  warn "scheduler — cannot confirm (gateway unreachable)"; _record scheduler skip
fi

# ── frontend ────────────────────────────────────────────────────────────
if curl -fsS --max-time 5 -o /dev/null "http://localhost:${ARGUS_WEB_PORT:-3000}/" 2>&1; then
  ok "frontend"; _record frontend pass
else
  fail "frontend — is web running? try ./run.sh start"; _record frontend fail
fi

# ── tool health ─────────────────────────────────────────────────────────
if tools_check >/dev/null 2>&1; then ok "tool health (all required tools)"; _record tools pass
else warn "tool health — one or more required tools degraded/missing (./doctor.sh --tools for detail)"; _record tools fail; fi

# ── storage / configuration / report generation / findings / scope —
#    the gateway's own pytest suite, against its local sqlite fixture. ────
if [[ -x "$ARGUS_VENV_PY" ]]; then
  info "running gateway test suite (storage, config, reports, findings, scope, auth)…"
  if ( cd "$ARGUS_GATEWAY_DIR" && "$ARGUS_VENV_DIR/bin/pytest" -q ) >"${ARGUS_TMP_DIR}/self-test-pytest.log" 2>&1; then
    ok "gateway test suite"; _record gateway_tests pass
  else
    fail "gateway test suite — see ${ARGUS_TMP_DIR}/self-test-pytest.log"
    tail -n 15 "${ARGUS_TMP_DIR}/self-test-pytest.log" | sed 's/^/    /'
    _record gateway_tests fail
  fi
else
  warn "gateway test suite — Python environment not set up"; _record gateway_tests skip
fi

if has_cmd go && [[ -d "${ARGUS_ORCH_DIR}" ]]; then
  info "running orchestrator test suite (scope engine, recon pipeline, injection engine)…"
  if ( cd "$ARGUS_ORCH_DIR" && go test ./... ) >"${ARGUS_TMP_DIR}/self-test-gotest.log" 2>&1; then
    ok "orchestrator test suite"; _record orch_tests pass
  else
    fail "orchestrator test suite — see ${ARGUS_TMP_DIR}/self-test-gotest.log"
    tail -n 15 "${ARGUS_TMP_DIR}/self-test-gotest.log" | sed 's/^/    /'
    _record orch_tests fail
  fi
else
  warn "orchestrator test suite — Go not available"; _record orch_tests skip
fi

section "SELF-TEST SUMMARY"
passed=0 failed=0 skipped=0
for r in "${RESULTS[@]}"; do
  case "${r#*:}" in
    pass) passed=$((passed + 1)) ;;
    fail) failed=$((failed + 1)) ;;
    skip) skipped=$((skipped + 1)) ;;
  esac
done
info "${passed} passed, ${failed} failed, ${skipped} skipped"
[[ "$failed" -eq 0 ]]
