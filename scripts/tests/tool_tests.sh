#!/usr/bin/env bash
# scripts/tests/tool_tests.sh — regression tests for the YAML-lite parsers,
# version comparison, and (critically) secret redaction. Pure logic, no
# network/services required — safe to run anywhere, including CI.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/scripts/lib/common.sh"
# shellcheck source=../lib/logging.sh
source "${ARGUS_LIB_DIR}/logging.sh"
# shellcheck source=../lib/tools.sh
source "${ARGUS_LIB_DIR}/tools.sh"
# shellcheck source=_harness.sh
source "${SCRIPT_DIR}/scripts/tests/_harness.sh"

echo "=== version_ge ==="
assert_true  "3.0.0 >= 2.6.0" version_ge "3.0.0" "2.6.0"
assert_true  "1.2.0 >= 1.2.0 (equal)" version_ge "1.2.0" "1.2.0"
assert_false "1.1.9 >= 1.2.0" version_ge "1.1.9" "1.2.0"
assert_true  "2.1.0-dev >= 2.0.0 (suffix ignored)" version_ge "2.1.0-dev" "2.0.0"
assert_true  "empty minimum always satisfied" version_ge "1.0.0" ""

echo "=== tools.yaml parser ==="
assert_eq "known tool field (nuclei install_method)" "go" "$(tools_yaml_get nuclei install_method)"
assert_eq "known tool field (nmap apt_package)" "nmap" "$(tools_yaml_get nmap apt_package)"
assert_eq "absent field on a real tool returns empty, not an error" "" "$(tools_yaml_get subfinder apt_package)"
assert_eq "unknown tool name returns empty, not an error" "" "$(tools_yaml_get nosuchtool anything)"
names="$(tools_yaml_names)"
assert_contains "tools_yaml_names lists nuclei" "$names" "nuclei"
assert_contains "tools_yaml_names lists nmap" "$names" "nmap"

echo "=== yaml_flat_get ==="
assert_eq "known key" "3.11" "$(yaml_flat_get "${ARGUS_CONFIG_DIR}/versions.yaml" python_min)"
assert_eq "missing key returns the given default" "fallback" "$(yaml_flat_get "${ARGUS_CONFIG_DIR}/versions.yaml" no_such_key fallback)"

echo "=== redact_secrets (regression: must never leak a real secret) ==="
out="$(redact_secrets "PASSWORD=supersecret123")"
assert_not_contains "KEY=value password redacted" "$out" "supersecret123"

out="$(redact_secrets "Authorization: Bearer abc123SECRETtoken")"
assert_not_contains "Bearer token redacted" "$out" "abc123SECRETtoken"

out="$(redact_secrets "JWT_SECRET=deadbeefcafef00d")"
assert_not_contains "JWT secret redacted" "$out" "deadbeefcafef00d"

# The exact shape that leaked into logs/runtime.log before the db_migrate
# fix in scripts/lib/database.sh — a connection string with an embedded
# password. Covered here so this specific class of leak can never recur
# silently.
out="$(redact_secrets "DATABASE_URL=postgresql+asyncpg://argus:hunter2ThePassword@localhost:5432/argus")"
assert_not_contains "DB URL password redacted" "$out" "hunter2ThePassword"
assert_contains "DB URL structure preserved (host still visible)" "$out" "localhost:5432/argus"

out="$(redact_secrets "redis://:anotherSecretValue@localhost:6379/0")"
assert_not_contains "redis URL with empty username redacted" "$out" "anotherSecretValue"

out="$(redact_secrets "a perfectly ordinary line with no secrets in it")"
assert_eq "clean line passes through unchanged" "a perfectly ordinary line with no secrets in it" "$out"

test_summary
