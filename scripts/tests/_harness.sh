#!/usr/bin/env bash
# scripts/tests/_harness.sh — tiny assert helpers shared by the test scripts
# in this directory. Not a general-purpose framework — just enough to make
# each test file self-explanatory and give a clear pass/fail summary.
# shellcheck shell=bash

TEST_PASS=0
TEST_FAIL=0

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  [PASS] $desc"
    TEST_PASS=$((TEST_PASS + 1))
  else
    echo "  [FAIL] $desc — expected [$expected], got [$actual]"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi
}

assert_true() {
  local desc="$1"; shift
  if "$@"; then
    echo "  [PASS] $desc"
    TEST_PASS=$((TEST_PASS + 1))
  else
    echo "  [FAIL] $desc — command returned non-zero: $*"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi
}

assert_false() {
  local desc="$1"; shift
  if ! "$@"; then
    echo "  [PASS] $desc"
    TEST_PASS=$((TEST_PASS + 1))
  else
    echo "  [FAIL] $desc — command unexpectedly returned zero: $*"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi
}

assert_matches() {
  local desc="$1" value="$2" pattern="$3"
  if [[ "$value" =~ $pattern ]]; then
    echo "  [PASS] $desc"
    TEST_PASS=$((TEST_PASS + 1))
  else
    echo "  [FAIL] $desc — [$value] does not match /$pattern/"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi
}

assert_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  [PASS] $desc"
    TEST_PASS=$((TEST_PASS + 1))
  else
    echo "  [FAIL] $desc — [$needle] not found in output"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi
}

assert_not_contains() {
  local desc="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "  [PASS] $desc"
    TEST_PASS=$((TEST_PASS + 1))
  else
    echo "  [FAIL] $desc — [$needle] unexpectedly found in output"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi
}

test_summary() {
  echo ""
  echo "$(basename "$0"): ${TEST_PASS} passed, ${TEST_FAIL} failed"
  [[ "$TEST_FAIL" -eq 0 ]]
}
