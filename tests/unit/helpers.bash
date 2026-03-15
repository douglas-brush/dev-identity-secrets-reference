#!/usr/bin/env bash
# helpers.bash — Shared BATS test helpers for dev-identity-secrets-reference
# Source this from your .bats files: load helpers

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_DIRNAME}")/.." && pwd)"

# Create a temporary directory for the test run, cleaned up automatically
setup_temp_dir() {
  BATS_TMPDIR="${BATS_TMPDIR:-/tmp}"
  TEST_TEMP_DIR="$(mktemp -d "${BATS_TMPDIR}/bats-test-XXXXXX")"
  export TEST_TEMP_DIR
}

# Remove the temporary directory
teardown_temp_dir() {
  if [[ -n "${TEST_TEMP_DIR:-}" && -d "$TEST_TEMP_DIR" ]]; then
    rm -rf "$TEST_TEMP_DIR"
  fi
}

# Standard setup — call from setup() in your .bats file
common_setup() {
  setup_temp_dir
  export REPO_ROOT
}

# Standard teardown — call from teardown() in your .bats file
common_teardown() {
  teardown_temp_dir
}

# Assert that output contains a string
assert_output_contains() {
  local expected="$1"
  if [[ "$output" != *"$expected"* ]]; then
    echo "Expected output to contain: $expected"
    echo "Actual output: $output"
    return 1
  fi
}

# Assert that output does NOT contain a string
assert_output_not_contains() {
  local unexpected="$1"
  if [[ "$output" == *"$unexpected"* ]]; then
    echo "Expected output NOT to contain: $unexpected"
    echo "Actual output: $output"
    return 1
  fi
}

# Assert file exists
assert_file_exists() {
  local filepath="$1"
  if [[ ! -f "$filepath" ]]; then
    echo "Expected file to exist: $filepath"
    return 1
  fi
}

# Assert file contains string
assert_file_contains() {
  local filepath="$1"
  local expected="$2"
  if ! grep -q "$expected" "$filepath" 2>/dev/null; then
    echo "Expected file $filepath to contain: $expected"
    return 1
  fi
}

# Assert exit code
assert_success() {
  if [[ "$status" -ne 0 ]]; then
    echo "Expected success (exit 0), got exit $status"
    echo "Output: $output"
    return 1
  fi
}

assert_failure() {
  if [[ "$status" -eq 0 ]]; then
    echo "Expected failure (non-zero exit), got exit 0"
    echo "Output: $output"
    return 1
  fi
}

# Check if a command exists (for skipping tests)
require_command() {
  local cmd="$1"
  if ! command -v "$cmd" &>/dev/null; then
    skip "$cmd not installed"
  fi
}
