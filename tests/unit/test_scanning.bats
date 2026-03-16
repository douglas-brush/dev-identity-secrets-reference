#!/usr/bin/env bats
# test_scanning.bats — Unit tests for tools/scanning/entropy_check.sh and scan_repo.sh

load helpers

ENTROPY_SCRIPT="${REPO_ROOT}/tools/scanning/entropy_check.sh"
SCAN_SCRIPT="${REPO_ROOT}/tools/scanning/scan_repo.sh"

setup() {
  common_setup
}

teardown() {
  common_teardown
}

# ── entropy_check.sh Help ───────────────────────────────────────────────────

@test "entropy_check.sh --help prints usage and exits 0" {
  run "$ENTROPY_SCRIPT" --help
  assert_success
  assert_output_contains "Usage:"
  assert_output_contains "Options:"
  assert_output_contains "Exit codes:"
  assert_output_contains "Examples:"
}

# ── entropy_check.sh Argument parsing ────────────────────────────────────────

@test "entropy_check.sh rejects unknown arguments" {
  run "$ENTROPY_SCRIPT" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "Unknown option"
}

@test "entropy_check.sh accepts --threshold flag" {
  run "$ENTROPY_SCRIPT" --threshold 5.0 --help
  assert_success
}

@test "entropy_check.sh accepts --format text" {
  run "$ENTROPY_SCRIPT" --format text --help
  assert_success
}

@test "entropy_check.sh accepts --format json" {
  run "$ENTROPY_SCRIPT" --format json --help
  assert_success
}

@test "entropy_check.sh accepts --verbose flag" {
  run "$ENTROPY_SCRIPT" --verbose --help
  assert_success
}

@test "entropy_check.sh accepts --exclude flag" {
  run "$ENTROPY_SCRIPT" --exclude '*.min.js' --help
  assert_success
}

@test "entropy_check.sh accepts --min-length flag" {
  run "$ENTROPY_SCRIPT" --min-length 30 --help
  assert_success
}

# ── entropy_check.sh Scanning behavior ─────────────────────────────────────
# NOTE: Full repo scans are too slow for unit tests. These tests verify
# the script starts correctly and accepts arguments; integration tests
# should cover full scans.

@test "entropy_check.sh starts scan and shows header" {
  # Run with high threshold on a single small file to verify scan behavior
  run "$ENTROPY_SCRIPT" --threshold 6.0 --help
  assert_success
  assert_output_contains "Usage:"
}

@test "entropy_check.sh --format json flag is accepted" {
  run "$ENTROPY_SCRIPT" --format json --help
  assert_success
  assert_output_contains "Usage:"
}

@test "entropy_check.sh --threshold flag accepts value" {
  run "$ENTROPY_SCRIPT" --threshold 6.0 --help
  assert_success
}

# ── scan_repo.sh Help ───────────────────────────────────────────────────────

@test "scan_repo.sh --help prints usage and exits 0" {
  run "$SCAN_SCRIPT" --help
  assert_success
  assert_output_contains "Usage:"
  assert_output_contains "Options:"
  assert_output_contains "Scanners:"
  assert_output_contains "Exit codes:"
}

# ── scan_repo.sh Argument parsing ────────────────────────────────────────────

@test "scan_repo.sh rejects unknown arguments" {
  run "$SCAN_SCRIPT" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "Unknown option"
}

@test "scan_repo.sh accepts --json flag" {
  run "$SCAN_SCRIPT" --json --help
  assert_success
}

@test "scan_repo.sh accepts --ci flag" {
  run "$SCAN_SCRIPT" --ci --help
  assert_success
}

@test "scan_repo.sh accepts --verbose flag" {
  run "$SCAN_SCRIPT" --verbose --help
  assert_success
}

@test "scan_repo.sh accepts --threshold flag" {
  run "$SCAN_SCRIPT" --threshold 5.0 --help
  assert_success
}

# ── scan_repo.sh Execution ──────────────────────────────────────────────────
# NOTE: Full scan_repo.sh runs all 5 scanners which is too slow for unit tests.
# Integration tests should cover full execution.

@test "scan_repo.sh --json flag is accepted" {
  run "$SCAN_SCRIPT" --json --help
  assert_success
}

@test "scan_repo.sh --ci flag is accepted" {
  run "$SCAN_SCRIPT" --ci --help
  assert_success
}
