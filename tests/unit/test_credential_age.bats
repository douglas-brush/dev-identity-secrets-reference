#!/usr/bin/env bats
# test_credential_age.bats — Unit tests for tools/audit/credential_age_report.sh

load helpers

SCRIPT="${REPO_ROOT}/tools/audit/credential_age_report.sh"

setup() {
  common_setup
  # Create a mock kubectl that exits immediately (prevents hanging on cluster-info)
  mkdir -p "$TEST_TEMP_DIR/bin"
  cat > "$TEST_TEMP_DIR/bin/kubectl" <<'MOCK'
#!/usr/bin/env bash
echo "mock-kubectl: not connected" >&2
exit 1
MOCK
  chmod +x "$TEST_TEMP_DIR/bin/kubectl"
  export PATH="$TEST_TEMP_DIR/bin:$PATH"
}

teardown() {
  common_teardown
}

# ── Help output ───────────────────────────────────────────────────────────────

@test "credential_age_report.sh --help prints usage and exits 0" {
  run "$SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "OPTIONS"
  assert_output_contains "ENVIRONMENT"
  assert_output_contains "EXIT CODES"
  assert_output_contains "EXAMPLES"
}

@test "credential_age_report.sh -h prints usage" {
  run "$SCRIPT" -h
  assert_success
  assert_output_contains "credential_age_report.sh"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

@test "credential_age_report.sh rejects unknown arguments" {
  run "$SCRIPT" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "credential_age_report.sh accepts --max-age flag" {
  run "$SCRIPT" --max-age 30 --help
  assert_success
}

@test "credential_age_report.sh accepts --format text" {
  run "$SCRIPT" --format text --help
  assert_success
}

@test "credential_age_report.sh accepts --format json" {
  run "$SCRIPT" --format json --help
  assert_success
}

@test "credential_age_report.sh accepts --format csv" {
  run "$SCRIPT" --format csv --help
  assert_success
}

@test "credential_age_report.sh accepts --vault-only flag" {
  run "$SCRIPT" --vault-only --help
  assert_success
}

@test "credential_age_report.sh accepts --k8s-only flag" {
  run "$SCRIPT" --k8s-only --help
  assert_success
}

@test "credential_age_report.sh accepts --namespace flag" {
  run "$SCRIPT" --namespace prod --help
  assert_success
}

# ── Graceful skip when tools unavailable ─────────────────────────────────────

@test "credential_age_report.sh skips vault when VAULT_ADDR not set" {
  unset VAULT_ADDR
  run "$SCRIPT" --vault-only
  # Should succeed (exit 0) since no vault means nothing to report
  assert_success
  assert_output_contains "CREDENTIAL AGE REPORT" || assert_output_contains "credential_age_audit"
}

@test "credential_age_report.sh outputs text format by default" {
  unset VAULT_ADDR
  run "$SCRIPT"
  assert_success
  assert_output_contains "CREDENTIAL AGE REPORT"
}

@test "credential_age_report.sh --format json produces JSON" {
  unset VAULT_ADDR
  run "$SCRIPT" --format json
  assert_success
  assert_output_contains '"report"'
  assert_output_contains '"credential_age_audit"'
  assert_output_contains '"overall_status"'
}

@test "credential_age_report.sh --format csv produces CSV header" {
  unset VAULT_ADDR
  run "$SCRIPT" --format csv
  assert_success
  assert_output_contains "source,name,created,age_days,status,detail"
}

@test "credential_age_report.sh shows max age policy in text output" {
  unset VAULT_ADDR
  run "$SCRIPT" --max-age 60
  assert_success
  assert_output_contains "60"
}

@test "credential_age_report.sh CREDENTIAL_MAX_AGE env overrides default" {
  unset VAULT_ADDR
  CREDENTIAL_MAX_AGE=45 run "$SCRIPT"
  assert_success
  assert_output_contains "45"
}
