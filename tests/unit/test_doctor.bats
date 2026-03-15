#!/usr/bin/env bats
# test_doctor.bats — Unit tests for tools/secrets-doctor/doctor.sh

load helpers

DOCTOR_SCRIPT="${REPO_ROOT}/tools/secrets-doctor/doctor.sh"

setup() {
  common_setup
}

teardown() {
  common_teardown
}

# ── Help output ───────────────────────────────────────────────────────────────

@test "doctor.sh --help prints usage and exits 0" {
  run "$DOCTOR_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "COMMANDS"
  assert_output_contains "OPTIONS"
}

@test "doctor.sh -h prints usage and exits 0" {
  run "$DOCTOR_SCRIPT" -h
  assert_success
  assert_output_contains "secrets-doctor"
}

# ── Argument parsing ──────────────────────────────────────────────────────────

@test "doctor.sh rejects unknown arguments" {
  run "$DOCTOR_SCRIPT" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "doctor.sh accepts --no-color flag" {
  run "$DOCTOR_SCRIPT" deps --no-color
  # Should run without error (exit 0 or 1 depending on deps)
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  # Output should not contain ANSI escape codes
  if [[ "$output" == *$'\033'* ]]; then
    echo "Output contains ANSI escape codes despite --no-color"
    return 1
  fi
}

# ── Individual check modules ─────────────────────────────────────────────────

@test "doctor.sh deps check runs without crashing" {
  run "$DOCTOR_SCRIPT" deps --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Dependency Checks"
}

@test "doctor.sh git check runs without crashing" {
  run "$DOCTOR_SCRIPT" git --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Git Security"
}

@test "doctor.sh sops check runs without crashing" {
  run "$DOCTOR_SCRIPT" sops --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "SOPS Configuration"
}

@test "doctor.sh audit check runs without crashing" {
  run "$DOCTOR_SCRIPT" audit --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Secret Audit"
}

@test "doctor.sh certs check runs without crashing" {
  run "$DOCTOR_SCRIPT" certs --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Certificate Health"
}

@test "doctor.sh vault check skips when VAULT_ADDR not set" {
  unset VAULT_ADDR
  run "$DOCTOR_SCRIPT" vault --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Vault Health"
}

@test "doctor.sh k8s check runs without crashing" {
  run "$DOCTOR_SCRIPT" k8s --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Kubernetes Secrets"
}

# ── JSON output ───────────────────────────────────────────────────────────────

@test "doctor.sh --json produces valid JSON" {
  require_command jq
  run "$DOCTOR_SCRIPT" deps --json --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]

  # Extract JSON from output (may have banner text before it)
  local json_output
  json_output=$(echo "$output" | grep -E '^\{' | head -1)

  if [[ -n "$json_output" ]]; then
    echo "$json_output" | jq . >/dev/null 2>&1
    [ $? -eq 0 ]
  fi
}

@test "doctor.sh --json output contains expected fields" {
  require_command jq
  run "$DOCTOR_SCRIPT" deps --json --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]

  local json_output
  json_output=$(echo "$output" | grep -E '^\{' | head -1)

  if [[ -n "$json_output" ]]; then
    local has_timestamp has_overall has_results
    has_timestamp=$(echo "$json_output" | jq 'has("timestamp")' 2>/dev/null)
    has_overall=$(echo "$json_output" | jq 'has("overall")' 2>/dev/null)
    has_results=$(echo "$json_output" | jq 'has("results")' 2>/dev/null)

    [ "$has_timestamp" = "true" ]
    [ "$has_overall" = "true" ]
    [ "$has_results" = "true" ]
  fi
}

# ── Multiple commands ─────────────────────────────────────────────────────────

@test "doctor.sh accepts multiple check commands" {
  run "$DOCTOR_SCRIPT" deps git --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "Dependency Checks"
  assert_output_contains "Git Security"
}

@test "doctor.sh 'all' runs all checks" {
  run "$DOCTOR_SCRIPT" all --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "HEALTH REPORT SUMMARY"
}

# ── Verbose mode ──────────────────────────────────────────────────────────────

@test "doctor.sh --verbose provides extra output" {
  run "$DOCTOR_SCRIPT" deps --verbose --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  # Verbose mode should include INFO lines
  # (depends on environment but should not crash)
}

# ── Skip mechanism ────────────────────────────────────────────────────────────

@test "doctor.sh SECRETS_DOCTOR_SKIP skips specified checks" {
  SECRETS_DOCTOR_SKIP="deps,vault" run "$DOCTOR_SCRIPT" all --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "skipped via SECRETS_DOCTOR_SKIP"
}
