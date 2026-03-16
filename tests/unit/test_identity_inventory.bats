#!/usr/bin/env bats
# test_identity_inventory.bats — Unit tests for tools/audit/identity_inventory.sh

load helpers

SCRIPT="${REPO_ROOT}/tools/audit/identity_inventory.sh"

setup() {
  common_setup
  mkdir -p "$TEST_TEMP_DIR/logs"
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

@test "identity_inventory.sh --help prints usage and exits 0" {
  run "$SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "OPTIONS"
  assert_output_contains "DESCRIPTION"
  assert_output_contains "ENVIRONMENT"
  assert_output_contains "EXIT CODES"
  assert_output_contains "EXAMPLES"
}

@test "identity_inventory.sh -h prints usage" {
  run "$SCRIPT" -h
  assert_success
  assert_output_contains "identity_inventory.sh"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

@test "identity_inventory.sh rejects unknown arguments" {
  run "$SCRIPT" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "identity_inventory.sh accepts --json flag" {
  run "$SCRIPT" --json --help
  assert_success
}

@test "identity_inventory.sh accepts --namespace flag" {
  run "$SCRIPT" --namespace prod --help
  assert_success
}

@test "identity_inventory.sh accepts --verbose flag" {
  run "$SCRIPT" --verbose --help
  assert_success
}

# ── Graceful skip when tools unavailable ─────────────────────────────────────

@test "identity_inventory.sh runs without vault" {
  unset VAULT_ADDR
  run "$SCRIPT"
  assert_success
  assert_output_contains "NON-HUMAN IDENTITY INVENTORY" || assert_output_contains "Non-Human Identity Inventory"
}

@test "identity_inventory.sh shows text table by default" {
  unset VAULT_ADDR
  run "$SCRIPT"
  assert_success
  assert_output_contains "NON-HUMAN IDENTITY INVENTORY" || assert_output_contains "Non-Human Identity Inventory"
}

@test "identity_inventory.sh --json outputs JSON" {
  unset VAULT_ADDR
  run "$SCRIPT" --json
  assert_success
  assert_output_contains '"report"'
  assert_output_contains '"non_human_identity_inventory"'
  assert_output_contains '"total_identities"'
}

@test "identity_inventory.sh skips kubectl when not connected" {
  unset VAULT_ADDR
  run "$SCRIPT"
  # Should not crash, even if kubectl can't connect
  assert_success
}

@test "identity_inventory.sh skips vault when VAULT_ADDR not set" {
  unset VAULT_ADDR
  run "$SCRIPT"
  assert_success
  assert_output_contains "SKIP" || assert_output_contains "not set" || assert_output_contains "not installed"
}

@test "identity_inventory.sh records inventory timestamp in JSON" {
  unset VAULT_ADDR
  run "$SCRIPT" --json
  assert_success
  assert_output_contains '"timestamp"'
}
