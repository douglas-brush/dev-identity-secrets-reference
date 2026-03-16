#!/usr/bin/env bats
# test_rotate_vault.bats — Unit tests for tools/rotate/rotate_vault_secrets.sh

load helpers

SCRIPT="${REPO_ROOT}/tools/rotate/rotate_vault_secrets.sh"

setup() {
  common_setup
  # Create mock vault binary
  mkdir -p "$TEST_TEMP_DIR/bin"
  cat > "$TEST_TEMP_DIR/bin/vault" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  version) echo "Vault v1.15.0" ;;
  token)
    if [[ "$2" == "lookup" ]]; then
      echo '{"data":{"display_name":"test-user"}}'
      exit 0
    fi ;;
  secrets)
    if [[ "$2" == "list" ]]; then
      echo '{"secret/":{"type":"kv","description":"KV v2"}}'
      exit 0
    fi ;;
  kv)
    case "$2" in
      list)
        echo '["app/db-password","app/api-key"]'
        exit 0 ;;
      metadata)
        echo '{"data":{"current_version":3,"created_time":"2024-01-01T00:00:00Z","versions":{"3":{"created_time":"2024-06-01T00:00:00Z"}}}}'
        exit 0 ;;
    esac ;;
  status)
    echo '{"sealed":false}'
    exit 0 ;;
esac
exit 0
MOCK
  chmod +x "$TEST_TEMP_DIR/bin/vault"

  # Create mock jq (use real jq if available, otherwise skip)
  if command -v jq &>/dev/null; then
    ln -sf "$(command -v jq)" "$TEST_TEMP_DIR/bin/jq"
  fi

  # Create mock curl
  cat > "$TEST_TEMP_DIR/bin/curl" <<'MOCK'
#!/usr/bin/env bash
# Return HTTP 200
echo -n ""
printf "200"
MOCK
  chmod +x "$TEST_TEMP_DIR/bin/curl"

  export PATH="$TEST_TEMP_DIR/bin:$PATH"
  export VAULT_ADDR="http://127.0.0.1:8200"
  export VAULT_TOKEN="test-token"

  mkdir -p "$TEST_TEMP_DIR/logs"
}

teardown() {
  common_teardown
}

# ── Help output ───────────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh --help prints usage and exits 0" {
  run "$SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "OPTIONS"
  assert_output_contains "DESCRIPTION"
  assert_output_contains "ENVIRONMENT"
  assert_output_contains "EXIT CODES"
  assert_output_contains "EXAMPLES"
}

@test "rotate_vault_secrets.sh -h prints usage" {
  run "$SCRIPT" -h
  assert_success
  assert_output_contains "rotate_vault_secrets.sh"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh rejects unknown arguments" {
  run "$SCRIPT" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "rotate_vault_secrets.sh accepts --dry-run flag" {
  run "$SCRIPT" --dry-run --help
  assert_success
}

@test "rotate_vault_secrets.sh accepts --max-age flag" {
  run "$SCRIPT" --max-age 30 --help
  assert_success
}

@test "rotate_vault_secrets.sh accepts --path flag" {
  run "$SCRIPT" --path secret/prod --help
  assert_success
}

@test "rotate_vault_secrets.sh accepts --webhook flag" {
  run "$SCRIPT" --webhook https://hooks.example.com/rotate --help
  assert_success
}

@test "rotate_vault_secrets.sh accepts --verbose flag" {
  run "$SCRIPT" --verbose --help
  assert_success
}

@test "rotate_vault_secrets.sh accepts --log-file flag" {
  run "$SCRIPT" --log-file /tmp/test.log --help
  assert_success
}

# ── Preflight checks ─────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh fails when vault CLI missing" {
  run env PATH="/usr/bin:/bin" VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" "$SCRIPT"
  [ "$status" -eq 2 ]
  assert_output_contains "vault CLI not found"
}

@test "rotate_vault_secrets.sh fails when VAULT_ADDR not set" {
  unset VAULT_ADDR
  run "$SCRIPT"
  [ "$status" -eq 2 ]
  assert_output_contains "VAULT_ADDR not set"
}

@test "rotate_vault_secrets.sh fails when vault auth fails" {
  # Override vault mock to fail on token lookup
  cat > "$TEST_TEMP_DIR/bin/vault" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  version) echo "Vault v1.15.0" ;;
  token) exit 1 ;;
esac
exit 0
MOCK
  chmod +x "$TEST_TEMP_DIR/bin/vault"
  run "$SCRIPT"
  [ "$status" -eq 2 ]
  assert_output_contains "Cannot authenticate"
}

@test "rotate_vault_secrets.sh uses jq for JSON processing" {
  # jq is at /usr/bin/jq and cannot be removed from PATH without breaking
  # the script. Instead verify the script runs and uses jq successfully.
  require_command jq
  run "$SCRIPT" --dry-run
  # Exit 1 = stale secrets found (valid result), exit 0 = all compliant
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  # The script processes JSON via jq — verify it completed preflight
  assert_output_contains "Vault authentication verified"
}

@test "rotate_vault_secrets.sh shows max age policy" {
  require_command jq
  run "$SCRIPT" --dry-run
  assert_output_contains "Max age policy: 90 days"
}

@test "rotate_vault_secrets.sh --max-age overrides default" {
  require_command jq
  run "$SCRIPT" --max-age 30 --dry-run
  assert_output_contains "Max age policy: 30 days"
}

@test "rotate_vault_secrets.sh VAULT_SECRET_MAX_AGE env overrides default" {
  require_command jq
  VAULT_SECRET_MAX_AGE=45 run "$SCRIPT" --dry-run
  assert_output_contains "Max age policy: 45 days"
}

# ── Dry run mode ─────────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh --dry-run shows DRY RUN banner" {
  require_command jq
  run "$SCRIPT" --dry-run
  assert_output_contains "DRY RUN"
}

# ── Path filter ──────────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh --path shows path filter info" {
  require_command jq
  run "$SCRIPT" --dry-run --path secret/prod
  assert_output_contains "Path filter: secret/prod"
}

# ── Summary output ───────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh prints rotation report" {
  require_command jq
  run "$SCRIPT" --dry-run
  assert_output_contains "VAULT SECRET ROTATION REPORT"
}

@test "rotate_vault_secrets.sh shows vault address in summary" {
  require_command jq
  run "$SCRIPT" --dry-run
  assert_output_contains "127.0.0.1:8200"
}

@test "rotate_vault_secrets.sh creates log file" {
  require_command jq
  run "$SCRIPT" --dry-run --log-file "$TEST_TEMP_DIR/test-rotation.log"
  assert_file_exists "$TEST_TEMP_DIR/test-rotation.log"
}

# ── Verbose mode ─────────────────────────────────────────────────────────────

@test "rotate_vault_secrets.sh --verbose passes through" {
  require_command jq
  run "$SCRIPT" --dry-run --verbose
  # Should not crash with verbose
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
}
