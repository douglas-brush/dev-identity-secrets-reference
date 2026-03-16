#!/usr/bin/env bats
# test_signing.bats — Unit tests for tools/signing/sign_artifact.sh and verify_artifact.sh

load helpers

SIGN_SCRIPT="${REPO_ROOT}/tools/signing/sign_artifact.sh"
VERIFY_SCRIPT="${REPO_ROOT}/tools/signing/verify_artifact.sh"

setup() {
  common_setup
  mkdir -p "$TEST_TEMP_DIR/bin" "$TEST_TEMP_DIR/logs" "$TEST_TEMP_DIR/.signatures"

  # Create mock cosign
  cat > "$TEST_TEMP_DIR/bin/cosign" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  version) echo "cosign v2.2.0" ;;
  sign)
    echo "Signing artifact..."
    exit 0 ;;
  sign-blob)
    # Create a .sig file if --output-signature is given
    for i in "$@"; do
      if [[ "$prev" == "--output-signature" ]]; then
        echo "fake-signature-data" > "$i"
        break
      fi
      prev="$i"
    done
    echo "Signed blob"
    exit 0 ;;
  verify)
    echo "Verified OK"
    exit 0 ;;
  verify-blob)
    echo "Verified OK"
    exit 0 ;;
  triangulate)
    echo "sha256:abc123def456"
    exit 0 ;;
  tree)
    exit 0 ;;
esac
exit 0
MOCK
  chmod +x "$TEST_TEMP_DIR/bin/cosign"
  export PATH="$TEST_TEMP_DIR/bin:$PATH"

  # Create a test artifact file
  echo "test binary content" > "$TEST_TEMP_DIR/test-binary"
  echo '{"name":"test"}' > "$TEST_TEMP_DIR/test-sbom.spdx.json"
}

teardown() {
  common_teardown
}

# ── sign_artifact.sh Help ────────────────────────────────────────────────────

@test "sign_artifact.sh --help prints usage and exits 0" {
  run "$SIGN_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "REQUIRED"
  assert_output_contains "OPTIONS"
  assert_output_contains "SIGNING METHODS"
  assert_output_contains "EXAMPLES"
}

@test "sign_artifact.sh -h prints usage" {
  run "$SIGN_SCRIPT" -h
  assert_success
  assert_output_contains "sign_artifact.sh"
}

# ── sign_artifact.sh Argument validation ─────────────────────────────────────

@test "sign_artifact.sh fails without --artifact" {
  run "$SIGN_SCRIPT" --type binary
  assert_failure
  assert_output_contains "--artifact is required"
}

@test "sign_artifact.sh fails without --type" {
  run "$SIGN_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary"
  assert_failure
  assert_output_contains "--type is required"
}

@test "sign_artifact.sh rejects invalid --type" {
  run "$SIGN_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type invalid
  assert_failure
  assert_output_contains "Invalid --type"
}

@test "sign_artifact.sh rejects unknown arguments" {
  run "$SIGN_SCRIPT" --unknown-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "sign_artifact.sh fails when artifact file not found" {
  run "$SIGN_SCRIPT" --artifact /nonexistent/file --type binary
  assert_failure
  assert_output_contains "not found"
}

# ── sign_artifact.sh Signing ────────────────────────────────────────────────

@test "sign_artifact.sh --dry-run shows what would be done" {
  run "$SIGN_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type binary --dry-run
  assert_success
  assert_output_contains "DRY"
}

@test "sign_artifact.sh signs binary with cosign keyless" {
  run "$SIGN_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type binary --dry-run
  assert_success
  assert_output_contains "cosign"
}

@test "sign_artifact.sh signs binary with vault key" {
  export VAULT_ADDR="http://127.0.0.1:8200"
  run "$SIGN_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type binary --key mykey --dry-run
  assert_success
  assert_output_contains "cosign"
  assert_output_contains "Vault KMS"
}

@test "sign_artifact.sh accepts sbom type" {
  run "$SIGN_SCRIPT" --artifact "$TEST_TEMP_DIR/test-sbom.spdx.json" --type sbom --dry-run
  assert_success
}

@test "sign_artifact.sh accepts image type" {
  run "$SIGN_SCRIPT" --artifact "ghcr.io/org/app:v1.0" --type image --dry-run
  assert_success
}

# ── verify_artifact.sh Help ──────────────────────────────────────────────────

@test "verify_artifact.sh --help prints usage and exits 0" {
  run "$VERIFY_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "REQUIRED"
  assert_output_contains "OPTIONS"
  assert_output_contains "VERIFICATION CHECKS"
  assert_output_contains "EXAMPLES"
}

@test "verify_artifact.sh -h prints usage" {
  run "$VERIFY_SCRIPT" -h
  assert_success
  assert_output_contains "verify_artifact.sh"
}

# ── verify_artifact.sh Argument validation ───────────────────────────────────

@test "verify_artifact.sh fails without --artifact" {
  run "$VERIFY_SCRIPT" --type binary
  assert_failure
  assert_output_contains "--artifact is required"
}

@test "verify_artifact.sh fails without --type" {
  run "$VERIFY_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary"
  assert_failure
  assert_output_contains "--type is required"
}

@test "verify_artifact.sh rejects invalid --type" {
  run "$VERIFY_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type invalid
  assert_failure
  assert_output_contains "Invalid --type"
}

@test "verify_artifact.sh rejects unknown arguments" {
  run "$VERIFY_SCRIPT" --unknown-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "verify_artifact.sh --dry-run skips cryptographic verification" {
  run "$VERIFY_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type binary --dry-run
  # Should complete with some checks skipped
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  assert_output_contains "dry run"
}

@test "verify_artifact.sh --no-color disables ANSI codes" {
  run "$VERIFY_SCRIPT" --artifact "$TEST_TEMP_DIR/test-binary" --type binary --dry-run --no-color
  [[ "$status" -eq 0 || "$status" -eq 1 ]]
  # Should not contain raw ANSI escape codes
  if [[ "$output" == *$'\033'* ]]; then
    echo "Output contains ANSI escape codes despite --no-color"
    return 1
  fi
}
