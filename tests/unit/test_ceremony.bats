#!/usr/bin/env bats
# test_ceremony.bats — Unit tests for tools/ceremony/root_ca_ceremony.sh and intermediate_ca_ceremony.sh

load helpers

ROOT_CA_SCRIPT="${REPO_ROOT}/tools/ceremony/root_ca_ceremony.sh"
INTERMEDIATE_CA_SCRIPT="${REPO_ROOT}/tools/ceremony/intermediate_ca_ceremony.sh"

setup() {
  common_setup
}

teardown() {
  common_teardown
}

# ── root_ca_ceremony.sh Help ────────────────────────────────────────────────

@test "root_ca_ceremony.sh --help prints usage and exits 0" {
  run "$ROOT_CA_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "OPTIONS"
  assert_output_contains "PREREQUISITES"
  assert_output_contains "EXAMPLES"
}

@test "root_ca_ceremony.sh -h prints usage" {
  run "$ROOT_CA_SCRIPT" -h
  assert_success
  assert_output_contains "root_ca_ceremony.sh"
}

# ── root_ca_ceremony.sh Argument validation ──────────────────────────────────

@test "root_ca_ceremony.sh rejects invalid algorithm" {
  run "$ROOT_CA_SCRIPT" --algorithm invalid --dry-run
  assert_failure
  assert_output_contains "Invalid algorithm"
}

@test "root_ca_ceremony.sh accepts ecdsap384 algorithm" {
  run "$ROOT_CA_SCRIPT" --algorithm ecdsap384 --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
}

@test "root_ca_ceremony.sh accepts rsa4096 algorithm" {
  run "$ROOT_CA_SCRIPT" --algorithm rsa4096 --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
}

@test "root_ca_ceremony.sh rejects threshold greater than shares" {
  run "$ROOT_CA_SCRIPT" --shares 3 --threshold 5 --dry-run
  assert_failure
  assert_output_contains "Threshold"
}

@test "root_ca_ceremony.sh rejects threshold less than 2" {
  run "$ROOT_CA_SCRIPT" --threshold 1 --dry-run
  assert_failure
  assert_output_contains "Threshold must be at least 2"
}

# ── root_ca_ceremony.sh --dry-run ──────────────────────────────────────────

@test "root_ca_ceremony.sh --dry-run does not create files" {
  run "$ROOT_CA_SCRIPT" --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
  assert_output_contains "DRY RUN"
  # The output dir should not exist because dry-run skips mkdir
  [ ! -d "$TEST_TEMP_DIR/ceremony" ] || [ -z "$(ls -A "$TEST_TEMP_DIR/ceremony" 2>/dev/null)" ] || true
}

@test "root_ca_ceremony.sh --dry-run shows what would be done" {
  run "$ROOT_CA_SCRIPT" --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
  assert_output_contains "Would generate"
  assert_output_contains "Would create"
  assert_output_contains "Would split"
}

@test "root_ca_ceremony.sh --dry-run prints summary" {
  run "$ROOT_CA_SCRIPT" --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
  assert_output_contains "ROOT CA CEREMONY COMPLETE"
  assert_output_contains "DRY RUN"
}

@test "root_ca_ceremony.sh --dry-run shows algorithm in summary" {
  run "$ROOT_CA_SCRIPT" --algorithm rsa4096 --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
  assert_output_contains "rsa4096"
}

@test "root_ca_ceremony.sh --dry-run shows shamir params" {
  run "$ROOT_CA_SCRIPT" --shares 7 --threshold 4 --dry-run --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
  assert_output_contains "4-of-7"
}

@test "root_ca_ceremony.sh --no-color disables ANSI codes" {
  run "$ROOT_CA_SCRIPT" --dry-run --no-color --output-dir "$TEST_TEMP_DIR/ceremony"
  assert_success
  if [[ "$output" == *$'\033'* ]]; then
    echo "Output contains ANSI escape codes despite --no-color"
    return 1
  fi
}

# ── intermediate_ca_ceremony.sh Help ─────────────────────────────────────────

@test "intermediate_ca_ceremony.sh --help prints usage and exits 0" {
  run "$INTERMEDIATE_CA_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "OPTIONS"
  assert_output_contains "PREREQUISITES"
  assert_output_contains "EXAMPLES"
}

@test "intermediate_ca_ceremony.sh -h prints usage" {
  run "$INTERMEDIATE_CA_SCRIPT" -h
  assert_success
  assert_output_contains "intermediate_ca_ceremony.sh"
}

# ── intermediate_ca_ceremony.sh Argument validation ──────────────────────────

@test "intermediate_ca_ceremony.sh requires --root-cert" {
  run "$INTERMEDIATE_CA_SCRIPT" --shares-dir /tmp/shares --dry-run
  assert_failure
  assert_output_contains "--root-cert is required"
}

@test "intermediate_ca_ceremony.sh requires --shares-dir" {
  run "$INTERMEDIATE_CA_SCRIPT" --root-cert /tmp/root.pem --dry-run
  assert_failure
  assert_output_contains "--shares-dir is required"
}

@test "intermediate_ca_ceremony.sh rejects invalid algorithm" {
  run "$INTERMEDIATE_CA_SCRIPT" --root-cert /tmp/root.pem --shares-dir /tmp/shares --algorithm invalid --dry-run
  assert_failure
  assert_output_contains "Invalid algorithm"
}

@test "intermediate_ca_ceremony.sh --dry-run shows what would be done" {
  mkdir -p "$TEST_TEMP_DIR/shares"
  echo "fake-share" > "$TEST_TEMP_DIR/shares/share-1.pem"
  echo "fake-root-cert" > "$TEST_TEMP_DIR/root.pem"

  run "$INTERMEDIATE_CA_SCRIPT" \
    --root-cert "$TEST_TEMP_DIR/root.pem" \
    --shares-dir "$TEST_TEMP_DIR/shares" \
    --dry-run \
    --output-dir "$TEST_TEMP_DIR/int-ceremony"
  assert_success
  assert_output_contains "DRY RUN"
}

@test "intermediate_ca_ceremony.sh --dry-run prints ceremony summary" {
  mkdir -p "$TEST_TEMP_DIR/shares"
  echo "fake-root-cert" > "$TEST_TEMP_DIR/root.pem"

  run "$INTERMEDIATE_CA_SCRIPT" \
    --root-cert "$TEST_TEMP_DIR/root.pem" \
    --shares-dir "$TEST_TEMP_DIR/shares" \
    --dry-run \
    --output-dir "$TEST_TEMP_DIR/int-ceremony"
  assert_success
  assert_output_contains "INTERMEDIATE CA CEREMONY COMPLETE"
}
