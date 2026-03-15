#!/usr/bin/env bats
# test_onboard.bats — Unit tests for bootstrap/scripts/onboard_app.sh

load helpers

ONBOARD_SCRIPT="${REPO_ROOT}/bootstrap/scripts/onboard_app.sh"

setup() {
  common_setup
}

teardown() {
  common_teardown
}

# ── Help output ───────────────────────────────────────────────────────────────

@test "onboard_app.sh --help prints usage and exits 0" {
  run "$ONBOARD_SCRIPT" --help
  assert_success
  assert_output_contains "Usage: onboard_app.sh"
  assert_output_contains "Arguments"
  assert_output_contains "Options"
  assert_output_contains "Examples"
}

@test "onboard_app.sh -h prints usage and exits 0" {
  run "$ONBOARD_SCRIPT" -h
  assert_success
  assert_output_contains "Usage: onboard_app.sh"
}

@test "onboard_app.sh with no arguments prints usage" {
  run "$ONBOARD_SCRIPT"
  assert_success
  assert_output_contains "Usage:"
}

@test "onboard_app.sh with one argument prints usage" {
  run "$ONBOARD_SCRIPT" my-app
  assert_success
  assert_output_contains "Usage:"
}

# ── Platform flag validation ──────────────────────────────────────────────────

@test "onboard_app.sh rejects unknown platform" {
  run "$ONBOARD_SCRIPT" my-app dev --platform invalid
  assert_failure
  assert_output_contains "Unknown platform"
}

@test "onboard_app.sh accepts platform=k8s" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Platform:    k8s"
}

@test "onboard_app.sh accepts platform=ecs" {
  run "$ONBOARD_SCRIPT" my-app dev --platform ecs --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Platform:    ecs"
}

@test "onboard_app.sh accepts platform=lambda" {
  run "$ONBOARD_SCRIPT" my-app dev --platform lambda --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Platform:    lambda"
}

@test "onboard_app.sh accepts platform=none" {
  run "$ONBOARD_SCRIPT" my-app dev --platform none --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Platform:    none"
}

# ── Vault policy generation ──────────────────────────────────────────────────

@test "onboard_app.sh generates vault policy" {
  run "$ONBOARD_SCRIPT" my-api dev --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Vault Policy"
  assert_output_contains 'path "kv/data/dev/apps/my-api/*"'
}

@test "onboard_app.sh vault policy has correct path scoping" {
  run "$ONBOARD_SCRIPT" my-api prod --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains 'path "kv/data/prod/apps/my-api/*"'
  assert_output_contains 'path "database/creds/prod-my-api"'
}

# ── --output-dir writes files ─────────────────────────────────────────────────

@test "onboard_app.sh --output-dir writes vault policy file" {
  run "$ONBOARD_SCRIPT" my-app dev --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_file_exists "$TEST_TEMP_DIR/vault-policy-dev-my-app.hcl"
}

@test "onboard_app.sh --output-dir writes k8s manifests" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_file_exists "$TEST_TEMP_DIR/vault-policy-dev-my-app.hcl"
  assert_file_exists "$TEST_TEMP_DIR/namespace.yaml"
  assert_file_exists "$TEST_TEMP_DIR/service-account.yaml"
  assert_file_exists "$TEST_TEMP_DIR/secret-delivery-eso.yaml"
}

@test "onboard_app.sh --output-dir policy file contains correct content" {
  run "$ONBOARD_SCRIPT" test-svc staging --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_file_contains "$TEST_TEMP_DIR/vault-policy-staging-test-svc.hcl" "kv/data/staging/apps/test-svc"
}

# ── K8s delivery methods ─────────────────────────────────────────────────────

@test "onboard_app.sh --delivery eso generates ExternalSecret" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --delivery eso --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "ExternalSecret"
  assert_file_exists "$TEST_TEMP_DIR/secret-delivery-eso.yaml"
}

@test "onboard_app.sh --delivery csi generates SecretProviderClass" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --delivery csi --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "SecretProviderClass"
  assert_file_exists "$TEST_TEMP_DIR/secret-delivery-csi.yaml"
}

# ── Certificate generation ────────────────────────────────────────────────────

@test "onboard_app.sh --cert generates Certificate manifest" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --cert --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Certificate"
  assert_file_exists "$TEST_TEMP_DIR/certificate.yaml"
}

# ── Namespace defaulting ─────────────────────────────────────────────────────

@test "onboard_app.sh k8s namespace defaults to app name" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Namespace:   my-app"
}

@test "onboard_app.sh --namespace overrides default" {
  run "$ONBOARD_SCRIPT" my-app dev --platform k8s --namespace custom-ns --output-dir "$TEST_TEMP_DIR"
  assert_success
  assert_output_contains "Namespace:   custom-ns"
}

# ── Unknown option handling ───────────────────────────────────────────────────

@test "onboard_app.sh rejects unknown options" {
  run "$ONBOARD_SCRIPT" my-app dev --unknown-flag
  assert_failure
  assert_output_contains "Unknown option"
}
