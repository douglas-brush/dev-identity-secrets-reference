#!/usr/bin/env bats
# test_plaintext_scan.bats — Unit tests for bootstrap/scripts/check_no_plaintext_secrets.sh

load helpers

SCANNER_SCRIPT="${REPO_ROOT}/bootstrap/scripts/check_no_plaintext_secrets.sh"

setup() {
  common_setup

  # The scanner computes ROOT_DIR from its own path as ../../ from BASH_SOURCE.
  # To test in isolation, create a fake repo layout that mirrors this structure.
  mkdir -p "$TEST_TEMP_DIR/bootstrap/scripts"
  cp "$SCANNER_SCRIPT" "$TEST_TEMP_DIR/bootstrap/scripts/check_no_plaintext_secrets.sh"
  chmod +x "$TEST_TEMP_DIR/bootstrap/scripts/check_no_plaintext_secrets.sh"

  # Create .git dir so find doesn't complain
  mkdir -p "$TEST_TEMP_DIR/.git"

  SCANNER="$TEST_TEMP_DIR/bootstrap/scripts/check_no_plaintext_secrets.sh"
}

teardown() {
  common_teardown
}

# ── Clean files produce no findings ───────────────────────────────────────────

@test "scanner exits 0 on clean files" {
  cat > "$TEST_TEMP_DIR/app.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  LOG_LEVEL: debug
  APP_NAME: my-app
EOF

  run "$SCANNER" text
  assert_success
  assert_output_contains "No plaintext secrets detected"
}

@test "scanner JSON mode returns empty array on clean files" {
  cat > "$TEST_TEMP_DIR/clean.yaml" <<'EOF'
config:
  name: test
  value: hello
EOF

  run "$SCANNER" json
  assert_success
  assert_output_contains "[]"
}

# ── AWS key detection ─────────────────────────────────────────────────────────

@test "scanner detects AWS access key" {
  cat > "$TEST_TEMP_DIR/config.yaml" <<'EOF'
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "AWS Access Key"
}

@test "scanner detects AWS secret key" {
  cat > "$TEST_TEMP_DIR/config.sh" <<'EOF'
export aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "AWS Secret Key"
}

# ── GitHub token detection ────────────────────────────────────────────────────

@test "scanner detects GitHub PAT" {
  cat > "$TEST_TEMP_DIR/ci.yaml" <<'EOF'
github:
  token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "GitHub"
}

# ── Private key detection ─────────────────────────────────────────────────────

@test "scanner detects PEM private key" {
  cat > "$TEST_TEMP_DIR/server.yaml" <<'EOF'
tls:
  key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJlGFOPg2AOqe+d7EXXXXXX
    -----END RSA PRIVATE KEY-----
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "Private Key PEM"
}

# ── JWT detection ─────────────────────────────────────────────────────────────

@test "scanner detects JWT token" {
  cat > "$TEST_TEMP_DIR/auth.json" <<'EOF'
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dizfSwOupErNLBLkpoU6G4RmT7XZVpZQk"
}
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "JWT Token"
}

# ── Generic password detection ────────────────────────────────────────────────

@test "scanner detects generic password assignment" {
  cat > "$TEST_TEMP_DIR/config.env" <<'EOF'
password=SuperSecretP@ssw0rd123
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "Generic Secret"
}

# ── Exclusion patterns ────────────────────────────────────────────────────────

@test "scanner skips .enc.yaml files" {
  cat > "$TEST_TEMP_DIR/secrets.enc.yaml" <<'EOF'
password=SuperSecretP@ssw0rd123
AKIAIOSFODNN7EXAMPLE
EOF

  # Only the enc file exists -- should find nothing
  run "$SCANNER" text
  assert_success
}

@test "scanner skips .git directory" {
  cat > "$TEST_TEMP_DIR/.git/secret_config" <<'EOF'
password=SuperSecretP@ssw0rd123
EOF

  run "$SCANNER" text
  assert_success
}

# ── JSON output format ────────────────────────────────────────────────────────

@test "scanner JSON output contains file and pattern fields" {
  require_command jq

  cat > "$TEST_TEMP_DIR/leak.yaml" <<'EOF'
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
EOF

  run "$SCANNER" json
  assert_failure

  # Validate JSON structure
  echo "$output" | jq '.[0].file' >/dev/null 2>&1
  [ $? -eq 0 ]

  echo "$output" | jq '.[0].pattern' >/dev/null 2>&1
  [ $? -eq 0 ]
}

# ── .secretsignore support ────────────────────────────────────────────────────

@test "scanner respects .secretsignore file" {
  cat > "$TEST_TEMP_DIR/test-fixture.yaml" <<'EOF'
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
EOF

  cat > "$TEST_TEMP_DIR/.secretsignore" <<'EOF'
test-fixture.yaml
EOF

  run "$SCANNER" text
  assert_success
}

# ── Multiple findings ─────────────────────────────────────────────────────────

@test "scanner reports multiple findings from different files" {
  cat > "$TEST_TEMP_DIR/aws.yaml" <<'EOF'
key: AKIAIOSFODNN7EXAMPLE
EOF

  cat > "$TEST_TEMP_DIR/gh.yaml" <<'EOF'
token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
EOF

  run "$SCANNER" text
  assert_failure
  assert_output_contains "Plaintext secret scan FAILED"
}
