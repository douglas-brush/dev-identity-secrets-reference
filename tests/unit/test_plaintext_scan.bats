#!/usr/bin/env bats
# test_plaintext_scan.bats — Unit tests for bootstrap/scripts/check_no_plaintext_secrets.sh

load helpers

SCANNER_SCRIPT="${REPO_ROOT}/bootstrap/scripts/check_no_plaintext_secrets.sh"

setup() {
  common_setup

  # Create a fake repo structure for the scanner to scan
  mkdir -p "$TEST_TEMP_DIR/repo/.git"
  touch "$TEST_TEMP_DIR/repo/.git/HEAD"
}

teardown() {
  common_teardown
}

# ── Clean files produce no findings ───────────────────────────────────────────

@test "scanner exits 0 on clean files" {
  # Create a clean file with no secrets
  cat > "$TEST_TEMP_DIR/repo/app.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  LOG_LEVEL: debug
  APP_NAME: my-app
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_success
  assert_output_contains "No plaintext secrets detected"
}

@test "scanner JSON mode returns empty array on clean files" {
  cat > "$TEST_TEMP_DIR/repo/clean.yaml" <<'EOF'
config:
  name: test
  value: hello
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" json
  assert_success
  assert_output_contains "[]"
}

# ── AWS key detection ─────────────────────────────────────────────────────────

@test "scanner detects AWS access key" {
  cat > "$TEST_TEMP_DIR/repo/config.yaml" <<'EOF'
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "AWS Access Key"
}

@test "scanner detects AWS secret key" {
  cat > "$TEST_TEMP_DIR/repo/config.sh" <<'EOF'
export aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "AWS Secret Key"
}

# ── GitHub token detection ────────────────────────────────────────────────────

@test "scanner detects GitHub PAT" {
  cat > "$TEST_TEMP_DIR/repo/ci.yaml" <<'EOF'
github:
  token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "GitHub"
}

# ── Private key detection ─────────────────────────────────────────────────────

@test "scanner detects PEM private key" {
  cat > "$TEST_TEMP_DIR/repo/key.txt" <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJlGFOPg2AOqe+d7EXXXXXX
-----END RSA PRIVATE KEY-----
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "Private Key PEM"
}

# ── JWT detection ─────────────────────────────────────────────────────────────

@test "scanner detects JWT token" {
  cat > "$TEST_TEMP_DIR/repo/auth.json" <<'EOF'
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dizfSwOupErNLBLkpoU6G4RmT7XZVpZQk"
}
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "JWT Token"
}

# ── Generic password detection ────────────────────────────────────────────────

@test "scanner detects generic password assignment" {
  cat > "$TEST_TEMP_DIR/repo/config.env" <<'EOF'
password=SuperSecretP@ssw0rd123
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "Generic Secret"
}

# ── Exclusion patterns ────────────────────────────────────────────────────────

@test "scanner skips .enc.yaml files" {
  cat > "$TEST_TEMP_DIR/repo/secrets.enc.yaml" <<'EOF'
password=SuperSecretP@ssw0rd123
AKIAIOSFODNN7EXAMPLE
EOF

  # Only the enc file exists — should find nothing
  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_success
}

@test "scanner skips .git directory" {
  cat > "$TEST_TEMP_DIR/repo/.git/config" <<'EOF'
password=SuperSecretP@ssw0rd123
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_success
}

# ── JSON output format ────────────────────────────────────────────────────────

@test "scanner JSON output contains file and pattern fields" {
  require_command jq

  cat > "$TEST_TEMP_DIR/repo/leak.yaml" <<'EOF'
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" json
  assert_failure

  # Validate JSON structure
  echo "$output" | jq '.[0].file' >/dev/null 2>&1
  [ $? -eq 0 ]

  echo "$output" | jq '.[0].pattern' >/dev/null 2>&1
  [ $? -eq 0 ]
}

# ── .secretsignore support ────────────────────────────────────────────────────

@test "scanner respects .secretsignore file" {
  cat > "$TEST_TEMP_DIR/repo/test-fixture.yaml" <<'EOF'
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
EOF

  cat > "$TEST_TEMP_DIR/repo/.secretsignore" <<'EOF'
test-fixture.yaml
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_success
}

# ── Multiple findings ─────────────────────────────────────────────────────────

@test "scanner reports multiple findings from different files" {
  cat > "$TEST_TEMP_DIR/repo/aws.yaml" <<'EOF'
key: AKIAIOSFODNN7EXAMPLE
EOF

  cat > "$TEST_TEMP_DIR/repo/gh.yaml" <<'EOF'
token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
EOF

  cd "$TEST_TEMP_DIR/repo"
  run "$SCANNER_SCRIPT" text
  assert_failure
  assert_output_contains "Plaintext secret scan FAILED"
}
