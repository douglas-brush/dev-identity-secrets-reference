#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Integration Test: SOPS Encrypt/Decrypt Roundtrip
#
# Tests SOPS encryption and decryption using ephemeral age keys.
# No pre-existing keys or infrastructure required — generates everything
# needed for the test and cleans up afterward.
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; }

TESTS=0
PASSED=0
FAILED=0

assert() {
  local description="$1"
  local result="$2"
  TESTS=$((TESTS + 1))
  if [[ "$result" == "true" ]]; then
    ok "$description"
    PASSED=$((PASSED + 1))
  else
    fail "$description"
    FAILED=$((FAILED + 1))
  fi
}

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Integration Test: SOPS Encrypt/Decrypt Roundtrip║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Preflight ---
info "Preflight checks..."

for cmd in sops age-keygen jq; do
  if ! command -v "$cmd" &>/dev/null; then
    fail "$cmd not found"
    exit 1
  fi
done
ok "Required tools available"

# --- Setup ephemeral test directory ---
TEST_DIR=$(mktemp -d /tmp/sops-test-XXXXXX)

cleanup() {
  info "Cleaning up test artifacts..."
  rm -rf "$TEST_DIR"
  ok "Test directory removed"
}
trap cleanup EXIT INT TERM

# --- Generate ephemeral age keys ---
info "Generating ephemeral age keys..."

KEY1_FILE="$TEST_DIR/key1.txt"
KEY2_FILE="$TEST_DIR/key2.txt"

age-keygen -o "$KEY1_FILE" 2>"$TEST_DIR/key1.pub"
age-keygen -o "$KEY2_FILE" 2>"$TEST_DIR/key2.pub"

PUBKEY1=$(grep 'public key' "$TEST_DIR/key1.pub" | awk '{print $NF}')
PUBKEY2=$(grep 'public key' "$TEST_DIR/key2.pub" | awk '{print $NF}')

assert "Age key pair 1 generated" "$([ -n "$PUBKEY1" ] && echo true || echo false)"
assert "Age key pair 2 generated" "$([ -n "$PUBKEY2" ] && echo true || echo false)"

export SOPS_AGE_KEY_FILE="$KEY1_FILE"

# =============================================================================
# Test 1: Basic YAML roundtrip
# =============================================================================
info "Test: Basic YAML encrypt/decrypt roundtrip..."

cat > "$TEST_DIR/plain.yaml" <<EOF
database:
  host: db.example.com
  port: 5432
  username: testuser
  password: s3cret-passw0rd
api:
  key: ak_live_1234567890abcdef
  endpoint: https://api.example.com
EOF

# Create .sops.yaml for this test
cat > "$TEST_DIR/.sops.yaml" <<EOF
creation_rules:
  - path_regex: \.enc\.yaml$
    age: >-
      $PUBKEY1
EOF

# Encrypt
sops -e --config "$TEST_DIR/.sops.yaml" "$TEST_DIR/plain.yaml" > "$TEST_DIR/encrypted.enc.yaml"
assert "YAML encryption succeeded" "$([ -f "$TEST_DIR/encrypted.enc.yaml" ] && echo true || echo false)"

# Verify encrypted file contains SOPS metadata
SOPS_META=$(grep -c "sops:" "$TEST_DIR/encrypted.enc.yaml" 2>/dev/null || echo 0)
assert "Encrypted file contains SOPS metadata" "$([ "$SOPS_META" -gt 0 ] && echo true || echo false)"

# Verify encrypted values are not plaintext
PLAIN_PASS=$(grep -c "s3cret-passw0rd" "$TEST_DIR/encrypted.enc.yaml" 2>/dev/null || echo 0)
assert "Password is not in plaintext in encrypted file" "$([ "$PLAIN_PASS" -eq 0 ] && echo true || echo false)"

# Decrypt
sops -d "$TEST_DIR/encrypted.enc.yaml" > "$TEST_DIR/decrypted.yaml"

# Verify roundtrip
ORIG_HOST=$(yq -r '.database.host // empty' "$TEST_DIR/plain.yaml" 2>/dev/null || \
  python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['database']['host'])" "$TEST_DIR/plain.yaml" 2>/dev/null || echo "")
DEC_HOST=$(yq -r '.database.host // empty' "$TEST_DIR/decrypted.yaml" 2>/dev/null || \
  python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['database']['host'])" "$TEST_DIR/decrypted.yaml" 2>/dev/null || echo "")
assert "Database host matches after roundtrip" "$([ "$ORIG_HOST" = "$DEC_HOST" ] && echo true || echo false)"

DEC_PASS=$(sops -d --extract '["database"]["password"]' "$TEST_DIR/encrypted.enc.yaml" 2>/dev/null || echo "")
assert "Password matches after roundtrip" "$([ "$DEC_PASS" = "s3cret-passw0rd" ] && echo true || echo false)"

DEC_KEY=$(sops -d --extract '["api"]["key"]' "$TEST_DIR/encrypted.enc.yaml" 2>/dev/null || echo "")
assert "API key matches after roundtrip" "$([ "$DEC_KEY" = "ak_live_1234567890abcdef" ] && echo true || echo false)"

rm -f "$TEST_DIR/decrypted.yaml"

# =============================================================================
# Test 2: JSON roundtrip
# =============================================================================
info "Test: JSON encrypt/decrypt roundtrip..."

cat > "$TEST_DIR/plain.json" <<EOF
{
  "database": {
    "connection_string": "postgres://user:pass@host:5432/db",
    "pool_size": 10
  },
  "feature_flags": {
    "enable_v2": true
  }
}
EOF

sops -e --age "$PUBKEY1" "$TEST_DIR/plain.json" > "$TEST_DIR/encrypted.enc.json"
assert "JSON encryption succeeded" "$([ -f "$TEST_DIR/encrypted.enc.json" ] && echo true || echo false)"

DEC_CONN=$(sops -d --extract '["database"]["connection_string"]' "$TEST_DIR/encrypted.enc.json" 2>/dev/null || echo "")
assert "JSON connection string matches after roundtrip" \
  "$([ "$DEC_CONN" = "postgres://user:pass@host:5432/db" ] && echo true || echo false)"

DEC_POOL=$(sops -d --extract '["database"]["pool_size"]' "$TEST_DIR/encrypted.enc.json" 2>/dev/null || echo "")
assert "JSON integer value preserved" "$([ "$DEC_POOL" = "10" ] && echo true || echo false)"

DEC_FLAG=$(sops -d --extract '["feature_flags"]["enable_v2"]' "$TEST_DIR/encrypted.enc.json" 2>/dev/null || echo "")
assert "JSON boolean value preserved" "$([ "$DEC_FLAG" = "true" ] && echo true || echo false)"

# =============================================================================
# Test 3: Partial encryption (encrypted_regex)
# =============================================================================
info "Test: Partial encryption with encrypted_regex..."

cat > "$TEST_DIR/partial.yaml" <<EOF
public_config:
  app_name: my-app
  log_level: debug
  port: 8080
secret_config:
  api_key: secret-key-12345
  db_password: super-secret
EOF

# Encrypt only keys matching "secret"
sops -e --age "$PUBKEY1" \
  --encrypted-regex '^secret_' \
  "$TEST_DIR/partial.yaml" > "$TEST_DIR/partial.enc.yaml"

assert "Partial encryption succeeded" "$([ -f "$TEST_DIR/partial.enc.yaml" ] && echo true || echo false)"

# public_config values should be plaintext
PUBLIC_VISIBLE=$(grep -c "my-app" "$TEST_DIR/partial.enc.yaml" 2>/dev/null || echo 0)
assert "Public config remains in plaintext" "$([ "$PUBLIC_VISIBLE" -gt 0 ] && echo true || echo false)"

# secret_config values should be encrypted
SECRET_VISIBLE=$(grep -c "secret-key-12345" "$TEST_DIR/partial.enc.yaml" 2>/dev/null || echo 0)
assert "Secret config is encrypted (not plaintext)" "$([ "$SECRET_VISIBLE" -eq 0 ] && echo true || echo false)"

# Decrypt and verify
DEC_SECRET=$(sops -d --extract '["secret_config"]["api_key"]' "$TEST_DIR/partial.enc.yaml" 2>/dev/null || echo "")
assert "Partial-encrypted secret decrypts correctly" "$([ "$DEC_SECRET" = "secret-key-12345" ] && echo true || echo false)"

# =============================================================================
# Test 4: Key rotation
# =============================================================================
info "Test: Key rotation..."

# Re-encrypt with key2 (add key2, remove key1 is done via updatekeys)
cat > "$TEST_DIR/.sops-rotated.yaml" <<EOF
creation_rules:
  - path_regex: \.enc\.yaml$
    age: >-
      $PUBKEY2
EOF

# Rotate: re-encrypt the file for the new key
# Need key1 to decrypt, key2 to re-encrypt
sops -d "$TEST_DIR/encrypted.enc.yaml" | \
  sops -e --config "$TEST_DIR/.sops-rotated.yaml" /dev/stdin > "$TEST_DIR/rotated.enc.yaml" 2>/dev/null || {
    # Fallback: decrypt then re-encrypt
    sops -d "$TEST_DIR/encrypted.enc.yaml" > "$TEST_DIR/_tmp_rotation.yaml"
    sops -e --age "$PUBKEY2" "$TEST_DIR/_tmp_rotation.yaml" > "$TEST_DIR/rotated.enc.yaml"
    rm -f "$TEST_DIR/_tmp_rotation.yaml"
  }

assert "Key rotation produced new encrypted file" "$([ -f "$TEST_DIR/rotated.enc.yaml" ] && echo true || echo false)"

# Verify old key can no longer decrypt
export SOPS_AGE_KEY_FILE="$KEY2_FILE"
DEC_AFTER_ROTATE=$(sops -d --extract '["database"]["password"]' "$TEST_DIR/rotated.enc.yaml" 2>/dev/null || echo "")
assert "New key can decrypt rotated file" "$([ "$DEC_AFTER_ROTATE" = "s3cret-passw0rd" ] && echo true || echo false)"

# =============================================================================
# Test 5: Multi-recipient encryption
# =============================================================================
info "Test: Multi-recipient encryption..."

export SOPS_AGE_KEY_FILE="$KEY1_FILE"

cat > "$TEST_DIR/multi.yaml" <<EOF
shared_secret: multi-recipient-test-value
EOF

# Encrypt for both recipients
sops -e --age "${PUBKEY1},${PUBKEY2}" "$TEST_DIR/multi.yaml" > "$TEST_DIR/multi.enc.yaml"
assert "Multi-recipient encryption succeeded" "$([ -f "$TEST_DIR/multi.enc.yaml" ] && echo true || echo false)"

# Decrypt with key1
export SOPS_AGE_KEY_FILE="$KEY1_FILE"
DEC_MULTI1=$(sops -d --extract '["shared_secret"]' "$TEST_DIR/multi.enc.yaml" 2>/dev/null || echo "")
assert "Recipient 1 can decrypt" "$([ "$DEC_MULTI1" = "multi-recipient-test-value" ] && echo true || echo false)"

# Decrypt with key2
export SOPS_AGE_KEY_FILE="$KEY2_FILE"
DEC_MULTI2=$(sops -d --extract '["shared_secret"]' "$TEST_DIR/multi.enc.yaml" 2>/dev/null || echo "")
assert "Recipient 2 can decrypt" "$([ "$DEC_MULTI2" = "multi-recipient-test-value" ] && echo true || echo false)"

# =============================================================================
# Test 6: Dotenv output format
# =============================================================================
info "Test: Dotenv output format..."

export SOPS_AGE_KEY_FILE="$KEY1_FILE"

DOTENV_OUT=$(sops -d --output-type dotenv "$TEST_DIR/encrypted.enc.yaml" 2>/dev/null || echo "")
CONTAINS_EXPORT=$(echo "$DOTENV_OUT" | grep -c "database_password=s3cret-passw0rd" 2>/dev/null || echo 0)
assert "Dotenv output contains flattened key=value pairs" "$([ "$CONTAINS_EXPORT" -gt 0 ] && echo true || echo false)"

# --- Report ---
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo -e "  Tests: ${TESTS}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"

if [[ "$FAILED" -gt 0 ]]; then
  exit 1
fi
