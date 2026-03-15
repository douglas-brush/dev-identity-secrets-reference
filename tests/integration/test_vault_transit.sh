#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Integration Test: Vault Transit Secrets Engine
#
# Tests transit key creation, encryption, decryption, key rotation, and
# rewrap operations.
#
# Requires a running Vault instance with a valid token.
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

: "${VAULT_ADDR:?VAULT_ADDR must be set}"

TEST_ID="transit-test-$$"
TRANSIT_MOUNT="transit-${TEST_ID}"
KEY_NAME="test-key-${TEST_ID}"
PLAINTEXT="The quick brown fox jumps over the lazy dog"
PLAINTEXT_B64=$(echo -n "$PLAINTEXT" | base64)

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Integration Test: Vault Transit Engine           ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Preflight ---
info "Preflight checks..."

for cmd in vault jq base64; do
  if ! command -v "$cmd" &>/dev/null; then
    fail "$cmd not found"
    exit 1
  fi
done

vault token lookup &>/dev/null 2>&1 || { fail "No valid Vault token"; exit 1; }
ok "Vault connectivity verified"

# --- Setup ---
cleanup() {
  info "Cleaning up transit test resources..."
  vault secrets disable "$TRANSIT_MOUNT" 2>/dev/null || true
  ok "Cleanup complete"
}
trap cleanup EXIT INT TERM

# =============================================================================
# Step 1: Enable Transit Engine
# =============================================================================
info "Enabling transit engine at $TRANSIT_MOUNT..."

vault secrets enable -path="$TRANSIT_MOUNT" transit 2>/dev/null
assert "Transit engine enabled" \
  "$(vault secrets list -format=json | jq -r "has(\"${TRANSIT_MOUNT}/\")" 2>/dev/null)"

# =============================================================================
# Step 2: Create Encryption Key
# =============================================================================
info "Creating transit encryption key..."

vault write -f "${TRANSIT_MOUNT}/keys/${KEY_NAME}" 2>/dev/null

KEY_INFO=$(vault read -format=json "${TRANSIT_MOUNT}/keys/${KEY_NAME}" 2>/dev/null || echo "{}")
KEY_TYPE=$(echo "$KEY_INFO" | jq -r '.data.type // empty')
KEY_VERSION=$(echo "$KEY_INFO" | jq -r '.data.latest_version // 0')
MIN_DECRYPT=$(echo "$KEY_INFO" | jq -r '.data.min_decryption_version // 0')

assert "Transit key created" "$([ -n "$KEY_TYPE" ] && echo true || echo false)"
assert "Key type is aes256-gcm96" "$([ "$KEY_TYPE" = "aes256-gcm96" ] && echo true || echo false)"
assert "Key version is 1" "$([ "$KEY_VERSION" = "1" ] && echo true || echo false)"

# =============================================================================
# Step 3: Encrypt Data
# =============================================================================
info "Encrypting data..."

ENCRYPT_JSON=$(vault write -format=json "${TRANSIT_MOUNT}/encrypt/${KEY_NAME}" \
  plaintext="$PLAINTEXT_B64" 2>/dev/null)

CIPHERTEXT=$(echo "$ENCRYPT_JSON" | jq -r '.data.ciphertext // empty')
assert "Data encrypted successfully" "$([ -n "$CIPHERTEXT" ] && echo true || echo false)"

# Verify ciphertext format: vault:v<version>:<base64>
CIPHER_FORMAT=$(echo "$CIPHERTEXT" | grep -cE '^vault:v[0-9]+:' 2>/dev/null || echo 0)
assert "Ciphertext has correct format (vault:v1:...)" "$([ "$CIPHER_FORMAT" -gt 0 ] && echo true || echo false)"

# Verify ciphertext is different from plaintext
assert "Ciphertext differs from plaintext" "$([ "$CIPHERTEXT" != "$PLAINTEXT_B64" ] && echo true || echo false)"

# =============================================================================
# Step 4: Decrypt Data
# =============================================================================
info "Decrypting data..."

DECRYPT_JSON=$(vault write -format=json "${TRANSIT_MOUNT}/decrypt/${KEY_NAME}" \
  ciphertext="$CIPHERTEXT" 2>/dev/null)

DECRYPTED_B64=$(echo "$DECRYPT_JSON" | jq -r '.data.plaintext // empty')
DECRYPTED=$(echo "$DECRYPTED_B64" | base64 -d 2>/dev/null || echo "$DECRYPTED_B64" | base64 -D 2>/dev/null)

assert "Data decrypted successfully" "$([ -n "$DECRYPTED" ] && echo true || echo false)"
assert "Decrypted data matches original" "$([ "$DECRYPTED" = "$PLAINTEXT" ] && echo true || echo false)"

# =============================================================================
# Step 5: Encrypt Same Data Again (Different Ciphertext)
# =============================================================================
info "Testing non-deterministic encryption..."

ENCRYPT2_JSON=$(vault write -format=json "${TRANSIT_MOUNT}/encrypt/${KEY_NAME}" \
  plaintext="$PLAINTEXT_B64" 2>/dev/null)

CIPHERTEXT2=$(echo "$ENCRYPT2_JSON" | jq -r '.data.ciphertext // empty')
assert "Second encryption produces different ciphertext" \
  "$([ "$CIPHERTEXT" != "$CIPHERTEXT2" ] && echo true || echo false)"

# Both should decrypt to the same value
DECRYPT2_B64=$(vault write -format=json "${TRANSIT_MOUNT}/decrypt/${KEY_NAME}" \
  ciphertext="$CIPHERTEXT2" 2>/dev/null | jq -r '.data.plaintext // empty')
DECRYPTED2=$(echo "$DECRYPT2_B64" | base64 -d 2>/dev/null || echo "$DECRYPT2_B64" | base64 -D 2>/dev/null)
assert "Both ciphertexts decrypt to same plaintext" "$([ "$DECRYPTED2" = "$PLAINTEXT" ] && echo true || echo false)"

# =============================================================================
# Step 6: Key Rotation
# =============================================================================
info "Rotating transit key..."

vault write -f "${TRANSIT_MOUNT}/keys/${KEY_NAME}/rotate" 2>/dev/null

KEY_INFO_POST=$(vault read -format=json "${TRANSIT_MOUNT}/keys/${KEY_NAME}" 2>/dev/null || echo "{}")
NEW_VERSION=$(echo "$KEY_INFO_POST" | jq -r '.data.latest_version // 0')

assert "Key rotated to version 2" "$([ "$NEW_VERSION" = "2" ] && echo true || echo false)"

# Old ciphertext should still decrypt (version 1 key retained)
DECRYPT_OLD_B64=$(vault write -format=json "${TRANSIT_MOUNT}/decrypt/${KEY_NAME}" \
  ciphertext="$CIPHERTEXT" 2>/dev/null | jq -r '.data.plaintext // empty')
DECRYPT_OLD=$(echo "$DECRYPT_OLD_B64" | base64 -d 2>/dev/null || echo "$DECRYPT_OLD_B64" | base64 -D 2>/dev/null)
assert "Old ciphertext still decrypts after rotation" "$([ "$DECRYPT_OLD" = "$PLAINTEXT" ] && echo true || echo false)"

# New encryption uses version 2
ENCRYPT_V2_JSON=$(vault write -format=json "${TRANSIT_MOUNT}/encrypt/${KEY_NAME}" \
  plaintext="$PLAINTEXT_B64" 2>/dev/null)
CIPHERTEXT_V2=$(echo "$ENCRYPT_V2_JSON" | jq -r '.data.ciphertext // empty')
V2_PREFIX=$(echo "$CIPHERTEXT_V2" | grep -cE '^vault:v2:' 2>/dev/null || echo 0)
assert "New encryption uses key version 2" "$([ "$V2_PREFIX" -gt 0 ] && echo true || echo false)"

# =============================================================================
# Step 7: Rewrap (Re-encrypt with Latest Key Version)
# =============================================================================
info "Testing rewrap (re-encrypt old ciphertext with new key)..."

REWRAP_JSON=$(vault write -format=json "${TRANSIT_MOUNT}/rewrap/${KEY_NAME}" \
  ciphertext="$CIPHERTEXT" 2>/dev/null)

REWRAPPED=$(echo "$REWRAP_JSON" | jq -r '.data.ciphertext // empty')
assert "Rewrap succeeded" "$([ -n "$REWRAPPED" ] && echo true || echo false)"

# Rewrapped ciphertext should use version 2
REWRAP_V2=$(echo "$REWRAPPED" | grep -cE '^vault:v2:' 2>/dev/null || echo 0)
assert "Rewrapped ciphertext uses latest key version" "$([ "$REWRAP_V2" -gt 0 ] && echo true || echo false)"

# Rewrapped should still decrypt to original
DECRYPT_REWRAP_B64=$(vault write -format=json "${TRANSIT_MOUNT}/decrypt/${KEY_NAME}" \
  ciphertext="$REWRAPPED" 2>/dev/null | jq -r '.data.plaintext // empty')
DECRYPT_REWRAP=$(echo "$DECRYPT_REWRAP_B64" | base64 -d 2>/dev/null || echo "$DECRYPT_REWRAP_B64" | base64 -D 2>/dev/null)
assert "Rewrapped ciphertext decrypts to original plaintext" "$([ "$DECRYPT_REWRAP" = "$PLAINTEXT" ] && echo true || echo false)"

# =============================================================================
# Step 8: Enforce Minimum Decryption Version
# =============================================================================
info "Testing minimum decryption version enforcement..."

# Set min_decryption_version to 2 — v1 ciphertexts should fail
vault write "${TRANSIT_MOUNT}/keys/${KEY_NAME}/config" \
  min_decryption_version=2 2>/dev/null

# Old v1 ciphertext should now fail
V1_DECRYPT_FAIL="true"
if vault write -format=json "${TRANSIT_MOUNT}/decrypt/${KEY_NAME}" \
  ciphertext="$CIPHERTEXT" &>/dev/null 2>&1; then
  V1_DECRYPT_FAIL="false"
fi
assert "V1 ciphertext rejected after min_decryption_version=2" "$V1_DECRYPT_FAIL"

# Rewrapped (v2) ciphertext should still work
DECRYPT_V2_OK_B64=$(vault write -format=json "${TRANSIT_MOUNT}/decrypt/${KEY_NAME}" \
  ciphertext="$REWRAPPED" 2>/dev/null | jq -r '.data.plaintext // empty')
DECRYPT_V2_OK=$(echo "$DECRYPT_V2_OK_B64" | base64 -d 2>/dev/null || echo "$DECRYPT_V2_OK_B64" | base64 -D 2>/dev/null)
assert "V2 ciphertext still decrypts with min_decryption_version=2" \
  "$([ "$DECRYPT_V2_OK" = "$PLAINTEXT" ] && echo true || echo false)"

# --- Report ---
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo -e "  Tests: ${TESTS}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"

if [[ "$FAILED" -gt 0 ]]; then
  exit 1
fi
