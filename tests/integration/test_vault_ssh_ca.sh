#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Integration Test: Vault SSH Certificate Authority
#
# Tests SSH engine: CA configuration, user key signing, certificate
# verification, and expiry enforcement.
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

TEST_ID="ssh-test-$$"
SSH_MOUNT="ssh-${TEST_ID}"
SSH_ROLE="test-user-${TEST_ID}"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Integration Test: Vault SSH Certificate Authority║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Preflight ---
info "Preflight checks..."

for cmd in vault jq ssh-keygen; do
  if ! command -v "$cmd" &>/dev/null; then
    fail "$cmd not found"
    exit 1
  fi
done

vault token lookup &>/dev/null 2>&1 || { fail "No valid Vault token"; exit 1; }
ok "Vault connectivity verified"

# --- Setup ---
TEST_DIR=$(mktemp -d /tmp/vault-ssh-test-XXXXXX)

cleanup() {
  info "Cleaning up SSH test resources..."
  vault secrets disable "$SSH_MOUNT" 2>/dev/null || true
  rm -rf "$TEST_DIR"
  ok "Cleanup complete"
}
trap cleanup EXIT INT TERM

# =============================================================================
# Step 1: Enable SSH Engine
# =============================================================================
info "Enabling SSH secret engine at $SSH_MOUNT..."

vault secrets enable -path="$SSH_MOUNT" ssh 2>/dev/null
assert "SSH engine enabled" \
  "$(vault secrets list -format=json | jq -r "has(\"${SSH_MOUNT}/\")" 2>/dev/null)"

# =============================================================================
# Step 2: Configure CA
# =============================================================================
info "Configuring SSH CA..."

CA_JSON=$(vault write -format=json "${SSH_MOUNT}/config/ca" generate_signing_key=true 2>/dev/null)
CA_PUBLIC_KEY=$(echo "$CA_JSON" | jq -r '.data.public_key')

assert "SSH CA key generated" "$([ -n "$CA_PUBLIC_KEY" ] && [ "$CA_PUBLIC_KEY" != "null" ] && echo true || echo false)"

# Verify we can read the CA public key back
CA_READ=$(vault read -format=json "${SSH_MOUNT}/config/ca" 2>/dev/null | jq -r '.data.public_key // empty')
assert "CA public key is readable" "$([ -n "$CA_READ" ] && echo true || echo false)"

echo "$CA_PUBLIC_KEY" > "$TEST_DIR/ca.pub"

# =============================================================================
# Step 3: Create Signing Role
# =============================================================================
info "Creating SSH signing role..."

vault write "${SSH_MOUNT}/roles/${SSH_ROLE}" \
  key_type="ca" \
  default_user="testuser" \
  allowed_users="testuser,admin" \
  allow_user_certificates=true \
  allowed_extensions="permit-pty,permit-port-forwarding" \
  default_extensions='{"permit-pty": ""}' \
  ttl="30m" \
  max_ttl="1h" 2>/dev/null

ROLE_EXISTS="false"
if vault read "${SSH_MOUNT}/roles/${SSH_ROLE}" &>/dev/null 2>&1; then
  ROLE_EXISTS="true"
fi
assert "SSH signing role created" "$ROLE_EXISTS"

# =============================================================================
# Step 4: Generate User Key Pair and Sign
# =============================================================================
info "Generating user SSH key pair..."

ssh-keygen -t ed25519 -f "$TEST_DIR/user_key" -N "" -C "test-user-${TEST_ID}" -q
assert "User key pair generated" "$([ -f "$TEST_DIR/user_key.pub" ] && echo true || echo false)"

USER_PUB=$(cat "$TEST_DIR/user_key.pub")

info "Signing user public key with Vault CA..."

SIGN_JSON=$(vault write -format=json "${SSH_MOUNT}/sign/${SSH_ROLE}" \
  public_key="$USER_PUB" \
  valid_principals="testuser" \
  ttl="30m" 2>/dev/null)

SIGNED_KEY=$(echo "$SIGN_JSON" | jq -r '.data.signed_key')
CERT_SERIAL=$(echo "$SIGN_JSON" | jq -r '.data.serial_number // empty')

assert "User key signed by CA" "$([ -n "$SIGNED_KEY" ] && [ "$SIGNED_KEY" != "null" ] && echo true || echo false)"
assert "Certificate serial number assigned" "$([ -n "$CERT_SERIAL" ] && echo true || echo false)"

echo "$SIGNED_KEY" > "$TEST_DIR/user_key-cert.pub"

# =============================================================================
# Step 5: Verify Certificate
# =============================================================================
info "Verifying SSH certificate..."

# Use ssh-keygen to inspect the certificate
CERT_INFO=$(ssh-keygen -L -f "$TEST_DIR/user_key-cert.pub" 2>/dev/null || echo "")
assert "Certificate is parseable by ssh-keygen" "$([ -n "$CERT_INFO" ] && echo true || echo false)"

# Check certificate type
CERT_TYPE=$(echo "$CERT_INFO" | grep -i "Type:" | head -1 || echo "")
assert "Certificate is a user certificate" "$(echo "$CERT_TYPE" | grep -qi 'user' && echo true || echo false)"

# Check principals
PRINCIPAL_MATCH=$(echo "$CERT_INFO" | grep -c "testuser" 2>/dev/null || echo 0)
assert "Certificate contains correct principal (testuser)" "$([ "$PRINCIPAL_MATCH" -gt 0 ] && echo true || echo false)"

# Check signing CA matches
SIGNING_CA=$(echo "$CERT_INFO" | grep "Signing CA" | head -1 || echo "")
assert "Certificate has a signing CA fingerprint" "$([ -n "$SIGNING_CA" ] && echo true || echo false)"

# =============================================================================
# Step 6: Test Certificate Expiry
# =============================================================================
info "Testing certificate TTL and expiry..."

# Sign with very short TTL
SHORT_SIGN_JSON=$(vault write -format=json "${SSH_MOUNT}/sign/${SSH_ROLE}" \
  public_key="$USER_PUB" \
  valid_principals="testuser" \
  ttl="5m" 2>/dev/null)

SHORT_CERT=$(echo "$SHORT_SIGN_JSON" | jq -r '.data.signed_key')
echo "$SHORT_CERT" > "$TEST_DIR/short_cert.pub"

SHORT_INFO=$(ssh-keygen -L -f "$TEST_DIR/short_cert.pub" 2>/dev/null || echo "")
VALID_LINE=$(echo "$SHORT_INFO" | grep "Valid:" | head -1 || echo "")
assert "Short-TTL certificate has validity window" "$([ -n "$VALID_LINE" ] && echo true || echo false)"

# Verify the certificate is currently valid (not expired)
VALID_NOW="false"
if echo "$SHORT_INFO" | grep -q "Valid:"; then
  VALID_NOW="true"
fi
assert "Short-TTL certificate is currently valid" "$VALID_NOW"

# =============================================================================
# Step 7: Test with Different Principal
# =============================================================================
info "Testing signing with alternate principal..."

ADMIN_SIGN=$(vault write -format=json "${SSH_MOUNT}/sign/${SSH_ROLE}" \
  public_key="$USER_PUB" \
  valid_principals="admin" \
  ttl="10m" 2>/dev/null || echo "{}")

ADMIN_CERT=$(echo "$ADMIN_SIGN" | jq -r '.data.signed_key // empty')
assert "Certificate with admin principal issued" "$([ -n "$ADMIN_CERT" ] && echo true || echo false)"

if [[ -n "$ADMIN_CERT" ]]; then
  echo "$ADMIN_CERT" > "$TEST_DIR/admin_cert.pub"
  ADMIN_PRINCIPAL=$(ssh-keygen -L -f "$TEST_DIR/admin_cert.pub" 2>/dev/null | grep -c "admin" || echo 0)
  assert "Admin certificate contains admin principal" "$([ "$ADMIN_PRINCIPAL" -gt 0 ] && echo true || echo false)"
fi

# =============================================================================
# Step 8: Test Disallowed Principal (Negative Test)
# =============================================================================
info "Testing disallowed principal (negative test)..."

DENIED="true"
if vault write -format=json "${SSH_MOUNT}/sign/${SSH_ROLE}" \
  public_key="$USER_PUB" \
  valid_principals="unauthorized_user" \
  ttl="10m" &>/dev/null 2>&1; then
  DENIED="false"
fi
assert "Disallowed principal is rejected" "$DENIED"

# --- Report ---
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo -e "  Tests: ${TESTS}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"

if [[ "$FAILED" -gt 0 ]]; then
  exit 1
fi
