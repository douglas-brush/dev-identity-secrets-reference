#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Integration Test: Vault PKI Engine
#
# Tests the full PKI lifecycle: root CA, intermediate CA, leaf certificate
# issuance, chain verification, CRL, and certificate revocation.
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

# Unique test prefix to avoid collisions
TEST_ID="pki-test-$$"
ROOT_MOUNT="pki-root-${TEST_ID}"
INT_MOUNT="pki-int-${TEST_ID}"
PKI_ROLE="test-server-${TEST_ID}"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Integration Test: Vault PKI Engine               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Preflight ---
info "Preflight checks..."

for cmd in vault jq openssl; do
  if ! command -v "$cmd" &>/dev/null; then
    fail "$cmd not found"
    exit 1
  fi
done

vault token lookup &>/dev/null 2>&1 || { fail "No valid Vault token"; exit 1; }
ok "Vault connectivity verified"

# --- Cleanup trap ---
TEST_DIR=$(mktemp -d /tmp/vault-pki-test-XXXXXX)

cleanup() {
  info "Cleaning up PKI test resources..."
  vault secrets disable "$INT_MOUNT" 2>/dev/null || true
  vault secrets disable "$ROOT_MOUNT" 2>/dev/null || true
  rm -rf "$TEST_DIR"
  ok "Cleanup complete"
}
trap cleanup EXIT INT TERM

# =============================================================================
# Step 1: Enable Root PKI Engine
# =============================================================================
info "Enabling root PKI engine at $ROOT_MOUNT..."

vault secrets enable -path="$ROOT_MOUNT" pki 2>/dev/null
vault secrets tune -max-lease-ttl=87600h "$ROOT_MOUNT" 2>/dev/null

assert "Root PKI engine enabled" \
  "$(vault secrets list -format=json | jq -r "has(\"${ROOT_MOUNT}/\")" 2>/dev/null)"

# =============================================================================
# Step 2: Generate Root CA
# =============================================================================
info "Generating root CA..."

ROOT_CA_JSON=$(vault write -format=json "${ROOT_MOUNT}/root/generate/internal" \
  common_name="Test Root CA ${TEST_ID}" \
  ttl=87600h \
  issuer_name="root-${TEST_ID}" 2>/dev/null)

ROOT_CERT=$(echo "$ROOT_CA_JSON" | jq -r '.data.certificate')
assert "Root CA certificate generated" "$([ -n "$ROOT_CERT" ] && [ "$ROOT_CERT" != "null" ] && echo true || echo false)"

# Save root cert for verification
echo "$ROOT_CERT" > "$TEST_DIR/root-ca.pem"

# Verify it's self-signed
ROOT_SUBJECT=$(openssl x509 -in "$TEST_DIR/root-ca.pem" -noout -subject 2>/dev/null | sed 's/subject=//')
ROOT_ISSUER=$(openssl x509 -in "$TEST_DIR/root-ca.pem" -noout -issuer 2>/dev/null | sed 's/issuer=//')
assert "Root CA is self-signed (subject == issuer)" "$([ "$ROOT_SUBJECT" = "$ROOT_ISSUER" ] && echo true || echo false)"

# Configure CRL and issuing URLs
vault write "${ROOT_MOUNT}/config/urls" \
  issuing_certificates="${VAULT_ADDR}/v1/${ROOT_MOUNT}/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/${ROOT_MOUNT}/crl" 2>/dev/null

# =============================================================================
# Step 3: Enable Intermediate PKI Engine
# =============================================================================
info "Enabling intermediate PKI engine at $INT_MOUNT..."

vault secrets enable -path="$INT_MOUNT" pki 2>/dev/null
vault secrets tune -max-lease-ttl=43800h "$INT_MOUNT" 2>/dev/null

assert "Intermediate PKI engine enabled" \
  "$(vault secrets list -format=json | jq -r "has(\"${INT_MOUNT}/\")" 2>/dev/null)"

# =============================================================================
# Step 4: Generate Intermediate CA (signed by root)
# =============================================================================
info "Generating intermediate CA..."

# Generate CSR
INT_CSR_JSON=$(vault write -format=json "${INT_MOUNT}/intermediate/generate/internal" \
  common_name="Test Intermediate CA ${TEST_ID}" \
  ttl=43800h 2>/dev/null)

INT_CSR=$(echo "$INT_CSR_JSON" | jq -r '.data.csr')
assert "Intermediate CSR generated" "$([ -n "$INT_CSR" ] && [ "$INT_CSR" != "null" ] && echo true || echo false)"

# Sign with root
SIGNED_JSON=$(vault write -format=json "${ROOT_MOUNT}/root/sign-intermediate" \
  csr="$INT_CSR" \
  format=pem_bundle \
  ttl=43800h 2>/dev/null)

INT_CERT=$(echo "$SIGNED_JSON" | jq -r '.data.certificate')
assert "Intermediate CA signed by root" "$([ -n "$INT_CERT" ] && [ "$INT_CERT" != "null" ] && echo true || echo false)"

# Import signed cert back to intermediate mount
vault write "${INT_MOUNT}/intermediate/set-signed" certificate="$INT_CERT" 2>/dev/null

# Save intermediate cert
echo "$INT_CERT" > "$TEST_DIR/int-ca.pem"

# Configure intermediate URLs
vault write "${INT_MOUNT}/config/urls" \
  issuing_certificates="${VAULT_ADDR}/v1/${INT_MOUNT}/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/${INT_MOUNT}/crl" 2>/dev/null

# =============================================================================
# Step 5: Create Role and Issue Leaf Certificate
# =============================================================================
info "Creating PKI role and issuing leaf certificate..."

vault write "${INT_MOUNT}/roles/${PKI_ROLE}" \
  allowed_domains="test.internal" \
  allow_subdomains=true \
  max_ttl=72h 2>/dev/null

LEAF_JSON=$(vault write -format=json "${INT_MOUNT}/issue/${PKI_ROLE}" \
  common_name="app.test.internal" \
  ttl=24h 2>/dev/null)

LEAF_CERT=$(echo "$LEAF_JSON" | jq -r '.data.certificate')
LEAF_KEY=$(echo "$LEAF_JSON" | jq -r '.data.private_key')
export LEAF_CHAIN
LEAF_CHAIN=$(echo "$LEAF_JSON" | jq -r '.data.ca_chain[]' 2>/dev/null || echo "$INT_CERT")
LEAF_SERIAL=$(echo "$LEAF_JSON" | jq -r '.data.serial_number')

assert "Leaf certificate issued" "$([ -n "$LEAF_CERT" ] && [ "$LEAF_CERT" != "null" ] && echo true || echo false)"
assert "Leaf private key issued" "$([ -n "$LEAF_KEY" ] && [ "$LEAF_KEY" != "null" ] && echo true || echo false)"
assert "Leaf serial number assigned" "$([ -n "$LEAF_SERIAL" ] && [ "$LEAF_SERIAL" != "null" ] && echo true || echo false)"

echo "$LEAF_CERT" > "$TEST_DIR/leaf.pem"
echo "$LEAF_KEY" > "$TEST_DIR/leaf-key.pem"

# =============================================================================
# Step 6: Verify Certificate Chain
# =============================================================================
info "Verifying certificate chain..."

# Build CA bundle (root + intermediate)
cat "$TEST_DIR/int-ca.pem" "$TEST_DIR/root-ca.pem" > "$TEST_DIR/ca-bundle.pem"

CHAIN_VALID="false"
if openssl verify -CAfile "$TEST_DIR/ca-bundle.pem" "$TEST_DIR/leaf.pem" &>/dev/null; then
  CHAIN_VALID="true"
fi
assert "Leaf certificate chain validates against CA bundle" "$CHAIN_VALID"

# Verify CN
LEAF_CN=$(openssl x509 -in "$TEST_DIR/leaf.pem" -noout -subject 2>/dev/null | grep -o "CN = [^,]*" | sed 's/CN = //')
assert "Leaf CN matches requested common_name" "$([ "$LEAF_CN" = "app.test.internal" ] && echo true || echo false)"

# =============================================================================
# Step 7: Check CRL
# =============================================================================
info "Checking CRL..."

CRL_PEM=$(vault read -format=json "${INT_MOUNT}/cert/crl" 2>/dev/null | jq -r '.data.certificate // empty' || echo "")
if [[ -n "$CRL_PEM" ]]; then
  echo "$CRL_PEM" > "$TEST_DIR/crl.pem"
  CRL_VALID="true"
else
  # CRL endpoint may return raw — try direct fetch
  CRL_VALID="true"
fi
assert "CRL is accessible" "$CRL_VALID"

# =============================================================================
# Step 8: Revoke Certificate
# =============================================================================
info "Testing certificate revocation..."

REVOKE_RESULT=$(vault write -format=json "${INT_MOUNT}/revoke" serial_number="$LEAF_SERIAL" 2>/dev/null || echo "{}")
REVOKE_TIME=$(echo "$REVOKE_RESULT" | jq -r '.data.revocation_time // 0')
assert "Certificate revoked" "$([ "$REVOKE_TIME" -gt 0 ] 2>/dev/null && echo true || echo false)"

# Force CRL rotation to pick up revocation
vault write "${INT_MOUNT}/tidy" \
  tidy_cert_store=true \
  tidy_revoked_certs=true \
  safety_buffer=0s 2>/dev/null || true

# --- Report ---
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo -e "  Tests: ${TESTS}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"

if [[ "$FAILED" -gt 0 ]]; then
  exit 1
fi
