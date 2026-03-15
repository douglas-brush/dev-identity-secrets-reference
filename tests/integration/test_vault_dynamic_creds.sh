#!/usr/bin/env bash
set -euo pipefail

# Integration test: Vault dynamic database credentials
# Requires a running Vault instance with database engine configured.

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
: "${DB_ROLE:=dev-demo-app}"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Integration Test: Dynamic Database Credentials  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Preflight ---
info "Preflight checks..."

if ! command -v vault &>/dev/null; then
  fail "vault CLI not found"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  fail "jq not found"
  exit 1
fi

if ! vault token lookup &>/dev/null 2>&1; then
  fail "No valid Vault token"
  exit 1
fi
ok "Vault connectivity verified"

# --- Test: Database engine is mounted ---
info "Checking database engine..."
DB_MOUNTED=$(vault secrets list -format=json 2>/dev/null | jq -r 'has("database/")' 2>/dev/null || echo "false")
assert "Database secret engine is mounted" "$DB_MOUNTED"

if [[ "$DB_MOUNTED" != "true" ]]; then
  fail "Cannot continue without database engine"
  exit 1
fi

# --- Test: Role exists ---
info "Checking role: $DB_ROLE..."
ROLE_EXISTS="false"
if vault read "database/roles/$DB_ROLE" &>/dev/null 2>&1; then
  ROLE_EXISTS="true"
fi
assert "Database role '$DB_ROLE' exists" "$ROLE_EXISTS"

if [[ "$ROLE_EXISTS" != "true" ]]; then
  fail "Cannot continue without database role"
  exit 1
fi

# --- Test: Generate dynamic credentials ---
info "Generating dynamic credentials..."
CREDS_JSON=$(vault read -format=json "database/creds/$DB_ROLE" 2>/dev/null || echo "{}")

USERNAME=$(echo "$CREDS_JSON" | jq -r '.data.username // empty')
PASSWORD=$(echo "$CREDS_JSON" | jq -r '.data.password // empty')
LEASE_ID=$(echo "$CREDS_JSON" | jq -r '.lease_id // empty')
LEASE_TTL=$(echo "$CREDS_JSON" | jq -r '.lease_duration // 0')

assert "Dynamic username generated" "$([ -n "$USERNAME" ] && echo true || echo false)"
assert "Dynamic password generated" "$([ -n "$PASSWORD" ] && echo true || echo false)"
assert "Lease ID assigned" "$([ -n "$LEASE_ID" ] && echo true || echo false)"
assert "Lease TTL is positive" "$([ "$LEASE_TTL" -gt 0 ] 2>/dev/null && echo true || echo false)"

if [[ -n "$USERNAME" ]]; then
  info "  Username: $USERNAME"
  info "  Lease TTL: ${LEASE_TTL}s"
  info "  Lease ID: $LEASE_ID"
fi

# --- Test: Credentials are unique ---
info "Generating second set of credentials..."
CREDS2_JSON=$(vault read -format=json "database/creds/$DB_ROLE" 2>/dev/null || echo "{}")
USERNAME2=$(echo "$CREDS2_JSON" | jq -r '.data.username // empty')
LEASE_ID2=$(echo "$CREDS2_JSON" | jq -r '.lease_id // empty')

assert "Second username is different (unique)" "$([ "$USERNAME" != "$USERNAME2" ] && echo true || echo false)"
assert "Second lease ID is different" "$([ "$LEASE_ID" != "$LEASE_ID2" ] && echo true || echo false)"

# --- Test: Lease lookup ---
info "Verifying lease..."
if [[ -n "$LEASE_ID" ]]; then
  LEASE_VALID="false"
  if vault lease lookup "$LEASE_ID" &>/dev/null 2>&1; then
    LEASE_VALID="true"
  fi
  assert "Lease is valid and lookupable" "$LEASE_VALID"
fi

# --- Test: Lease renewal ---
info "Testing lease renewal..."
if [[ -n "$LEASE_ID" ]]; then
  RENEW_OK="false"
  if vault lease renew "$LEASE_ID" &>/dev/null 2>&1; then
    RENEW_OK="true"
  fi
  assert "Lease can be renewed" "$RENEW_OK"
fi

# --- Test: Lease revocation ---
info "Testing lease revocation..."
if [[ -n "$LEASE_ID" ]]; then
  REVOKE_OK="false"
  if vault lease revoke "$LEASE_ID" &>/dev/null 2>&1; then
    REVOKE_OK="true"
  fi
  assert "Lease can be revoked" "$REVOKE_OK"
fi

# Revoke second lease too
if [[ -n "$LEASE_ID2" ]]; then
  vault lease revoke "$LEASE_ID2" &>/dev/null 2>&1 || true
fi

# --- Report ---
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"
echo -e "  Tests: ${TESTS}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════${NC}"

if [[ "$FAILED" -gt 0 ]]; then
  exit 1
fi
