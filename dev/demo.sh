#!/usr/bin/env bash

#!/usr/bin/env bash
# Interactive demo of all Vault secret engine patterns.
# Usage: ./demo.sh [--auto]
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
export VAULT_ADDR VAULT_TOKEN

AUTO=false
[ "${1:-}" = "--auto" ] && AUTO=true

# ── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# Track leases for cleanup
LEASES=()

# ── Helpers ──────────────────────────────────────────────────────────
header() {
  printf '\n%b══════════════════════════════════════════════════════════════%b\n' "$BLUE" "$RESET"
  printf '%b  %s%b\n' "$BOLD" "$1" "$RESET"
  printf '%b══════════════════════════════════════════════════════════════%b\n\n' "$BLUE" "$RESET"
}

step() {
  printf '%b▸ %s%b\n' "$CYAN" "$1" "$RESET"
}

run() {
  printf '%b  $ %s%b\n' "$DIM" "$*" "$RESET"
  eval "$@" 2>&1 | sed 's/^/    /'
  printf '\n'
}

success() {
  printf '%b  ✓ %s%b\n\n' "$GREEN" "$1" "$RESET"
}

warn() {
  printf '%b  ! %s%b\n' "$YELLOW" "$1" "$RESET"
}

pause() {
  if [ "$AUTO" = false ]; then
    printf '%b  Press Enter to continue...%b' "$DIM" "$RESET"
    read -r
  fi
}

cleanup() {
  header "Cleanup"
  step "Revoking leases created during demo..."
  for lease in "${LEASES[@]}"; do
    vault lease revoke "$lease" 2>/dev/null && \
      printf '    Revoked: %s\n' "$lease" || \
      printf '    Already expired: %s\n' "$lease"
  done
  success "Cleanup complete"
}

trap cleanup EXIT

# ── Preflight ────────────────────────────────────────────────────────
header "Developer Identity & Secrets Management — Live Demo"

step "Checking prerequisites..."
for cmd in vault jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf '%b  ✗ %s not found. Install it and retry.%b\n' "$RED" "$cmd" "$RESET"
    exit 1
  fi
done
success "All prerequisites available"

step "Checking Vault connectivity..."
if ! vault status >/dev/null 2>&1; then
  warn "Vault is not running. Starting the stack..."
  if [ -f "$(dirname "$0")/Makefile" ]; then
    make -C "$(dirname "$0")" up setup
  else
    printf '%b  ✗ Cannot start Vault. Run: make up && make setup%b\n' "$RED" "$RESET"
    exit 1
  fi
fi
success "Vault is ready at ${VAULT_ADDR}"
pause

# ═══════════════════════════════════════════════════════════════════
# 1. KV Secrets Engine
# ═══════════════════════════════════════════════════════════════════
header "1. KV Secrets Engine — Static Secret Storage"

step "Write a secret to KV v2"
run vault kv put kv/dev/apps/demo-app/demo \
  username=demo-user \
  password=s3cret-demo-value \
  environment=development

step "Read the secret back"
run vault kv get -format=json kv/dev/apps/demo-app/demo

step "Read a specific field"
run vault kv get -field=password kv/dev/apps/demo-app/demo

step "Show version metadata"
run vault kv metadata get kv/dev/apps/demo-app/demo

success "KV secrets engine working"
pause

# ═══════════════════════════════════════════════════════════════════
# 2. Dynamic Database Credentials
# ═══════════════════════════════════════════════════════════════════
header "2. Database Engine — Dynamic Credentials"

step "Generate dynamic PostgreSQL credentials (dev-demo-app role)"
DB_CREDS=$(vault read -format=json database/creds/dev-demo-app)
DB_USER=$(echo "$DB_CREDS" | jq -r '.data.username')
DB_PASS=$(echo "$DB_CREDS" | jq -r '.data.password')
DB_LEASE=$(echo "$DB_CREDS" | jq -r '.lease_id')
LEASES+=("$DB_LEASE")

printf '    %bUsername:%b %s\n' "$BOLD" "$RESET" "$DB_USER"
printf '    %bPassword:%b %s\n' "$BOLD" "$RESET" "$DB_PASS"
printf '    %bLease ID:%b %s\n' "$BOLD" "$RESET" "$DB_LEASE"
printf '    %bLease TTL:%b %s\n\n' "$BOLD" "$RESET" "$(echo "$DB_CREDS" | jq -r '.lease_duration')s"

step "Test the dynamic credentials against PostgreSQL"
run docker exec dev-postgres psql -U "$DB_USER" -d demo -c "SELECT current_user, now();"

step "Generate read-only credentials"
RO_CREDS=$(vault read -format=json database/creds/dev-readonly)
RO_LEASE=$(echo "$RO_CREDS" | jq -r '.lease_id')
LEASES+=("$RO_LEASE")
printf '    %bRead-only user:%b %s\n\n' "$BOLD" "$RESET" "$(echo "$RO_CREDS" | jq -r '.data.username')"

step "Look up lease details"
run vault lease lookup "$DB_LEASE"

success "Dynamic database credentials working"
pause

# ═══════════════════════════════════════════════════════════════════
# 3. PKI — Certificate Issuance
# ═══════════════════════════════════════════════════════════════════
header "3. PKI Engine — X.509 Certificate Issuance"

step "Issue a certificate for api.dev.local"
CERT_DATA=$(vault write -format=json pki_int/issue/dev-services \
  common_name="api.dev.local" \
  alt_names="api.svc.local,localhost" \
  ip_sans="127.0.0.1" \
  ttl="24h")

printf '    %bSerial:%b  %s\n' "$BOLD" "$RESET" "$(echo "$CERT_DATA" | jq -r '.data.serial_number')"
printf '    %bExpiry:%b  %s\n' "$BOLD" "$RESET" "$(echo "$CERT_DATA" | jq -r '.data.expiration | todate')"
printf '    %bCA Chain:%b %s certificates\n\n' "$BOLD" "$RESET" "$(echo "$CERT_DATA" | jq -r '.data.ca_chain | length')"

step "Verify the certificate (first 5 lines)"
echo "$CERT_DATA" | jq -r '.data.certificate' | openssl x509 -noout -text 2>/dev/null | head -15 | sed 's/^/    /'
printf '\n'

step "Show the CA chain"
run vault read -field=certificate pki_int/cert/ca | openssl x509 -noout -subject -issuer

success "PKI certificate issuance working"
pause

# ═══════════════════════════════════════════════════════════════════
# 4. SSH Signed Keys
# ═══════════════════════════════════════════════════════════════════
header "4. SSH Engine — Certificate Authority"

step "Get the SSH CA public key"
run vault read -field=public_key ssh/config/ca

step "Sign a temporary SSH public key"
# Generate a temporary key pair for demo
ssh-keygen -t ed25519 -f /tmp/demo_ssh_key -N "" -q 2>/dev/null || true
SIGNED=$(vault write -format=json ssh/sign/dev-admin \
  public_key=@/tmp/demo_ssh_key.pub \
  valid_principals="dev,ubuntu" \
  ttl="30m")

printf '    %bSigned key serial:%b %s\n' "$BOLD" "$RESET" "$(echo "$SIGNED" | jq -r '.data.serial_number')"
printf '    %bValid principals:%b dev, ubuntu\n' "$BOLD" "$RESET"
printf '    %bTTL:%b 30 minutes\n\n' "$BOLD" "$RESET"

step "Inspect the signed certificate"
echo "$SIGNED" | jq -r '.data.signed_key' > /tmp/demo_ssh_key-cert.pub
ssh-keygen -L -f /tmp/demo_ssh_key-cert.pub 2>/dev/null | head -15 | sed 's/^/    /'
printf '\n'

# Cleanup temp keys
rm -f /tmp/demo_ssh_key /tmp/demo_ssh_key.pub /tmp/demo_ssh_key-cert.pub

success "SSH CA signing working"
pause

# ═══════════════════════════════════════════════════════════════════
# 5. Transit — Encryption as a Service
# ═══════════════════════════════════════════════════════════════════
header "5. Transit Engine — Encryption as a Service"

PLAINTEXT="Sensitive data: SSN 123-45-6789"
B64_PLAIN=$(echo -n "$PLAINTEXT" | base64)

step "Encrypt data using the demo-app transit key"
ENCRYPTED=$(vault write -format=json transit/encrypt/demo-app \
  plaintext="$B64_PLAIN")
CIPHERTEXT=$(echo "$ENCRYPTED" | jq -r '.data.ciphertext')
printf '    %bPlaintext:%b  %s\n' "$BOLD" "$RESET" "$PLAINTEXT"
printf '    %bCiphertext:%b %s\n\n' "$BOLD" "$RESET" "$CIPHERTEXT"

step "Decrypt the ciphertext"
DECRYPTED=$(vault write -format=json transit/decrypt/demo-app \
  ciphertext="$CIPHERTEXT")
RESULT=$(echo "$DECRYPTED" | jq -r '.data.plaintext' | base64 -d 2>/dev/null || echo "$DECRYPTED" | jq -r '.data.plaintext' | base64 --decode)
printf '    %bDecrypted:%b  %s\n\n' "$BOLD" "$RESET" "$RESULT"

step "Key rotation — rotate the encryption key"
run vault write -f transit/keys/demo-app/rotate
run vault read -format=json transit/keys/demo-app | jq '{latest_version: .data.latest_version, min_decryption_version: .data.min_decryption_version}'

step "Re-encrypt with the new key version (rewrap)"
REWRAPPED=$(vault write -format=json transit/rewrap/demo-app \
  ciphertext="$CIPHERTEXT")
NEW_CIPHERTEXT=$(echo "$REWRAPPED" | jq -r '.data.ciphertext')
printf '    %bOld ciphertext:%b %s\n' "$BOLD" "$RESET" "$CIPHERTEXT"
printf '    %bNew ciphertext:%b %s\n\n' "$BOLD" "$RESET" "$NEW_CIPHERTEXT"

step "Verify decryption still works after rewrap"
FINAL=$(vault write -format=json transit/decrypt/demo-app \
  ciphertext="$NEW_CIPHERTEXT")
printf '    %bDecrypted:%b %s\n\n' "$BOLD" "$RESET" "$(echo "$FINAL" | jq -r '.data.plaintext' | base64 -d 2>/dev/null || echo "$FINAL" | jq -r '.data.plaintext' | base64 --decode)"

success "Transit encryption/decryption working"
pause

# ═══════════════════════════════════════════════════════════════════
# 6. AppRole Authentication
# ═══════════════════════════════════════════════════════════════════
header "6. AppRole Authentication — Machine Identity"

step "Fetch the demo-app Role ID (stable identifier)"
ROLE_ID=$(vault read -format=json auth/approle/role/demo-app/role-id | jq -r '.data.role_id')
printf '    %bRole ID:%b %s\n\n' "$BOLD" "$RESET" "$ROLE_ID"

step "Generate a Secret ID (one-time credential)"
SECRET_ID=$(vault write -format=json -f auth/approle/role/demo-app/secret-id | jq -r '.data.secret_id')
printf '    %bSecret ID:%b %s\n\n' "$BOLD" "$RESET" "$SECRET_ID"

step "Authenticate with AppRole to get a client token"
LOGIN=$(vault write -format=json auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID")
APP_TOKEN=$(echo "$LOGIN" | jq -r '.auth.client_token')
APP_POLICIES=$(echo "$LOGIN" | jq -r '.auth.policies | join(", ")')
printf '    %bClient Token:%b %s\n' "$BOLD" "$RESET" "$APP_TOKEN"
printf '    %bPolicies:%b     %s\n' "$BOLD" "$RESET" "$APP_POLICIES"
printf '    %bTTL:%b           %ss\n\n' "$BOLD" "$RESET" "$(echo "$LOGIN" | jq -r '.auth.lease_duration')"

step "Use the AppRole token to read a secret (scoped access)"
run VAULT_TOKEN="$APP_TOKEN" vault kv get kv/dev/apps/demo-app/config

step "Verify the AppRole token cannot access admin paths"
printf '    %bAttempting to read sys/mounts (should fail):%b\n' "$DIM" "$RESET"
VAULT_TOKEN="$APP_TOKEN" vault read sys/mounts 2>&1 | sed 's/^/    /' || true
printf '\n'

success "AppRole authentication working"
pause

# ═══════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════
header "Demo Complete"

printf '  %bPatterns demonstrated:%b\n' "$BOLD" "$RESET"
printf '    1. KV v2         — Static secret storage with versioning\n'
printf '    2. Database       — Dynamic credential generation with TTL\n'
printf '    3. PKI            — X.509 certificate issuance from internal CA\n'
printf '    4. SSH            — Certificate-based SSH authentication\n'
printf '    5. Transit        — Encryption-as-a-service with key rotation\n'
printf '    6. AppRole        — Machine identity authentication\n'
printf '\n'
printf '  %bVault UI:%b     %s/ui\n' "$BOLD" "$RESET" "$VAULT_ADDR"
printf '  %bRoot Token:%b   %s\n' "$BOLD" "$RESET" "$VAULT_TOKEN"
printf '\n'
printf '  See the platform/vault/policies/ directory for all policy definitions.\n'
printf '  See lib/python/ for the Python SDK that wraps these patterns.\n'
printf '\n'
