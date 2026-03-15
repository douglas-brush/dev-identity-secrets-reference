#!/usr/bin/env bash

#!/usr/bin/env bash
# setup-complete.sh — Complete Vault setup: engines, auth, policies, PKI, SSH, Transit, DB
# Run against a freshly initialized and unsealed Vault cluster.
set -euo pipefail

###############################################################################
# Configuration
###############################################################################
: "${VAULT_ADDR:=https://vault.example.internal:8200}"
: "${OIDC_DISCOVERY_URL:=https://login.microsoftonline.com/TENANT_ID/v2.0}"
: "${OIDC_CLIENT_ID:=REPLACE_CLIENT_ID}"
: "${OIDC_CLIENT_SECRET:=REPLACE_CLIENT_SECRET}"
: "${GITHUB_ORG:=my-org}"
: "${K8S_HOST:=https://kubernetes.default.svc}"
: "${K8S_CA_CERT:=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt}"
: "${K8S_TOKEN_REVIEWER_JWT:=}"
: "${DB_HOST:=postgres.internal:5432}"
: "${DB_ADMIN_USER:=vault_admin}"
: "${DB_ADMIN_PASS:=REPLACE_DB_PASSWORD}"
: "${PKI_DOMAIN:=example.internal}"
: "${PKI_ROOT_TTL:=87600h}"       # 10 years
: "${PKI_INT_TTL:=43800h}"        # 5 years
: "${PKI_CERT_TTL:=8760h}"        # 1 year

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_DIR="$(cd "${SCRIPT_DIR}/../policies" && pwd)"

export VAULT_ADDR

###############################################################################
# Colors
###############################################################################
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log()  { printf "${BLUE}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()  { printf "${RED}[x]${NC} %s\n" "$*" >&2; }

section() {
  echo ""
  printf '%b═══════════════════════════════════════════════════%b\n' "${BLUE}" "${NC}"
  printf '%b %s%b\n' "${BLUE}" "$*" "${NC}"
  printf '%b═══════════════════════════════════════════════════%b\n' "${BLUE}" "${NC}"
}

###############################################################################
# Prerequisite checks
###############################################################################
preflight() {
  section "Preflight Checks"

  if ! command -v vault &>/dev/null; then
    err "vault CLI not found"; exit 1
  fi

  if ! command -v jq &>/dev/null; then
    err "jq not found"; exit 1
  fi

  if ! vault status -format=json &>/dev/null; then
    err "Cannot reach Vault at ${VAULT_ADDR}"
    exit 1
  fi

  local sealed
  sealed=$(vault status -format=json | jq -r '.sealed')
  if [[ "$sealed" == "true" ]]; then
    err "Vault is sealed. Unseal before running setup."
    exit 1
  fi

  if ! vault token lookup &>/dev/null 2>&1; then
    err "No valid Vault token. Authenticate as root/admin first."
    exit 1
  fi

  ok "Vault reachable and unsealed at ${VAULT_ADDR}"
}

###############################################################################
# 1. Secret Engines
###############################################################################
enable_engines() {
  section "Secret Engines"

  # KV v2
  if ! vault secrets list -format=json | jq -e '."kv/"' &>/dev/null; then
    vault secrets enable -path=kv -version=2 kv
    ok "Enabled: kv (v2)"
  else
    warn "Already enabled: kv"
  fi

  # Database
  if ! vault secrets list -format=json | jq -e '."database/"' &>/dev/null; then
    vault secrets enable database
    ok "Enabled: database"
  else
    warn "Already enabled: database"
  fi

  # PKI (root)
  if ! vault secrets list -format=json | jq -e '."pki/"' &>/dev/null; then
    vault secrets enable -path=pki pki
    vault secrets tune -max-lease-ttl="${PKI_ROOT_TTL}" pki
    ok "Enabled: pki (root CA)"
  else
    warn "Already enabled: pki"
  fi

  # PKI (intermediate)
  if ! vault secrets list -format=json | jq -e '."pki_int/"' &>/dev/null; then
    vault secrets enable -path=pki_int pki
    vault secrets tune -max-lease-ttl="${PKI_INT_TTL}" pki_int
    ok "Enabled: pki_int (intermediate CA)"
  else
    warn "Already enabled: pki_int"
  fi

  # SSH
  if ! vault secrets list -format=json | jq -e '."ssh/"' &>/dev/null; then
    vault secrets enable ssh
    ok "Enabled: ssh"
  else
    warn "Already enabled: ssh"
  fi

  # Transit
  if ! vault secrets list -format=json | jq -e '."transit/"' &>/dev/null; then
    vault secrets enable transit
    ok "Enabled: transit"
  else
    warn "Already enabled: transit"
  fi
}

###############################################################################
# 2. Auth Methods
###############################################################################
enable_auth() {
  section "Auth Methods"

  # OIDC
  if ! vault auth list -format=json | jq -e '."oidc/"' &>/dev/null; then
    vault auth enable oidc
    ok "Enabled auth: oidc"
  else
    warn "Already enabled: oidc"
  fi

  # JWT (for GitHub Actions)
  if ! vault auth list -format=json | jq -e '."jwt/github/"' &>/dev/null; then
    vault auth enable -path=jwt/github jwt
    ok "Enabled auth: jwt/github"
  else
    warn "Already enabled: jwt/github"
  fi

  # Kubernetes
  if ! vault auth list -format=json | jq -e '."kubernetes/"' &>/dev/null; then
    vault auth enable kubernetes
    ok "Enabled auth: kubernetes"
  else
    warn "Already enabled: kubernetes"
  fi

  # AppRole (for VMs and services)
  if ! vault auth list -format=json | jq -e '."approle/"' &>/dev/null; then
    vault auth enable approle
    ok "Enabled auth: approle"
  else
    warn "Already enabled: approle"
  fi
}

###############################################################################
# 3. Configure OIDC
###############################################################################
configure_oidc() {
  section "OIDC Configuration"

  vault write auth/oidc/config \
    oidc_discovery_url="${OIDC_DISCOVERY_URL}" \
    oidc_client_id="${OIDC_CLIENT_ID}" \
    oidc_client_secret="${OIDC_CLIENT_SECRET}" \
    default_role="developer"

  # Developer role
  vault write auth/oidc/role/developer \
    bound_audiences="${OIDC_CLIENT_ID}" \
    allowed_redirect_uris="${VAULT_ADDR}/ui/vault/auth/oidc/oidc/callback" \
    allowed_redirect_uris="http://localhost:8250/oidc/callback" \
    user_claim="email" \
    groups_claim="groups" \
    policies="developer-read" \
    ttl=8h \
    max_ttl=24h

  # Admin role
  vault write auth/oidc/role/admin \
    bound_audiences="${OIDC_CLIENT_ID}" \
    allowed_redirect_uris="${VAULT_ADDR}/ui/vault/auth/oidc/oidc/callback" \
    allowed_redirect_uris="http://localhost:8250/oidc/callback" \
    user_claim="email" \
    groups_claim="groups" \
    bound_claims='{"groups": ["vault-admins"]}' \
    policies="admin-emergency" \
    ttl=1h \
    max_ttl=4h

  ok "OIDC configured with developer and admin roles"
}

###############################################################################
# 4. Configure JWT/GitHub Actions
###############################################################################
configure_github_jwt() {
  section "GitHub Actions JWT"

  vault write auth/jwt/github/config \
    oidc_discovery_url="https://token.actions.githubusercontent.com" \
    bound_issuer="https://token.actions.githubusercontent.com"

  # CI role — scoped to specific repo
  vault write auth/jwt/github/role/ci-deploy \
    role_type="jwt" \
    bound_audiences="https://github.com/${GITHUB_ORG}" \
    bound_claims_type="glob" \
    bound_claims="{\"repository\": \"${GITHUB_ORG}/*\", \"ref\": \"refs/heads/main\"}" \
    user_claim="repository" \
    policies="ci-issuer" \
    ttl=15m \
    max_ttl=30m

  ok "GitHub Actions JWT configured for ${GITHUB_ORG}"
}

###############################################################################
# 5. Configure Kubernetes Auth
###############################################################################
configure_k8s_auth() {
  section "Kubernetes Auth"

  local sa_token=""
  if [[ -n "$K8S_TOKEN_REVIEWER_JWT" ]]; then
    sa_token="$K8S_TOKEN_REVIEWER_JWT"
  elif [[ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]]; then
    sa_token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  else
    warn "No Kubernetes token available — configure manually"
    return 0
  fi

  vault write auth/kubernetes/config \
    kubernetes_host="${K8S_HOST}" \
    kubernetes_ca_cert=@"${K8S_CA_CERT}" \
    token_reviewer_jwt="${sa_token}" \
    disable_local_ca_jwt=false

  ok "Kubernetes auth configured for ${K8S_HOST}"
}

###############################################################################
# 6. Load Policies
###############################################################################
load_policies() {
  section "Policies"

  if [[ ! -d "$POLICY_DIR" ]]; then
    warn "Policy directory not found: ${POLICY_DIR}"
    return 0
  fi

  local count=0
  for policy_file in "${POLICY_DIR}"/*.hcl; do
    [[ ! -f "$policy_file" ]] && continue
    local name
    name=$(basename "$policy_file" .hcl)
    vault policy write "$name" "$policy_file"
    ok "Loaded policy: ${name}"
    count=$((count + 1))
  done

  log "Loaded ${count} policies"
}

###############################################################################
# 7. PKI Hierarchy — Root + Intermediate
###############################################################################
setup_pki() {
  section "PKI Hierarchy"

  # Check if root CA already exists
  if vault read pki/cert/ca &>/dev/null 2>&1; then
    warn "Root CA already exists — skipping generation"
  else
    # Generate root CA
    vault write -format=json pki/root/generate/internal \
      common_name="Root CA — ${PKI_DOMAIN}" \
      issuer_name="root-ca" \
      ttl="${PKI_ROOT_TTL}" \
      key_type="ec" \
      key_bits=384 > /dev/null

    # Configure root CA URLs
    vault write pki/config/urls \
      issuing_certificates="${VAULT_ADDR}/v1/pki/ca" \
      crl_distribution_points="${VAULT_ADDR}/v1/pki/crl"

    ok "Root CA created: Root CA — ${PKI_DOMAIN}"
  fi

  # Generate intermediate CSR
  local int_csr
  int_csr=$(vault write -format=json pki_int/intermediate/generate/internal \
    common_name="Intermediate CA — ${PKI_DOMAIN}" \
    issuer_name="intermediate-ca" \
    key_type="ec" \
    key_bits=256 | jq -r '.data.csr')

  # Sign intermediate with root
  local int_cert
  int_cert=$(vault write -format=json pki/root/sign-intermediate \
    csr="$int_csr" \
    format="pem_bundle" \
    ttl="${PKI_INT_TTL}" | jq -r '.data.certificate')

  # Set signed intermediate
  vault write pki_int/intermediate/set-signed certificate="$int_cert"

  # Configure intermediate URLs
  vault write pki_int/config/urls \
    issuing_certificates="${VAULT_ADDR}/v1/pki_int/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/pki_int/crl"

  # Create roles
  vault write pki_int/roles/services \
    allowed_domains="${PKI_DOMAIN}" \
    allow_subdomains=true \
    allow_bare_domains=false \
    max_ttl="${PKI_CERT_TTL}" \
    key_type="ec" \
    key_bits=256 \
    require_cn=true \
    generate_lease=true

  vault write pki_int/roles/dev-services \
    allowed_domains="${PKI_DOMAIN},svc.cluster.local" \
    allow_subdomains=true \
    allow_bare_domains=false \
    max_ttl="720h" \
    key_type="ec" \
    key_bits=256 \
    require_cn=true

  ok "PKI hierarchy established (root -> intermediate)"
  ok "Roles created: services, dev-services"
}

###############################################################################
# 8. SSH CA
###############################################################################
setup_ssh() {
  section "SSH Certificate Authority"

  # Generate CA keypair if not already done
  if ! vault read ssh/config/ca &>/dev/null 2>&1; then
    vault write ssh/config/ca generate_signing_key=true key_type="ed25519"
    ok "SSH CA keypair generated (ed25519)"
  else
    warn "SSH CA already configured"
  fi

  # User signing role
  vault write ssh/roles/dev-admin \
    key_type="ca" \
    default_user="ubuntu" \
    allowed_users="ubuntu,admin,ec2-user" \
    allowed_extensions="permit-pty,permit-agent-forwarding" \
    ttl="8h" \
    max_ttl="24h" \
    algorithm_signer="ssh-ed25519"

  # Host signing role
  vault write ssh/roles/host-role \
    key_type="ca" \
    cert_type="host" \
    allowed_domains="${PKI_DOMAIN}" \
    allow_subdomains=true \
    ttl="8760h" \
    max_ttl="17520h" \
    algorithm_signer="ssh-ed25519"

  ok "SSH roles created: dev-admin (user), host-role (host)"

  # Print public key for trusted CA distribution
  local pub_key
  pub_key=$(vault read -field=public_key ssh/config/ca 2>/dev/null)
  log "SSH CA public key (add to /etc/ssh/trusted-user-ca-keys.pem):"
  echo "  ${pub_key}"
}

###############################################################################
# 9. Transit Keys
###############################################################################
setup_transit() {
  section "Transit Encryption Keys"

  # General-purpose encryption key
  if ! vault read transit/keys/general &>/dev/null 2>&1; then
    vault write -f transit/keys/general type=aes256-gcm96
    ok "Created transit key: general (aes256-gcm96)"
  else
    warn "Transit key 'general' already exists"
  fi

  # Application-specific key
  if ! vault read transit/keys/demo-app &>/dev/null 2>&1; then
    vault write -f transit/keys/demo-app type=aes256-gcm96
    ok "Created transit key: demo-app (aes256-gcm96)"
  else
    warn "Transit key 'demo-app' already exists"
  fi

  # Signing key (for token signing, webhooks)
  if ! vault read transit/keys/signing &>/dev/null 2>&1; then
    vault write -f transit/keys/signing type=ecdsa-p256
    ok "Created transit key: signing (ecdsa-p256)"
  else
    warn "Transit key 'signing' already exists"
  fi
}

###############################################################################
# 10. Database Connection
###############################################################################
setup_database() {
  section "Database Secret Engine"

  # Configure PostgreSQL connection
  vault write database/config/postgres \
    plugin_name="postgresql-database-plugin" \
    allowed_roles="dev-*,staging-*" \
    connection_url="postgresql://{{username}}:{{password}}@${DB_HOST}/postgres?sslmode=require" \
    username="${DB_ADMIN_USER}" \
    password="${DB_ADMIN_PASS}" \
    password_authentication="scram-sha-256"

  # Rotate root password immediately
  vault write -f database/rotate-root/postgres 2>/dev/null || true

  # Dynamic credential role
  vault write database/roles/dev-demo-app \
    db_name="postgres" \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

  ok "Database engine configured with role: dev-demo-app"
}

###############################################################################
# 11. Create Auth Roles
###############################################################################
create_roles() {
  section "Auth Roles"

  # AppRole for rotation service
  vault write auth/approle/role/rotation-service \
    secret_id_ttl="720h" \
    token_ttl="1h" \
    token_max_ttl="4h" \
    policies="rotation-operator" \
    secret_id_num_uses=0 \
    token_num_uses=0

  ok "AppRole created: rotation-service"

  # Kubernetes roles will be created per-app via onboard_app.sh
  log "Kubernetes auth roles: create per-app via onboard_app.sh"
}

###############################################################################
# 12. Audit Devices
###############################################################################
setup_audit() {
  section "Audit Logging"

  # File audit (primary)
  if ! vault audit list -format=json | jq -e '."file/"' &>/dev/null; then
    vault audit enable file file_path=/vault/audit/audit.log log_raw=false
    ok "Enabled audit device: file (/vault/audit/audit.log)"
  else
    warn "File audit already enabled"
  fi

  # Syslog audit (secondary — for SIEM)
  # vault audit enable -path=syslog syslog tag="vault" facility="AUTH"
  log "Syslog audit: enable manually for SIEM integration"
}

###############################################################################
# 13. Seed Initial Secrets
###############################################################################
seed_secrets() {
  section "Seed Initial Secrets"

  # Only seed if path doesn't exist
  if ! vault kv get kv/dev/apps/demo-app/config &>/dev/null 2>&1; then
    vault kv put kv/dev/apps/demo-app/config \
      APP_NAME="demo-app" \
      APP_ENV="dev" \
      API_URL="https://api.dev.example.internal" \
      LOG_LEVEL="debug"
    ok "Seeded: kv/dev/apps/demo-app/config"
  else
    warn "Already seeded: kv/dev/apps/demo-app/config"
  fi
}

###############################################################################
# 14. Validation
###############################################################################
validate() {
  section "Validation"

  local checks=0 passed=0

  # Secret engines
  for engine in kv database pki pki_int ssh transit; do
    checks=$((checks + 1))
    if vault secrets list -format=json | jq -e ".\"${engine}/\"" &>/dev/null; then
      ok "Engine: ${engine}"
      passed=$((passed + 1))
    else
      err "Missing engine: ${engine}"
    fi
  done

  # Auth methods
  for auth in oidc "jwt/github" kubernetes approle; do
    checks=$((checks + 1))
    if vault auth list -format=json | jq -e ".\"${auth}/\"" &>/dev/null; then
      ok "Auth: ${auth}"
      passed=$((passed + 1))
    else
      err "Missing auth: ${auth}"
    fi
  done

  # Policies
  for policy in developer-read ci-issuer db-dynamic transit-app ssh-ca-operator admin-emergency pki-admin rotation-operator; do
    checks=$((checks + 1))
    if vault policy read "$policy" &>/dev/null 2>&1; then
      ok "Policy: ${policy}"
      passed=$((passed + 1))
    else
      warn "Missing policy: ${policy}"
    fi
  done

  # PKI chain
  checks=$((checks + 1))
  if vault read pki_int/cert/ca &>/dev/null 2>&1; then
    ok "PKI: intermediate CA present"
    passed=$((passed + 1))
  else
    warn "PKI: intermediate CA not configured"
  fi

  # SSH CA
  checks=$((checks + 1))
  if vault read ssh/config/ca &>/dev/null 2>&1; then
    ok "SSH: CA configured"
    passed=$((passed + 1))
  else
    warn "SSH: CA not configured"
  fi

  echo ""
  log "Validation complete: ${passed}/${checks} checks passed"

  if [[ "$passed" -eq "$checks" ]]; then
    ok "All checks passed — Vault is fully configured"
  else
    warn "Some checks failed — review output above"
  fi
}

###############################################################################
# Main
###############################################################################
main() {
  echo ""
  log "========================================="
  log " Complete Vault Setup"
  log " Target: ${VAULT_ADDR}"
  log " $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "========================================="

  preflight
  enable_engines
  enable_auth
  configure_oidc
  configure_github_jwt
  configure_k8s_auth
  load_policies
  setup_pki
  setup_ssh
  setup_transit
  setup_database
  create_roles
  setup_audit
  seed_secrets
  validate

  echo ""
  ok "Setup complete. Review validation results above."
  echo ""
}

main "$@"
