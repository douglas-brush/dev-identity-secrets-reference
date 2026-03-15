#!/usr/bin/env sh
# Vault bootstrap script — configures all secret engines, auth methods,
# policies, and demo data for the local dev environment.
# Designed for idempotent re-runs.
set -e

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="${VAULT_DEV_ROOT_TOKEN_ID:-dev-root-token}"

POLICY_DIR="/vault/policies"

# ── Helpers ──────────────────────────────────────────────────────────
log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m  ✓\033[0m %s\n' "$1"; }
skip() { printf '\033[1;33m  –\033[0m %s (already exists)\n' "$1"; }
err()  { printf '\033[1;31m  ✗\033[0m %s\n' "$1"; }

wait_for_vault() {
  log "Waiting for Vault to be ready..."
  for i in $(seq 1 30); do
    if vault status >/dev/null 2>&1; then
      ok "Vault is ready"
      return 0
    fi
    sleep 1
  done
  err "Vault did not become ready in 30s"
  exit 1
}

enable_engine() {
  engine="$1"; path="$2"; shift 2
  if vault secrets list -format=json | grep -q "\"${path}/\""; then
    skip "secrets engine ${path}"
  else
    vault secrets enable -path="${path}" "$@" "${engine}"
    ok "secrets engine ${path}"
  fi
}

enable_auth() {
  method="$1"; path="$2"
  if vault auth list -format=json | grep -q "\"${path}/\""; then
    skip "auth method ${path}"
  else
    vault auth enable -path="${path}" "${method}"
    ok "auth method ${path}"
  fi
}

# ── Wait ─────────────────────────────────────────────────────────────
wait_for_vault

# ── Audit ────────────────────────────────────────────────────────────
log "Configuring audit logging..."
if vault audit list -format=json 2>/dev/null | grep -q '"stdout/"'; then
  skip "audit device stdout"
else
  vault audit enable file file_path=stdout log_raw=false || true
  ok "audit device stdout"
fi

# ── Secret Engines ───────────────────────────────────────────────────
log "Enabling secret engines..."
enable_engine kv kv -version=2
enable_engine database database
enable_engine pki pki -max-lease-ttl=87600h
enable_engine pki pki_int -max-lease-ttl=43800h
enable_engine ssh ssh
enable_engine transit transit

# ── Policies ─────────────────────────────────────────────────────────
log "Loading policies from ${POLICY_DIR}..."
if [ -d "${POLICY_DIR}" ]; then
  for f in "${POLICY_DIR}"/*.hcl; do
    name=$(basename "$f" .hcl)
    vault policy write "${name}" "${f}"
    ok "policy ${name}"
  done
else
  err "Policy directory not found: ${POLICY_DIR}"
fi

# ── Auth: AppRole ────────────────────────────────────────────────────
log "Configuring AppRole auth..."
enable_auth approle approle

# ── KV: Seed example secrets ────────────────────────────────────────
log "Seeding KV secrets..."
vault kv put kv/dev/apps/demo-app/config \
  db_host="postgres" \
  db_port="5432" \
  db_name="demo" \
  api_key="demo-api-key-12345" \
  feature_flags='{"dark_mode":true,"beta_api":false}'
ok "kv/dev/apps/demo-app/config"

vault kv put kv/dev/apps/demo-app/tls \
  cert="placeholder-cert-pem" \
  key="placeholder-key-pem"
ok "kv/dev/apps/demo-app/tls"

vault kv put kv/dev/shared/database \
  admin_user="postgres" \
  admin_host="postgres:5432"
ok "kv/dev/shared/database"

# ── Database: Dynamic credentials ───────────────────────────────────
log "Configuring database secret engine..."

# Wait for PostgreSQL
log "Waiting for PostgreSQL..."
for i in $(seq 1 30); do
  if vault write -force database/config/demo-postgres 2>/dev/null; then
    break
  fi
  # Just check connectivity below
  sleep 1
  [ "$i" = "30" ] && err "Timed out waiting for PostgreSQL"
done

vault write database/config/demo-postgres \
  plugin_name=postgresql-database-plugin \
  allowed_roles="dev-demo-app,dev-readonly" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/demo?sslmode=disable" \
  username="vault_admin" \
  password="vault_admin_password"
ok "database connection demo-postgres"

vault write database/roles/dev-demo-app \
  db_name=demo-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
ok "database role dev-demo-app"

vault write database/roles/dev-readonly \
  db_name=demo-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
ok "database role dev-readonly"

# ── PKI: Root CA ────────────────────────────────────────────────────
log "Configuring PKI hierarchy..."

# Generate root CA (idempotent — check if already configured)
ROOT_CA=$(vault read -format=json pki/cert/ca 2>/dev/null | grep -c certificate || true)
if [ "$ROOT_CA" = "0" ] || [ -z "$ROOT_CA" ]; then
  vault write pki/root/generate/internal \
    common_name="Dev Root CA" \
    issuer_name="dev-root-ca" \
    ttl=87600h \
    key_bits=4096
  ok "PKI root CA"
else
  skip "PKI root CA"
fi

vault write pki/config/urls \
  issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
  crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
ok "PKI root URLs"

# Generate intermediate CA
INT_CA=$(vault read -format=json pki_int/cert/ca 2>/dev/null | grep -c certificate || true)
if [ "$INT_CA" = "0" ] || [ -z "$INT_CA" ]; then
  # Generate CSR
  vault write -format=json pki_int/intermediate/generate/internal \
    common_name="Dev Intermediate CA" \
    issuer_name="dev-intermediate-ca" \
    key_bits=4096 \
    | jq -r '.data.csr' > /tmp/pki_int.csr

  # Sign with root
  vault write -format=json pki/root/sign-intermediate \
    csr=@/tmp/pki_int.csr \
    format=pem_bundle \
    ttl=43800h \
    | jq -r '.data.certificate' > /tmp/pki_int.pem

  # Set signed certificate
  vault write pki_int/intermediate/set-signed \
    certificate=@/tmp/pki_int.pem
  ok "PKI intermediate CA"

  rm -f /tmp/pki_int.csr /tmp/pki_int.pem
else
  skip "PKI intermediate CA"
fi

vault write pki_int/config/urls \
  issuing_certificates="http://127.0.0.1:8200/v1/pki_int/ca" \
  crl_distribution_points="http://127.0.0.1:8200/v1/pki_int/crl"
ok "PKI intermediate URLs"

# Create PKI role for issuing dev service certs
vault write pki_int/roles/dev-services \
  allowed_domains="dev.local,svc.local,localhost" \
  allow_subdomains=true \
  allow_localhost=true \
  max_ttl=720h \
  key_bits=2048 \
  require_cn=false \
  allow_ip_sans=true
ok "PKI role dev-services"

# ── SSH: Signed keys ───────────────────────────────────────────────
log "Configuring SSH CA..."

SSH_KEY=$(vault read -format=json ssh/config/ca 2>/dev/null | grep -c public_key || true)
if [ "$SSH_KEY" = "0" ] || [ -z "$SSH_KEY" ]; then
  vault write ssh/config/ca generate_signing_key=true
  ok "SSH CA key pair"
else
  skip "SSH CA key pair"
fi

vault write ssh/roles/dev-admin \
  key_type=ca \
  default_user=dev \
  allowed_users="dev,ubuntu,ec2-user,root" \
  allow_user_certificates=true \
  ttl=30m \
  max_ttl=2h \
  algorithm_signer=rsa-sha2-256 \
  default_extensions='{"permit-pty":"","permit-agent-forwarding":""}'
ok "SSH role dev-admin"

# ── Transit: Encryption keys ───────────────────────────────────────
log "Configuring Transit engine..."
vault write -f transit/keys/demo-app type=aes256-gcm96
ok "transit key demo-app"

vault write -f transit/keys/signing-key type=ecdsa-p256
ok "transit key signing-key"

# ── AppRole: Demo role ──────────────────────────────────────────────
log "Configuring demo AppRole..."
vault write auth/approle/role/demo-app \
  token_policies="developer-read,db-dynamic,transit-app" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=10m \
  secret_id_num_uses=1 \
  bind_secret_id=true

ROLE_ID=$(vault read -format=json auth/approle/role/demo-app/role-id | jq -r '.data.role_id')
SECRET_ID=$(vault write -format=json -f auth/approle/role/demo-app/secret-id | jq -r '.data.secret_id')

ok "AppRole demo-app"

# ── CI AppRole ──────────────────────────────────────────────────────
vault write auth/approle/role/ci-issuer \
  token_policies="ci-issuer" \
  token_ttl=15m \
  token_max_ttl=30m \
  secret_id_ttl=5m \
  secret_id_num_uses=1 \
  bind_secret_id=true
ok "AppRole ci-issuer"

# ── Summary ─────────────────────────────────────────────────────────
printf '\n'
log "══════════════════════════════════════════════════════════════"
log "  Vault dev environment is ready!"
log "══════════════════════════════════════════════════════════════"
printf '\n'
printf '  \033[1mVault UI:\033[0m        http://localhost:8200/ui\n'
printf '  \033[1mVault Address:\033[0m   http://localhost:8200\n'
printf '  \033[1mRoot Token:\033[0m      %s\n' "${VAULT_TOKEN}"
printf '  \033[1mPostgreSQL:\033[0m      localhost:5432 (demo/postgres)\n'
printf '\n'
printf '  \033[1mDemo AppRole:\033[0m\n'
printf '    Role ID:     %s\n' "${ROLE_ID}"
printf '    Secret ID:   %s\n' "${SECRET_ID}"
printf '    (Secret ID is single-use — generate new ones with:\n'
printf '     vault write -f auth/approle/role/demo-app/secret-id)\n'
printf '\n'
printf '  \033[1mSecret Engines:\033[0m  kv, database, pki, pki_int, ssh, transit\n'
printf '  \033[1mPolicies:\033[0m        '
vault policy list 2>/dev/null | grep -v default | grep -v root | tr '\n' ' '
printf '\n\n'
log "Run 'make demo' or './demo.sh' to walk through all patterns."
log "══════════════════════════════════════════════════════════════"
