#!/usr/bin/env bash
# Seed Vault with realistic demo data across all engines.
# Idempotent — safe to re-run. Requires a running, bootstrapped Vault.
set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"

# ── Helpers ──────────────────────────────────────────────────────────
log()  { printf '\033[1;34m[seed]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m  +\033[0m %s\n' "$1"; }

# ── Preflight ────────────────────────────────────────────────────────
log "Checking Vault connectivity..."
vault status >/dev/null 2>&1 || { printf '\033[1;31mVault not reachable at %s\033[0m\n' "$VAULT_ADDR"; exit 1; }

# ═════════════════════════════════════════════════════════════════════
# 1. KV Secrets — dev / staging / prod paths
# ═════════════════════════════════════════════════════════════════════
log "Seeding KV secrets across environments..."

vault kv put kv/dev/apps/web-frontend/config \
  api_url="http://localhost:3000/api" \
  cdn_url="https://cdn.dev.example.com" \
  log_level="debug" \
  feature_flags='{"new_checkout":true,"dark_mode":true,"beta_api":false}'
ok "kv/dev/apps/web-frontend/config"

vault kv put kv/dev/apps/payment-service/config \
  stripe_endpoint="https://api.stripe.com/v1" \
  stripe_api_key="sk_test_demo_26PHem9AhJZvU623DfE1x4sd" \
  webhook_secret="whsec_demo_test_secret_abc123" \
  retry_max="3" \
  timeout_ms="5000"
ok "kv/dev/apps/payment-service/config"

vault kv put kv/dev/apps/notification-service/config \
  smtp_host="smtp.dev.example.com" \
  smtp_port="587" \
  smtp_user="notifications@dev.example.com" \
  smtp_password="demo-smtp-password-dev" \
  from_address="noreply@dev.example.com" \
  sendgrid_api_key="SG.demo_test_key_not_real"
ok "kv/dev/apps/notification-service/config"

vault kv put kv/dev/apps/auth-service/config \
  jwt_secret="dev-jwt-secret-change-in-prod-abc123" \
  jwt_expiry="3600" \
  oauth_client_id="dev-oauth-client-id" \
  oauth_client_secret="dev-oauth-client-secret" \
  session_encryption_key="32-byte-dev-encryption-key-here!"
ok "kv/dev/apps/auth-service/config"

vault kv put kv/staging/apps/web-frontend/config \
  api_url="https://api.staging.example.com" \
  cdn_url="https://cdn.staging.example.com" \
  log_level="info" \
  feature_flags='{"new_checkout":true,"dark_mode":true,"beta_api":true}'
ok "kv/staging/apps/web-frontend/config"

vault kv put kv/staging/apps/payment-service/config \
  stripe_endpoint="https://api.stripe.com/v1" \
  stripe_api_key="sk_test_staging_FakeKeyForDemo456" \
  webhook_secret="whsec_staging_demo_secret_def456" \
  retry_max="3" \
  timeout_ms="3000"
ok "kv/staging/apps/payment-service/config"

vault kv put kv/prod/apps/web-frontend/config \
  api_url="https://api.example.com" \
  cdn_url="https://cdn.example.com" \
  log_level="warn" \
  feature_flags='{"new_checkout":false,"dark_mode":true,"beta_api":false}'
ok "kv/prod/apps/web-frontend/config"

vault kv put kv/prod/apps/payment-service/config \
  stripe_endpoint="https://api.stripe.com/v1" \
  stripe_api_key="sk_live_REPLACE_IN_REAL_PROD" \
  webhook_secret="whsec_REPLACE_IN_REAL_PROD" \
  retry_max="5" \
  timeout_ms="10000"
ok "kv/prod/apps/payment-service/config"

vault kv put kv/dev/shared/infrastructure \
  redis_url="redis://localhost:6379/0" \
  rabbitmq_url="amqp://guest:guest@localhost:5672/" \
  elasticsearch_url="http://localhost:9200" \
  s3_bucket="dev-assets-bucket" \
  s3_region="us-east-1"
ok "kv/dev/shared/infrastructure"

vault kv put kv/dev/shared/observability \
  datadog_api_key="demo-dd-api-key-not-real" \
  sentry_dsn="https://demo@sentry.dev.example.com/1" \
  pagerduty_routing_key="demo-pd-routing-key"
ok "kv/dev/shared/observability"

# ═════════════════════════════════════════════════════════════════════
# 2. Database Roles — 3 roles with different privilege levels
# ═════════════════════════════════════════════════════════════════════
log "Configuring additional database roles..."

vault write database/roles/dev-analytics \
  db_name=demo-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="2h" \
  max_ttl="8h"
ok "database role dev-analytics (read-only, long TTL)"

vault write database/roles/dev-migration \
  db_name=demo-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\"; \
GRANT CREATE ON SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; \
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM \"{{name}}\"; \
REVOKE CREATE ON SCHEMA public FROM \"{{name}}\"; \
DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="15m" \
  max_ttl="1h"
ok "database role dev-migration (full DDL, short TTL)"

vault write database/roles/dev-backup \
  db_name=demo-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
GRANT USAGE ON SCHEMA public TO \"{{name}}\";" \
  revocation_statements="REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{name}}\"; DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="30m" \
  max_ttl="2h"
ok "database role dev-backup (select-only for pg_dump)"

# ═════════════════════════════════════════════════════════════════════
# 3. PKI — Issue 5 service certificates
# ═════════════════════════════════════════════════════════════════════
log "Issuing demo PKI certificates..."

for svc in api gateway auth payments notifications; do
  vault write pki_int/issue/dev-services \
    common_name="${svc}.dev.local" \
    alt_names="${svc}.svc.local,localhost" \
    ip_sans="127.0.0.1" \
    ttl="720h" >/dev/null 2>&1
  ok "cert: ${svc}.dev.local (30d TTL)"
done

# ═════════════════════════════════════════════════════════════════════
# 4. Transit Keys — Different use cases
# ═════════════════════════════════════════════════════════════════════
log "Creating Transit encryption keys..."

vault write -f transit/keys/pii-encryption type=aes256-gcm96
ok "transit key: pii-encryption (AES-256-GCM — PII at rest)"

vault write -f transit/keys/api-token-hmac type=aes256-gcm96
ok "transit key: api-token-hmac (AES-256-GCM — token hashing)"

vault write -f transit/keys/document-signing type=ecdsa-p256
ok "transit key: document-signing (ECDSA P-256 — document integrity)"

vault write -f transit/keys/backup-encryption type=chacha20-poly1305
ok "transit key: backup-encryption (ChaCha20 — backup archives)"

vault write -f transit/keys/config-encryption \
  type=aes256-gcm96 \
  auto_rotate_period="720h"
ok "transit key: config-encryption (AES-256-GCM — auto-rotate 30d)"

# ═════════════════════════════════════════════════════════════════════
# 5. AppRole Credentials — Demo application identities
# ═════════════════════════════════════════════════════════════════════
log "Configuring demo AppRole identities..."

vault write auth/approle/role/web-frontend \
  token_policies="developer-read" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h \
  secret_id_num_uses=0 \
  bind_secret_id=true
ok "AppRole: web-frontend (developer-read)"

vault write auth/approle/role/payment-service \
  token_policies="developer-read,transit-app" \
  token_ttl=30m \
  token_max_ttl=2h \
  secret_id_ttl=10m \
  secret_id_num_uses=1 \
  bind_secret_id=true
ok "AppRole: payment-service (developer-read, transit-app)"

vault write auth/approle/role/analytics-pipeline \
  token_policies="db-dynamic" \
  token_ttl=2h \
  token_max_ttl=8h \
  secret_id_ttl=1h \
  secret_id_num_uses=5 \
  bind_secret_id=true
ok "AppRole: analytics-pipeline (db-dynamic)"

# Write the vault-agent role-id and secret-id for the sidecar
log "Writing Vault Agent bootstrap credentials..."
AGENT_ROLE_ID=$(vault read -format=json auth/approle/role/demo-app/role-id | jq -r '.data.role_id')
AGENT_SECRET_ID=$(vault write -format=json -f auth/approle/role/demo-app/secret-id | jq -r '.data.secret_id')

# If vault-agent volume is mounted, write credentials there
if [ -d "/tmp/vault" ]; then
  echo "$AGENT_ROLE_ID" > /tmp/vault/role-id
  echo "$AGENT_SECRET_ID" > /tmp/vault/secret-id
  ok "Vault Agent credentials written to /tmp/vault/"
else
  printf '  \033[1;33m  Vault Agent role-id:\033[0m  %s\n' "$AGENT_ROLE_ID"
  printf '  \033[1;33m  Vault Agent secret-id:\033[0m %s\n' "$AGENT_SECRET_ID"
  ok "Vault Agent credentials (write to vault-agent volume manually or run inside container)"
fi

# ═════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════
printf '\n'
log "Demo data seeding complete."
printf '\n'
printf '  \033[1mKV Secrets:\033[0m\n'
printf '    dev/     — web-frontend, payment-service, notification-service, auth-service\n'
printf '    staging/ — web-frontend, payment-service\n'
printf '    prod/    — web-frontend, payment-service\n'
printf '    shared/  — infrastructure, observability\n'
printf '\n'
printf '  \033[1mDatabase Roles:\033[0m dev-demo-app, dev-readonly, dev-analytics, dev-migration, dev-backup\n'
printf '  \033[1mPKI Certs:\033[0m     api, gateway, auth, payments, notifications (.dev.local)\n'
printf '  \033[1mTransit Keys:\033[0m  demo-app, signing-key, pii-encryption, api-token-hmac,\n'
printf '                 document-signing, backup-encryption, config-encryption\n'
printf '  \033[1mAppRoles:\033[0m      demo-app, ci-issuer, web-frontend, payment-service, analytics-pipeline\n'
printf '\n'
