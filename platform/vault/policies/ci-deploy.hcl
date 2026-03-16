# ci-deploy.hcl — CI/CD deployment pipeline policy
#
# Purpose:  Enable deployment pipelines to read secrets, generate dynamic
#           database credentials, issue TLS certificates, and encrypt
#           deployment artifacts via Transit.
#
# Identity: CI deploy jobs (GitHub Actions deploy workflow, ArgoCD, Flux)
#           Bound via JWT/OIDC auth with environment/branch claims.
#
# Assign:   vault policy write ci-deploy ci-deploy.hcl
#           vault write auth/jwt/role/ci-deploy \
#             bound_claims='{"repository":"org/repo","ref":"refs/heads/main"}' \
#             token_policies="ci-deploy" token_ttl=30m token_max_ttl=1h

# ---------------------------------------------------------------------------
# KV v2 — read application secrets for deployment targets
# Capabilities: read (get secret data for config injection)
# ---------------------------------------------------------------------------
path "kv/data/dev/apps/+/config" {
  capabilities = ["read"]
}

path "kv/data/staging/apps/+/config" {
  capabilities = ["read"]
}

path "kv/data/prod/apps/+/config" {
  capabilities = ["read"]
}

# KV metadata — verify versions before deploying
# Capabilities: read (check version metadata for deployment validation)
path "kv/metadata/dev/apps/+/config" {
  capabilities = ["read"]
}

path "kv/metadata/staging/apps/+/config" {
  capabilities = ["read"]
}

path "kv/metadata/prod/apps/+/config" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Dynamic database credentials — short-lived creds for migrations & deploys
# Capabilities: read (generate dynamic credentials from configured roles)
# ---------------------------------------------------------------------------
path "database/creds/dev-*" {
  capabilities = ["read"]
}

path "database/creds/staging-*" {
  capabilities = ["read"]
}

path "database/creds/prod-deploy-*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# PKI — issue TLS certificates for deployed services
# Capabilities: create, update (request certificate signing)
# ---------------------------------------------------------------------------

# Sign CSRs against the intermediate CA for service identities
path "pki_int/sign/deploy-services" {
  capabilities = ["create", "update"]
}

# Issue certificates directly (when CSR is not pre-generated)
path "pki_int/issue/deploy-services" {
  capabilities = ["create", "update"]
}

# Read CA chain for trust bundle injection into deployments
# Capabilities: read (retrieve CA certificate chain)
path "pki_int/ca/pem" {
  capabilities = ["read"]
}

path "pki_int/ca_chain" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Transit — encrypt deployment secrets and artifacts
# Capabilities: create, update (encrypt and rewrap operations)
# ---------------------------------------------------------------------------

# Encrypt deployment artifacts (sealed secrets, config bundles)
path "transit/encrypt/deploy-*" {
  capabilities = ["create", "update"]
}

# Decrypt during rollback operations
path "transit/decrypt/deploy-*" {
  capabilities = ["create", "update"]
}

# Rewrap ciphertext to latest key version during key rotation
path "transit/rewrap/deploy-*" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Lease management — renew and lookup dynamic credential leases
# Capabilities: update (manage active leases for long-running deploys)
# ---------------------------------------------------------------------------
path "sys/leases/lookup" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

# ---------------------------------------------------------------------------
# Token introspection — pipeline health checks
# Capabilities: read (verify token validity during deployment)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no KV writes (deployments read, never write secrets)
# Capabilities: deny (prevent secret modification by CI)
# ---------------------------------------------------------------------------
path "kv/data/+/apps/+/*" {
  capabilities = ["deny"]
  # NOTE: specific read paths above override this for their exact matches
}

path "kv/delete/*" {
  capabilities = ["deny"]
}

path "kv/destroy/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no transit key management
# Capabilities: deny (prevent key creation, deletion, or configuration)
# ---------------------------------------------------------------------------
path "transit/keys/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no system or auth manipulation
# Capabilities: deny (prevent policy changes, auth reconfiguration, seal)
# ---------------------------------------------------------------------------
path "sys/policies/*" {
  capabilities = ["deny"]
}

path "sys/auth/*" {
  capabilities = ["deny"]
}

path "sys/seal" {
  capabilities = ["deny"]
}

path "sys/mounts" {
  capabilities = ["deny"]
}
