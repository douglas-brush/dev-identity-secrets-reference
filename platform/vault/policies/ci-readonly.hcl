# ci-readonly.hcl — CI/CD read-only policy
#
# Purpose:  Allow CI pipelines to read application secrets from KV.
#           No write, no list on root mounts, no access to other engines.
#
# Identity: CI runner service accounts (GitHub Actions, GitLab CI, Jenkins)
#           Bound via JWT/OIDC auth with repo/branch claims.
#
# Assign:   vault policy write ci-readonly ci-readonly.hcl
#           vault write auth/jwt/role/ci-readonly \
#             bound_claims='{"repository":"org/repo"}' \
#             token_policies="ci-readonly" token_ttl=15m token_max_ttl=30m

# ---------------------------------------------------------------------------
# KV v2 — read application config for specific environments
# Capabilities: read (get secret data)
# ---------------------------------------------------------------------------
path "kv/data/dev/apps/+/config" {
  capabilities = ["read"]
}

path "kv/data/staging/apps/+/config" {
  capabilities = ["read"]
}

# KV v2 — read metadata to verify secret versions exist
# Capabilities: read (check version metadata)
path "kv/metadata/dev/apps/+/config" {
  capabilities = ["read"]
}

path "kv/metadata/staging/apps/+/config" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Explicit deny — prevent any write operations on KV
# ---------------------------------------------------------------------------
path "kv/data/*" {
  capabilities = ["deny"]

  # Override: the read grants above take precedence for their specific paths
  # because Vault evaluates most-specific-path first. This deny catches
  # any path not explicitly granted above.
  #
  # NOTE: Vault policy resolution — explicit path matches beat glob matches.
  # The specific read paths above will still work despite this deny.
}

# Deny KV delete and destroy operations
# Capabilities: deny (prevent secret deletion and permanent destruction)
path "kv/delete/*" {
  capabilities = ["deny"]
}

path "kv/destroy/*" {
  capabilities = ["deny"]
}

# Deny KV metadata writes (prevents creating new secrets)
# Capabilities: deny (prevent metadata manipulation)
path "kv/metadata/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no root-level listing
# Capabilities: deny (prevent mount enumeration)
# ---------------------------------------------------------------------------
path "sys/mounts" {
  capabilities = ["deny"]
}

path "sys/mounts/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no access to other secret engines
# Capabilities: deny (prevent lateral movement to database, PKI, transit)
# ---------------------------------------------------------------------------
path "database/*" {
  capabilities = ["deny"]
}

path "pki_int/*" {
  capabilities = ["deny"]
}

path "transit/*" {
  capabilities = ["deny"]
}

path "ssh/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no system operations
# Capabilities: deny (prevent policy, auth, and seal manipulation)
# ---------------------------------------------------------------------------
path "sys/policies/*" {
  capabilities = ["deny"]
}

path "auth/*" {
  capabilities = ["deny"]
}

path "sys/seal" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Token introspection — allow CI to verify its own token
# Capabilities: read (lookup-self for health checks)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
