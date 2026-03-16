# rotation-agent.hcl — Automated secret rotation agent policy
#
# Purpose:  Allow rotation automation (CronJob, Lambda, Vault Agent) to
#           read current secrets, write rotated values, manage transit
#           keys for re-encryption, and trigger database credential rotation.
#
# Identity: Service account for rotation automation (Kubernetes SA, IAM role).
#           Bound via Kubernetes auth or AppRole with rotation-scoped role.
#
# Assign:   vault policy write rotation-agent rotation-agent.hcl
#           vault write auth/kubernetes/role/rotation-agent \
#             bound_service_account_names="vault-rotation-agent" \
#             bound_service_account_namespaces="vault-system" \
#             token_policies="rotation-agent" token_ttl=30m token_max_ttl=1h

# ---------------------------------------------------------------------------
# KV v2 — read and write rotation-managed secrets
# Capabilities: create, read, update (read current value, write new value)
# ---------------------------------------------------------------------------

# Application config secrets — rotation target
path "kv/data/+/apps/+/config" {
  capabilities = ["create", "read", "update"]
}

path "kv/metadata/+/apps/+/config" {
  capabilities = ["read"]
}

# Rotation state tracking — stores last rotation timestamp and status
path "kv/data/rotation/state/*" {
  capabilities = ["create", "read", "update"]
}

path "kv/metadata/rotation/state/*" {
  capabilities = ["read", "list"]
}

# ---------------------------------------------------------------------------
# Database — trigger role rotation and generate new credentials
# Capabilities: create, update (rotate static roles), read (verify creds)
# ---------------------------------------------------------------------------

# Rotate static database roles
path "database/rotate-role/*" {
  capabilities = ["create", "update"]
}

# Read credentials to verify rotation succeeded
path "database/creds/*" {
  capabilities = ["read"]
}

# Read static role configuration (for rotation validation)
path "database/static-creds/*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Transit — manage encryption keys for secret re-encryption during rotation
# Capabilities: read (key info), create/update (rotate, rewrap)
# ---------------------------------------------------------------------------

# Rotate transit key versions (creates new key version, does NOT delete old)
path "transit/keys/+/rotate" {
  capabilities = ["create", "update"]
}

# Read key configuration (to check key version, rotation schedule)
path "transit/keys/*" {
  capabilities = ["read"]
}

# Rewrap ciphertext from old key version to new key version
path "transit/rewrap/*" {
  capabilities = ["create", "update"]
}

# Encrypt with latest key version during rotation
path "transit/encrypt/*" {
  capabilities = ["create", "update"]
}

# Decrypt with old key version during re-encryption
path "transit/decrypt/*" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Lease management — manage leases for rotated dynamic credentials
# Capabilities: update (lookup and renew active leases)
# ---------------------------------------------------------------------------
path "sys/leases/lookup" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

# Revoke specific expired leases after rotation completes
path "sys/leases/revoke" {
  capabilities = ["update"]
}

# ---------------------------------------------------------------------------
# Token introspection
# Capabilities: read (verify own token for health checks)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

# ===========================================================================
# EXPLICIT DENY — Rotation agents must not modify infrastructure
# ===========================================================================

# ---------------------------------------------------------------------------
# Deny KV deletion — rotation writes new versions, never deletes
# Capabilities: deny (protect secret history for audit trail)
# ---------------------------------------------------------------------------
path "kv/delete/*" {
  capabilities = ["deny"]
}

path "kv/destroy/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny transit key deletion and configuration changes
# Rotation can add key versions and rewrap, but never delete or reconfigure
# Capabilities: deny (protect key material)
# ---------------------------------------------------------------------------
path "transit/keys/+/config" {
  capabilities = ["deny"]
}

# Transit key deletion requires a specific config set (deletion_allowed=true)
# plus a delete call — deny both the config change and the delete
path "transit/keys/*" {
  capabilities = ["deny"]
  # NOTE: read and rotate paths above are more specific and take precedence
}

# ---------------------------------------------------------------------------
# Deny auth method changes — rotation must not modify identity infrastructure
# Capabilities: deny (prevent auth reconfiguration)
# ---------------------------------------------------------------------------
path "sys/auth/*" {
  capabilities = ["deny"]
}

path "auth/+/role/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny policy and mount changes
# Capabilities: deny (prevent infrastructure tampering)
# ---------------------------------------------------------------------------
path "sys/policies/*" {
  capabilities = ["deny"]
}

path "sys/mounts/*" {
  capabilities = ["deny"]
}

path "sys/seal" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny bulk lease revocation — rotation handles individual leases only
# Capabilities: deny (prevent service disruption)
# ---------------------------------------------------------------------------
path "sys/leases/revoke-prefix/*" {
  capabilities = ["deny"]
}

path "sys/leases/revoke-force/*" {
  capabilities = ["deny"]
}
