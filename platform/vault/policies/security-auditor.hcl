# security-auditor.hcl — Security auditor policy
#
# Purpose:  Allow security team members and compliance auditors to inspect
#           Vault configuration, audit logs, and secret metadata without
#           accessing actual secret values. Designed for SOC2, ISO 27001,
#           and internal audit workflows.
#
# Identity: Security team members, compliance officers, external auditors.
#           Bound via OIDC with group claim for "security-auditors".
#
# Assign:   vault policy write security-auditor security-auditor.hcl
#           vault write auth/oidc/role/security-auditor \
#             bound_claims='{"groups":"security-auditors"}' \
#             token_policies="security-auditor" token_ttl=4h token_max_ttl=8h

# ---------------------------------------------------------------------------
# System health — cluster status and operational readiness
# Capabilities: read (check seal status, init status, HA mode)
# ---------------------------------------------------------------------------
path "sys/health" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Audit device configuration — verify audit logging is enabled
# Capabilities: read (list configured audit devices and their settings)
# ---------------------------------------------------------------------------
path "sys/audit" {
  capabilities = ["read"]
}

path "sys/audit/*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Mount enumeration — list all enabled secret and auth engines
# Capabilities: read (enumerate mounts for configuration audit)
# ---------------------------------------------------------------------------
path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/mounts/*" {
  capabilities = ["read"]
}

path "sys/auth" {
  capabilities = ["read"]
}

path "sys/auth/*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Policy enumeration — list and read all policies
# Capabilities: read, list (review policy definitions)
# ---------------------------------------------------------------------------
path "sys/policies/acl" {
  capabilities = ["read", "list"]
}

path "sys/policies/acl/*" {
  capabilities = ["read"]
}

# Sentinel policies (Enterprise)
path "sys/policies/egp" {
  capabilities = ["read", "list"]
}

path "sys/policies/egp/*" {
  capabilities = ["read"]
}

path "sys/policies/rgp" {
  capabilities = ["read", "list"]
}

path "sys/policies/rgp/*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# KV metadata — read metadata (versions, timestamps) without secret values
# Capabilities: read, list (audit secret lifecycle without data exposure)
# ---------------------------------------------------------------------------
path "kv/metadata/*" {
  capabilities = ["read", "list"]
}

# ---------------------------------------------------------------------------
# Explicit deny — never read actual secret values
# Capabilities: deny (prevent auditor from accessing secret data)
# ---------------------------------------------------------------------------
path "kv/data/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Identity — review entity and group configurations
# Capabilities: read, list (audit identity mappings and group memberships)
# ---------------------------------------------------------------------------
path "identity/entity/id/*" {
  capabilities = ["read"]
}

path "identity/entity/name/*" {
  capabilities = ["read"]
}

path "identity/entity-alias/id/*" {
  capabilities = ["read"]
}

path "identity/group/id/*" {
  capabilities = ["read"]
}

path "identity/group/name/*" {
  capabilities = ["read"]
}

path "identity/entity/id" {
  capabilities = ["list"]
}

path "identity/group/id" {
  capabilities = ["list"]
}

# ---------------------------------------------------------------------------
# Lease information — audit active leases and their TTLs
# Capabilities: list, update (enumerate and lookup leases)
# ---------------------------------------------------------------------------
path "sys/leases/lookup" {
  capabilities = ["update"]
}

path "sys/leases/lookup/*" {
  capabilities = ["list"]
}

# ---------------------------------------------------------------------------
# Replication status (Enterprise) — verify DR/performance replication
# Capabilities: read (check replication health)
# ---------------------------------------------------------------------------
path "sys/replication/status" {
  capabilities = ["read"]
}

path "sys/replication/dr/status" {
  capabilities = ["read"]
}

path "sys/replication/performance/status" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Token introspection — self-check
# Capabilities: read (verify own token)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no secret engine data access (only metadata)
# Capabilities: deny (prevent credential generation and secret reads)
# ---------------------------------------------------------------------------
path "database/creds/*" {
  capabilities = ["deny"]
}

path "pki_int/sign/*" {
  capabilities = ["deny"]
}

path "pki_int/issue/*" {
  capabilities = ["deny"]
}

path "transit/encrypt/*" {
  capabilities = ["deny"]
}

path "transit/decrypt/*" {
  capabilities = ["deny"]
}

path "ssh/sign/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no administrative mutations
# Capabilities: deny (auditors observe, they never modify)
# ---------------------------------------------------------------------------
path "sys/seal" {
  capabilities = ["deny"]
}

path "sys/unseal" {
  capabilities = ["deny"]
}

path "sys/policies/acl/+" {
  # Read is allowed above; this blocks write/delete on policy endpoints
  capabilities = ["deny"]
}

path "sys/audit/+" {
  # Read is allowed above; block creation/deletion of audit devices
  capabilities = ["deny"]
}
