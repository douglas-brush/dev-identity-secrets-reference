# break-glass.hcl — Emergency break-glass access policy
#
# Purpose:  Provide broad read access during incidents when normal approval
#           workflows are unavailable or too slow. Designed to be paired
#           with control group approval (2 approvers) and mandatory audit.
#
# Identity: On-call engineers, incident commanders. Issued via a separate
#           auth method (hardware token OIDC, sealed emergency credential,
#           or MFA-gated userpass with 2-person rule).
#
# CRITICAL: Break-glass usage MUST trigger:
#   - Immediate audit log entry tagged with break-glass metadata
#   - PagerDuty/Slack alert via audit webhook
#   - Mandatory post-incident review within 24 hours
#   - Token TTL capped at 2 hours by Sentinel EGP
#
# Assign:   vault policy write break-glass break-glass.hcl
#           vault write auth/token/roles/break-glass \
#             allowed_policies="break-glass" token_ttl=1h token_max_ttl=2h \
#             token_explicit_max_ttl=2h renewable=false

# ---------------------------------------------------------------------------
# KV v2 — broad read access across all environments
# Capabilities: read, list (retrieve and browse secrets during incidents)
# ---------------------------------------------------------------------------
path "kv/data/dev/*" {
  capabilities = ["read", "list"]
}

path "kv/data/staging/*" {
  capabilities = ["read", "list"]
}

path "kv/data/prod/*" {
  capabilities = ["read", "list"]
}

path "kv/metadata/*" {
  capabilities = ["read", "list"]
}

# ---------------------------------------------------------------------------
# Dynamic database credentials — all environments
# Capabilities: read (generate credentials for emergency access)
# ---------------------------------------------------------------------------
path "database/creds/dev-*" {
  capabilities = ["read"]
}

path "database/creds/staging-*" {
  capabilities = ["read"]
}

path "database/creds/prod-*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# PKI — issue certificates for emergency service restoration
# Capabilities: create, update (sign and issue certificates)
# ---------------------------------------------------------------------------
path "pki_int/sign/*" {
  capabilities = ["create", "update"]
}

path "pki_int/issue/*" {
  capabilities = ["create", "update"]
}

path "pki_int/ca/pem" {
  capabilities = ["read"]
}

path "pki_int/ca_chain" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# SSH — sign keys for emergency host access
# Capabilities: create, update (sign SSH public keys)
# ---------------------------------------------------------------------------
path "ssh/sign/*" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Transit — encrypt/decrypt for incident forensics and recovery
# Capabilities: create, update (cryptographic operations)
# ---------------------------------------------------------------------------
path "transit/encrypt/*" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/*" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# System observability — health, mounts, leases, audit status
# Capabilities: read (assess cluster state during incident)
# ---------------------------------------------------------------------------
path "sys/health" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/audit" {
  capabilities = ["read"]
}

path "sys/leases/lookup" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

# ---------------------------------------------------------------------------
# Token introspection
# Capabilities: read (verify own token state)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ===========================================================================
# EXPLICIT DENY — Hard boundaries even during emergencies
# ===========================================================================

# ---------------------------------------------------------------------------
# Deny seal operations — no emergency justifies sealing the cluster
# Capabilities: deny (protect cluster availability)
# ---------------------------------------------------------------------------
path "sys/seal" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny policy deletion — prevent privilege escalation via policy removal
# Capabilities: deny (protect governance controls)
# ---------------------------------------------------------------------------
path "sys/policies/acl/*" {
  capabilities = ["deny"]
}

path "sys/policies/egp/*" {
  capabilities = ["deny"]
}

path "sys/policies/rgp/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny auth method changes — prevent identity infrastructure tampering
# Capabilities: deny (protect authentication configuration)
# ---------------------------------------------------------------------------
path "sys/auth/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny secret destruction — incidents need data, not data loss
# Capabilities: deny (prevent permanent secret deletion)
# ---------------------------------------------------------------------------
path "kv/delete/*" {
  capabilities = ["deny"]
}

path "kv/destroy/*" {
  capabilities = ["deny"]
}

path "kv/metadata/+/+/+/*" {
  # Deny metadata delete — prevents wiping secret history
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny bulk lease revocation — prevent cascading service failures
# Capabilities: deny (protect active service credentials)
# ---------------------------------------------------------------------------
path "sys/leases/revoke-prefix/*" {
  capabilities = ["deny"]
}

path "sys/leases/revoke-force/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny mount management — prevent engine enable/disable during incidents
# Capabilities: deny (protect infrastructure topology)
# ---------------------------------------------------------------------------
path "sys/mounts/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny transit key management — use keys, don't change them
# Capabilities: deny (prevent key deletion or reconfiguration)
# ---------------------------------------------------------------------------
path "transit/keys/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Control group requirement (Enterprise) — requires 2 approvals
# This block is informational; actual control group config is applied
# when this policy is assigned to an identity group with a control
# group factor. See vault-jit-policy.hcl for the full pattern.
# ---------------------------------------------------------------------------
# control_group {
#   factor "break-glass-approval" {
#     identity {
#       group_names = ["incident-commanders"]
#       approvals   = 2
#     }
#   }
#   ttl = "15m"
# }
