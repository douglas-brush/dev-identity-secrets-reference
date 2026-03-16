# transit-only.hcl — Transit encryption-only policy
#
# Purpose:  Allow applications to perform encrypt, decrypt, and rewrap
#           operations on specifically named transit keys. No key deletion,
#           no key creation, no access to any other secret engine.
#
# Identity: Application service accounts that need envelope encryption
#           (e.g., encrypting PII at rest, signing JWTs, HMAC validation).
#           Bound via Kubernetes auth or AppRole with app-specific role.
#
# Assign:   vault policy write transit-only transit-only.hcl
#           vault write auth/kubernetes/role/transit-app \
#             bound_service_account_names="my-app" \
#             bound_service_account_namespaces="my-namespace" \
#             token_policies="transit-only" token_ttl=15m token_max_ttl=1h

# ---------------------------------------------------------------------------
# Encrypt — encrypt plaintext with named transit keys
# Capabilities: create, update (submit plaintext for encryption)
#
# Key naming convention: keys follow <env>-<app>-<purpose> pattern
# e.g., prod-payments-pii, dev-api-tokens
# ---------------------------------------------------------------------------
path "transit/encrypt/+" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Decrypt — decrypt ciphertext with named transit keys
# Capabilities: create, update (submit ciphertext for decryption)
# ---------------------------------------------------------------------------
path "transit/decrypt/+" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Rewrap — re-encrypt ciphertext with latest key version
# Used during key rotation to migrate ciphertext without exposing plaintext
# Capabilities: create, update (submit ciphertext for re-encryption)
# ---------------------------------------------------------------------------
path "transit/rewrap/+" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Sign and verify — digital signature operations
# Capabilities: create, update (sign data and verify signatures)
# ---------------------------------------------------------------------------
path "transit/sign/+/*" {
  capabilities = ["create", "update"]
}

path "transit/verify/+/*" {
  capabilities = ["create", "update"]
}

# Signing without hash algorithm suffix
path "transit/sign/+" {
  capabilities = ["create", "update"]
}

path "transit/verify/+" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# HMAC — generate and verify HMACs
# Capabilities: create, update (HMAC operations)
# ---------------------------------------------------------------------------
path "transit/hmac/+/*" {
  capabilities = ["create", "update"]
}

path "transit/hmac/+" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Data key generation — generate data encryption keys (envelope encryption)
# Capabilities: create, update (generate wrapped/plaintext DEKs)
# ---------------------------------------------------------------------------
path "transit/datakey/plaintext/+" {
  capabilities = ["create", "update"]
}

path "transit/datakey/wrapped/+" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Key info — read key metadata (version, type) for operational awareness
# Capabilities: read (check key configuration, NOT modify)
# ---------------------------------------------------------------------------
path "transit/keys/+" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Token introspection
# Capabilities: read (verify own token)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ===========================================================================
# EXPLICIT DENY — Transit users perform crypto ops, nothing else
# ===========================================================================

# ---------------------------------------------------------------------------
# Deny key creation — keys are provisioned by platform team, not apps
# Capabilities: deny (prevent unauthorized key provisioning)
# ---------------------------------------------------------------------------
path "transit/keys/+/config" {
  capabilities = ["deny"]
}

path "transit/keys/+/rotate" {
  capabilities = ["deny"]
}

# Deny creating new keys (POST to transit/keys/<name>)
path "transit/keys/*" {
  capabilities = ["deny"]
  # NOTE: the read path "transit/keys/+" above is more specific
  # and takes precedence, allowing key info reads.
}

# ---------------------------------------------------------------------------
# Deny key export and backup — prevent key material extraction
# Capabilities: deny (protect key material confidentiality)
# ---------------------------------------------------------------------------
path "transit/export/*" {
  capabilities = ["deny"]
}

path "transit/backup/*" {
  capabilities = ["deny"]
}

path "transit/restore/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny cache and config — transit engine configuration is admin-only
# Capabilities: deny (prevent engine reconfiguration)
# ---------------------------------------------------------------------------
path "transit/cache-config" {
  capabilities = ["deny"]
}

path "transit/config" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny all other secret engines
# Capabilities: deny (enforce single-engine access)
# ---------------------------------------------------------------------------
path "kv/*" {
  capabilities = ["deny"]
}

path "database/*" {
  capabilities = ["deny"]
}

path "pki_int/*" {
  capabilities = ["deny"]
}

path "ssh/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny system operations
# Capabilities: deny (prevent policy, auth, mount, seal manipulation)
# ---------------------------------------------------------------------------
path "sys/policies/*" {
  capabilities = ["deny"]
}

path "sys/auth/*" {
  capabilities = ["deny"]
}

path "sys/mounts/*" {
  capabilities = ["deny"]
}

path "sys/seal" {
  capabilities = ["deny"]
}
