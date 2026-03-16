# developer.hcl — Human developer policy
#
# Purpose:  Allow developers to manage their own secrets in a personal
#           KV namespace, read shared team secrets, generate dev-scoped
#           database credentials, and issue dev TLS certificates.
#
# Identity: Human developers authenticated via OIDC (Entra ID, Okta, etc.)
#           Entity alias templating scopes paths to the authenticated user.
#
# Assign:   vault policy write developer developer.hcl
#           vault write auth/oidc/role/developer \
#             bound_audiences="vault" allowed_redirect_uris="..." \
#             token_policies="developer" token_ttl=8h token_max_ttl=12h

# ---------------------------------------------------------------------------
# Personal KV namespace — full read/write for the developer's own space
# Uses identity templating to scope to the authenticated entity name.
# Capabilities: create, read, update, delete, list (full CRUD on own secrets)
# ---------------------------------------------------------------------------
path "kv/data/dev/personal/{{identity.entity.name}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv/metadata/dev/personal/{{identity.entity.name}}/*" {
  capabilities = ["read", "list", "delete"]
}

# ---------------------------------------------------------------------------
# Shared team KV — read-only access to team-scoped secrets
# Capabilities: read, list (browse and retrieve shared config)
# ---------------------------------------------------------------------------
path "kv/data/dev/shared/*" {
  capabilities = ["read", "list"]
}

path "kv/metadata/dev/shared/*" {
  capabilities = ["read", "list"]
}

# Shared app configs — read-only
# Capabilities: read (retrieve app configuration)
path "kv/data/dev/apps/+/config" {
  capabilities = ["read"]
}

path "kv/metadata/dev/apps/+/config" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Dynamic database credentials — dev-scoped roles only
# Capabilities: read (generate short-lived dev database credentials)
# ---------------------------------------------------------------------------
path "database/creds/dev-*" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# PKI — issue dev certificates for local development and testing
# Capabilities: create, update (request dev certificate signing)
# ---------------------------------------------------------------------------
path "pki_int/sign/dev-services" {
  capabilities = ["create", "update"]
}

path "pki_int/issue/dev-services" {
  capabilities = ["create", "update"]
}

# Read the CA chain for local trust store configuration
# Capabilities: read (retrieve CA certificate)
path "pki_int/ca/pem" {
  capabilities = ["read"]
}

path "pki_int/ca_chain" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Transit — encrypt/decrypt with dev-scoped keys
# Capabilities: create, update (encrypt and decrypt operations)
# ---------------------------------------------------------------------------
path "transit/encrypt/dev-*" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/dev-*" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# SSH — sign SSH keys for dev host access
# Capabilities: create, update (request SSH certificate)
# ---------------------------------------------------------------------------
path "ssh/sign/dev-admin" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Token and identity introspection
# Capabilities: read (verify own token and entity details)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "identity/entity/id/{{identity.entity.id}}" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no access to production secrets
# Capabilities: deny (enforce environment boundary)
# ---------------------------------------------------------------------------
path "kv/data/prod/*" {
  capabilities = ["deny"]
}

path "kv/metadata/prod/*" {
  capabilities = ["deny"]
}

path "database/creds/prod-*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no access to other developers' personal namespaces
# The identity-templated path above is the ONLY personal path accessible.
# Any attempt to reach another user's space hits this deny.
# Capabilities: deny (prevent cross-user secret access)
# ---------------------------------------------------------------------------
path "kv/data/dev/personal/*" {
  capabilities = ["deny"]
}

path "kv/metadata/dev/personal/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no system or administrative operations
# Capabilities: deny (prevent policy, auth, mount, seal manipulation)
# ---------------------------------------------------------------------------
path "sys/policies/*" {
  capabilities = ["deny"]
}

path "sys/auth/*" {
  capabilities = ["deny"]
}

path "sys/mounts" {
  capabilities = ["deny"]
}

path "sys/seal" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Explicit deny — no transit key management (use keys, don't manage them)
# Capabilities: deny (prevent key creation, deletion, rotation)
# ---------------------------------------------------------------------------
path "transit/keys/*" {
  capabilities = ["deny"]
}
