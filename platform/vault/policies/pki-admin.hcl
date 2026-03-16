# pki-admin.hcl — PKI infrastructure administrator policy
#
# Purpose:  Full management of the PKI intermediate CA mount including
#           role management, CRL configuration, certificate lifecycle,
#           and tidy operations. No access to transit, KV, or other engines.
#
# Identity: Platform/security engineers responsible for certificate infrastructure.
#           Bound via OIDC with group claim for "pki-admins".
#
# Assign:   vault policy write pki-admin pki-admin.hcl
#           vault write auth/oidc/role/pki-admin \
#             bound_claims='{"groups":"pki-admins"}' \
#             token_policies="pki-admin" token_ttl=4h token_max_ttl=8h

# ---------------------------------------------------------------------------
# Certificate signing and issuance — core CA operations
# Capabilities: create, update (sign CSRs and issue certificates)
# ---------------------------------------------------------------------------
path "pki_int/sign/*" {
  capabilities = ["create", "update"]
}

path "pki_int/issue/*" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Certificate revocation — revoke compromised or expired certificates
# Capabilities: create, update (submit revocation requests)
# ---------------------------------------------------------------------------
path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

path "pki_int/revoke-with-key" {
  capabilities = ["create", "update"]
}

# ---------------------------------------------------------------------------
# Certificate inventory — list and inspect issued certificates
# Capabilities: read, list (audit certificate inventory)
# ---------------------------------------------------------------------------
path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/certs/revoked" {
  capabilities = ["list"]
}

# ---------------------------------------------------------------------------
# CA certificate chain — retrieve for trust bundle distribution
# Capabilities: read (retrieve CA certificate and chain)
# ---------------------------------------------------------------------------
path "pki_int/ca/pem" {
  capabilities = ["read"]
}

path "pki_int/ca_chain" {
  capabilities = ["read"]
}

path "pki_int/cert/ca" {
  capabilities = ["read"]
}

path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# CRL management — configure and retrieve certificate revocation lists
# Capabilities: read (retrieve CRL), create/update (configure CRL settings)
# ---------------------------------------------------------------------------
path "pki_int/crl" {
  capabilities = ["read"]
}

path "pki_int/crl/pem" {
  capabilities = ["read"]
}

path "pki_int/crl/rotate" {
  capabilities = ["create", "update"]
}

path "pki_int/config/crl" {
  capabilities = ["read", "create", "update"]
}

# ---------------------------------------------------------------------------
# OCSP configuration (Vault 1.12+)
# Capabilities: read, create, update (manage OCSP responder config)
# ---------------------------------------------------------------------------
path "pki_int/config/ocsp" {
  capabilities = ["read", "create", "update"]
}

# ---------------------------------------------------------------------------
# PKI role management — create, read, update, delete certificate roles
# Capabilities: create, read, update, delete, list (full role lifecycle)
# ---------------------------------------------------------------------------
path "pki_int/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki_int/roles" {
  capabilities = ["list"]
}

# ---------------------------------------------------------------------------
# URLs configuration — set issuing and CRL distribution endpoints
# Capabilities: read, create, update (manage CA URL configuration)
# ---------------------------------------------------------------------------
path "pki_int/config/urls" {
  capabilities = ["read", "create", "update"]
}

# ---------------------------------------------------------------------------
# Issuers management (Vault 1.11+ multi-issuer support)
# Capabilities: read, list, create, update (manage intermediate CAs)
# ---------------------------------------------------------------------------
path "pki_int/issuers" {
  capabilities = ["list"]
}

path "pki_int/issuer/*" {
  capabilities = ["read", "create", "update"]
}

path "pki_int/config/issuers" {
  capabilities = ["read", "create", "update"]
}

# ---------------------------------------------------------------------------
# Tidy operations — clean up expired certificates and CRL entries
# Capabilities: create, update (trigger tidy), read (check tidy status)
# ---------------------------------------------------------------------------
path "pki_int/tidy" {
  capabilities = ["create", "update"]
}

path "pki_int/tidy-status" {
  capabilities = ["read"]
}

path "pki_int/config/auto-tidy" {
  capabilities = ["read", "create", "update"]
}

# ---------------------------------------------------------------------------
# Token introspection
# Capabilities: read (verify own token)
# ---------------------------------------------------------------------------
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# ===========================================================================
# EXPLICIT DENY — PKI admins manage certificates, nothing else
# ===========================================================================

# ---------------------------------------------------------------------------
# Deny root CA operations — intermediate CA only
# Capabilities: deny (protect root CA from intermediate CA administrators)
# ---------------------------------------------------------------------------
path "pki/root/*" {
  capabilities = ["deny"]
}

path "pki/config/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny transit access — PKI admins have no need for transit
# Capabilities: deny (enforce separation of duties)
# ---------------------------------------------------------------------------
path "transit/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny KV access — PKI admins manage certs, not application secrets
# Capabilities: deny (enforce separation of duties)
# ---------------------------------------------------------------------------
path "kv/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny database access
# Capabilities: deny (enforce separation of duties)
# ---------------------------------------------------------------------------
path "database/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny SSH access
# Capabilities: deny (enforce separation of duties)
# ---------------------------------------------------------------------------
path "ssh/*" {
  capabilities = ["deny"]
}

# ---------------------------------------------------------------------------
# Deny system administration — PKI admins don't manage Vault itself
# Capabilities: deny (prevent policy, auth, seal manipulation)
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

# Deny mount management — PKI admin manages PKI config, not mounts
# The mount itself should be enabled/disabled by platform admins
# Capabilities: deny (prevent mount topology changes)
path "sys/mounts/*" {
  capabilities = ["deny"]
}
