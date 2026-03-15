# Human developer role: read only what is needed in dev, not broad platform access.

path "kv/data/dev/apps/{{identity.entity.aliases.auth_oidc_*/name}}/*" {
  capabilities = ["read", "list"]
}

path "database/creds/dev-*" {
  capabilities = ["read"]
}

path "ssh/sign/dev-admin" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/dev-*" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/dev-*" {
  capabilities = ["create", "update"]
}
