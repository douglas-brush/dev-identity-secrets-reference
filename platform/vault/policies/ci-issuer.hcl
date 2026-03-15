# CI job role: tightly scoped issuance and secret read.

path "kv/data/dev/apps/demo-app/*" {
  capabilities = ["read"]
}

path "database/creds/dev-demo-app" {
  capabilities = ["read"]
}

path "pki_int/sign/dev-services" {
  capabilities = ["create", "update"]
}
