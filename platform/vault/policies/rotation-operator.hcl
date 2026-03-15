# Rotation operator — automated secret rotation service.

path "kv/data/+/apps/+/config" {
  capabilities = ["read", "update"]
}

path "kv/metadata/+/apps/+/config" {
  capabilities = ["read"]
}

path "database/rotate-role/*" {
  capabilities = ["create", "update"]
}

path "database/creds/*" {
  capabilities = ["read"]
}

path "sys/leases/lookup" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
