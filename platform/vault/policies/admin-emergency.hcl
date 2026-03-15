# Break-glass emergency access policy.
# Grant via: vault token create -policy=admin-emergency -ttl=1h -use-limit=100
# MUST be logged, reviewed, and rotated after use.

# Broad read access for emergency operations
path "kv/data/*" {
  capabilities = ["read", "list"]
}

path "database/creds/*" {
  capabilities = ["read"]
}

path "pki_int/sign/*" {
  capabilities = ["create", "update"]
}

path "ssh/sign/*" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/*" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/*" {
  capabilities = ["create", "update"]
}

# System health and audit
path "sys/health" {
  capabilities = ["read"]
}

path "sys/audit" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

# Explicitly deny destructive operations
path "sys/seal" {
  capabilities = ["deny"]
}

path "kv/delete/*" {
  capabilities = ["deny"]
}

path "kv/destroy/*" {
  capabilities = ["deny"]
}

path "sys/policies/acl/*" {
  capabilities = ["deny"]
}
