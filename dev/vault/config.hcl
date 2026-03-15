# Vault development server configuration.
# In dev mode Vault ignores most of this, but it documents the intent
# and is used if you switch to non-dev mode for testing.

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

ui = true

api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"

# Audit logging — stdout for container visibility.
# Enabled programmatically in setup.sh since audit backends
# must be enabled after server start via the API.
