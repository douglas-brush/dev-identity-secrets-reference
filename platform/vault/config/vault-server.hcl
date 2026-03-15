# HashiCorp Vault — Production Server Configuration
# This configuration assumes HA deployment with Raft storage.

# Cluster identification
cluster_name = "vault-prod"

# Listener — TLS required
listener "tcp" {
  address       = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/vault/tls/tls.crt"
  tls_key_file  = "/vault/tls/tls.key"
  tls_min_version = "tls12"

  # Telemetry
  telemetry {
    unauthenticated_metrics_access = true
  }
}

# Storage — Integrated Raft
storage "raft" {
  path    = "/vault/data"
  node_id = "vault-0"

  retry_join {
    leader_api_addr         = "https://vault-0.vault-internal:8200"
    leader_ca_cert_file     = "/vault/tls/ca.crt"
    leader_client_cert_file = "/vault/tls/tls.crt"
    leader_client_key_file  = "/vault/tls/tls.key"
  }

  retry_join {
    leader_api_addr         = "https://vault-1.vault-internal:8200"
    leader_ca_cert_file     = "/vault/tls/ca.crt"
    leader_client_cert_file = "/vault/tls/tls.crt"
    leader_client_key_file  = "/vault/tls/tls.key"
  }

  retry_join {
    leader_api_addr         = "https://vault-2.vault-internal:8200"
    leader_ca_cert_file     = "/vault/tls/ca.crt"
    leader_client_cert_file = "/vault/tls/tls.crt"
    leader_client_key_file  = "/vault/tls/tls.key"
  }
}

# Auto-unseal — choose ONE provider and uncomment
# AWS KMS
# seal "awskms" {
#   region     = "us-east-1"
#   kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/vault-unseal-key-id"
# }

# Azure Key Vault
# seal "azurekeyvault" {
#   tenant_id  = "your-tenant-id"
#   vault_name = "your-vault-name"
#   key_name   = "vault-unseal"
# }

# GCP Cloud KMS
# seal "gcpckms" {
#   project     = "your-project-id"
#   region      = "global"
#   key_ring    = "vault"
#   crypto_key  = "unseal"
# }

# API configuration
api_addr     = "https://vault.example.internal:8200"
cluster_addr = "https://vault-0.vault-internal:8201"

# UI
ui = true

# Telemetry — Prometheus
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname         = true
}

# Audit — file backend (also configure syslog/socket for SIEM)
# Enable via CLI: vault audit enable file file_path=/vault/audit/audit.log
