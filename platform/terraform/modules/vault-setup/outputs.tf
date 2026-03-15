###############################################################################
# Outputs — Vault Setup Module
###############################################################################

# -----------------------------------------------------------------------------
# Engine Mount Paths
# -----------------------------------------------------------------------------

output "kv_mount_path" {
  description = "Mount path of the KV v2 secrets engine"
  value       = vault_mount.kv.path
}

output "database_mount_path" {
  description = "Mount path of the database secrets engine (empty if disabled)"
  value       = var.enable_database_engine ? vault_mount.database[0].path : ""
}

output "pki_root_mount_path" {
  description = "Mount path of the root PKI CA (empty if disabled)"
  value       = var.enable_pki_engine ? vault_mount.pki_root[0].path : ""
}

output "pki_intermediate_mount_path" {
  description = "Mount path of the intermediate PKI CA (empty if disabled)"
  value       = var.enable_pki_engine ? vault_mount.pki_intermediate[0].path : ""
}

output "ssh_mount_path" {
  description = "Mount path of the SSH secrets engine (empty if disabled)"
  value       = var.enable_ssh_engine ? vault_mount.ssh[0].path : ""
}

output "transit_mount_path" {
  description = "Mount path of the transit secrets engine (empty if disabled)"
  value       = var.enable_transit_engine ? vault_mount.transit[0].path : ""
}

# -----------------------------------------------------------------------------
# Policy Names
# -----------------------------------------------------------------------------

output "policy_names" {
  description = "Map of all created policy names"
  value = merge(
    {
      admin            = vault_policy.admin.name
      secrets_reader   = vault_policy.secrets_reader.name
      secrets_writer   = vault_policy.secrets_writer.name
      github_actions   = vault_policy.github_actions.name
    },
    var.enable_kubernetes_auth ? {
      kubernetes_app = vault_policy.kubernetes_app[0].name
    } : {},
    { for k, v in vault_policy.custom : k => v.name },
  )
}

# -----------------------------------------------------------------------------
# Auth Method Paths
# -----------------------------------------------------------------------------

output "oidc_auth_path" {
  description = "Path of the OIDC auth method (empty if disabled)"
  value       = var.enable_oidc_auth ? vault_jwt_auth_backend.oidc[0].path : ""
}

output "github_jwt_auth_path" {
  description = "Path of the GitHub Actions JWT auth method (empty if disabled)"
  value       = var.enable_github_jwt_auth ? vault_jwt_auth_backend.github_actions[0].path : ""
}

output "kubernetes_auth_path" {
  description = "Path of the Kubernetes auth method (empty if disabled)"
  value       = var.enable_kubernetes_auth ? vault_auth_backend.kubernetes[0].path : ""
}

# -----------------------------------------------------------------------------
# Role Names
# -----------------------------------------------------------------------------

output "oidc_role_names" {
  description = "List of OIDC auth role names"
  value = var.enable_oidc_auth ? [
    vault_jwt_auth_backend_role.oidc_default[0].role_name,
    vault_jwt_auth_backend_role.oidc_admin[0].role_name,
  ] : []
}

output "github_actions_role_names" {
  description = "Map of GitHub repo names to their JWT auth role names"
  value = {
    for repo, role in vault_jwt_auth_backend_role.github_actions :
    repo => role.role_name
  }
}

output "kubernetes_role_names" {
  description = "Map of Kubernetes auth role names"
  value = {
    for name, role in vault_kubernetes_auth_backend_role.app :
    name => role.role_name
  }
}

# -----------------------------------------------------------------------------
# PKI
# -----------------------------------------------------------------------------

output "pki_root_ca_certificate" {
  description = "PEM-encoded root CA certificate (empty if PKI disabled)"
  value       = var.enable_pki_engine ? vault_pki_secret_backend_root_cert.root[0].certificate : ""
  sensitive   = true
}

output "pki_intermediate_ca_certificate" {
  description = "PEM-encoded intermediate CA certificate (empty if PKI disabled)"
  value       = var.enable_pki_engine ? vault_pki_secret_backend_root_sign_intermediate.intermediate[0].certificate : ""
  sensitive   = true
}

# -----------------------------------------------------------------------------
# SSH
# -----------------------------------------------------------------------------

output "ssh_ca_public_key" {
  description = "SSH CA public key for client verification (empty if SSH disabled)"
  value       = var.enable_ssh_engine ? vault_ssh_secret_backend_ca.ssh[0].public_key : ""
}
