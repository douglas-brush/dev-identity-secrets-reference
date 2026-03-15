###############################################################################
# Outputs — Azure Key Vault + OIDC Module
###############################################################################

output "key_vault_id" {
  description = "Resource ID of the Azure Key Vault"
  value       = azurerm_key_vault.main.id
}

output "key_vault_uri" {
  description = "URI of the Azure Key Vault"
  value       = azurerm_key_vault.main.vault_uri
}

output "key_vault_name" {
  description = "Name of the Azure Key Vault"
  value       = azurerm_key_vault.main.name
}

output "managed_identity_id" {
  description = "Resource ID of the user-assigned managed identity for GitHub Actions"
  value       = azurerm_user_assigned_identity.github_actions.id
}

output "managed_identity_client_id" {
  description = "Client ID of the user-assigned managed identity for GitHub Actions"
  value       = azurerm_user_assigned_identity.github_actions.client_id
}

output "managed_identity_principal_id" {
  description = "Principal ID of the user-assigned managed identity for GitHub Actions"
  value       = azurerm_user_assigned_identity.github_actions.principal_id
}

output "managed_identity_tenant_id" {
  description = "Tenant ID of the user-assigned managed identity"
  value       = azurerm_user_assigned_identity.github_actions.tenant_id
}

output "sops_key_id" {
  description = "ID of the Key Vault key used for SOPS encryption"
  value       = azurerm_key_vault_key.sops.id
}

output "sops_key_url" {
  description = "Versioned URL of the Key Vault key used for SOPS encryption"
  value       = azurerm_key_vault_key.sops.versionless_id
}

output "sops_key_name" {
  description = "Name of the Key Vault key used for SOPS encryption"
  value       = azurerm_key_vault_key.sops.name
}

output "tenant_id" {
  description = "Azure AD tenant ID"
  value       = data.azurerm_client_config.current.tenant_id
}
