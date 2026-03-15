# Azure Key Vault + OIDC Module

Provisions an Azure Key Vault with RBAC authorization, a user-assigned managed identity with GitHub Actions federated identity credentials, a SOPS encryption key with automatic rotation, and diagnostic settings for audit logging. This module enables keyless CI/CD authentication from GitHub Actions to Azure using workload identity federation.

## Usage

```hcl
module "azure_keyvault_oidc" {
  source = "./modules/azure-keyvault-oidc"

  resource_group_name = "rg-secrets-prod"
  location            = "eastus"

  github_org    = "my-org"
  allowed_repos = ["infra-repo", "app-repo"]
  environment   = "prod"

  key_vault_name         = "kv-myorg-prod-001"
  key_vault_sku          = "standard"
  enable_purge_protection = true

  network_default_action = "Deny"
  allowed_ip_ranges      = ["203.0.113.0/24"]

  additional_reader_principal_ids = ["00000000-0000-0000-0000-000000000001"]

  log_analytics_workspace_id = "/subscriptions/.../workspaces/la-prod"

  tags = {
    Project = "identity-reference"
  }
}
```

## Inputs

| Name | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `resource_group_name` | `string` | n/a | yes | Name of the Azure resource group to deploy into |
| `location` | `string` | n/a | yes | Azure region for resource deployment |
| `github_org` | `string` | n/a | yes | GitHub organization name for federated identity subject matching |
| `allowed_repos` | `list(string)` | n/a | yes | List of GitHub repository names to create federated identity credentials for |
| `default_branch` | `string` | `"main"` | no | Default branch name used in federated identity subject claims |
| `enable_environment_federation` | `bool` | `true` | no | Whether to create additional federated credentials for GitHub environment-based deployments |
| `environment` | `string` | n/a | yes | Deployment environment name (`dev`, `staging`, or `prod`) |
| `key_vault_name` | `string` | n/a | yes | Name of the Azure Key Vault (must be globally unique, 3-24 characters) |
| `key_vault_sku` | `string` | `"standard"` | no | SKU of the Key Vault (`standard` or `premium`; premium required for HSM-backed keys) |
| `enable_purge_protection` | `bool` | `true` | no | Whether to enable purge protection on the Key Vault |
| `soft_delete_retention_days` | `number` | `90` | no | Number of days to retain soft-deleted Key Vault objects (7-90) |
| `public_network_access_enabled` | `bool` | `true` | no | Whether public network access is enabled for the Key Vault |
| `network_default_action` | `string` | `"Allow"` | no | Default network action for Key Vault firewall (`Allow` or `Deny`) |
| `allowed_ip_ranges` | `list(string)` | `[]` | no | List of IP ranges allowed to access the Key Vault |
| `allowed_subnet_ids` | `list(string)` | `[]` | no | List of subnet IDs allowed to access the Key Vault |
| `additional_reader_principal_ids` | `list(string)` | `[]` | no | List of Azure AD principal IDs to grant Key Vault Secrets User role |
| `log_analytics_workspace_id` | `string` | `""` | no | ID of the Log Analytics workspace for diagnostic settings (empty to skip) |
| `diagnostics_storage_account_id` | `string` | `""` | no | ID of the storage account for diagnostic log archival (empty to skip) |
| `tags` | `map(string)` | `{}` | no | Additional tags to apply to all resources |

## Outputs

| Name | Description |
|------|-------------|
| `key_vault_id` | Resource ID of the Azure Key Vault |
| `key_vault_uri` | URI of the Azure Key Vault |
| `key_vault_name` | Name of the Azure Key Vault |
| `managed_identity_id` | Resource ID of the user-assigned managed identity for GitHub Actions |
| `managed_identity_client_id` | Client ID of the user-assigned managed identity for GitHub Actions |
| `managed_identity_principal_id` | Principal ID of the user-assigned managed identity for GitHub Actions |
| `managed_identity_tenant_id` | Tenant ID of the user-assigned managed identity |
| `sops_key_id` | ID of the Key Vault key used for SOPS encryption |
| `sops_key_url` | Versioned URL of the Key Vault key used for SOPS encryption |
| `sops_key_name` | Name of the Key Vault key used for SOPS encryption |
| `tenant_id` | Azure AD tenant ID |

## Prerequisites

- Terraform >= 1.5.0
- AzureRM provider >= 3.80, < 5.0
- An existing Azure resource group
- Azure AD permissions to create managed identities and federated identity credentials
- RBAC permissions to assign Key Vault roles at the resource scope

## Notes on Integration

- The Key Vault uses RBAC authorization (not access policies). The deploying principal is automatically assigned the Key Vault Administrator role.
- GitHub Actions managed identity receives `Key Vault Secrets User` in prod and `Key Vault Secrets Officer` in non-prod environments, plus `Key Vault Crypto User` for SOPS operations.
- When `enable_environment_federation` is true, additional federated credentials are created for GitHub Actions environment-based deployments (e.g., `repo:org/repo:environment:prod`).
- The SOPS key is an RSA-2048 key with automatic rotation every 365 days (30-day pre-expiry notification).
- Diagnostic settings support both Log Analytics and Storage Account destinations. AuditEvent and AzurePolicyEvaluationDetails log categories are enabled.
- Network ACLs bypass Azure services by default. Set `network_default_action` to `"Deny"` and provide `allowed_ip_ranges` or `allowed_subnet_ids` for restricted access.
