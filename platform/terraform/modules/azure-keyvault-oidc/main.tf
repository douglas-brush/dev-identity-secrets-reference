###############################################################################
# Azure Key Vault + OIDC Module
# Provisions Key Vault, federated identity for GitHub Actions, managed identity,
# SOPS encryption key, and diagnostic settings for audit logging.
###############################################################################

data "azurerm_client_config" "current" {}

locals {
  common_tags = merge(var.tags, {
    Module      = "azure-keyvault-oidc"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# -----------------------------------------------------------------------------
# User-Assigned Managed Identity for GitHub Actions
# -----------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "github_actions" {
  name                = "${var.environment}-github-actions-identity"
  resource_group_name = var.resource_group_name
  location            = var.location

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Federated Identity Credentials for GitHub Actions OIDC
# -----------------------------------------------------------------------------

resource "azurerm_federated_identity_credential" "github_repos" {
  for_each = toset(var.allowed_repos)

  name                = "${var.environment}-github-${replace(each.key, "/", "-")}"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.github_actions.id

  audience = ["api://AzureADTokenExchange"]
  issuer   = "https://token.actions.githubusercontent.com"
  subject  = "repo:${var.github_org}/${each.key}:ref:refs/heads/${var.default_branch}"
}

resource "azurerm_federated_identity_credential" "github_repos_environment" {
  for_each = var.enable_environment_federation ? toset(var.allowed_repos) : toset([])

  name                = "${var.environment}-github-${replace(each.key, "/", "-")}-env"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.github_actions.id

  audience = ["api://AzureADTokenExchange"]
  issuer   = "https://token.actions.githubusercontent.com"
  subject  = "repo:${var.github_org}/${each.key}:environment:${var.environment}"
}

# -----------------------------------------------------------------------------
# Azure Key Vault
# -----------------------------------------------------------------------------

resource "azurerm_key_vault" "main" {
  name                = var.key_vault_name
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = var.key_vault_sku

  enabled_for_deployment          = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false
  enable_rbac_authorization       = true
  purge_protection_enabled        = var.enable_purge_protection
  soft_delete_retention_days      = var.soft_delete_retention_days
  public_network_access_enabled   = var.public_network_access_enabled

  network_acls {
    bypass                     = "AzureServices"
    default_action             = var.network_default_action
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }

  tags = local.common_tags

  lifecycle {
    prevent_destroy = false # Set to true in production
  }
}

# -----------------------------------------------------------------------------
# RBAC Role Assignments
# -----------------------------------------------------------------------------

# Terraform deployer gets admin access
resource "azurerm_role_assignment" "deployer_admin" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# GitHub Actions managed identity gets secrets read access
resource "azurerm_role_assignment" "github_actions_secrets" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = var.environment == "prod" ? "Key Vault Secrets User" : "Key Vault Secrets Officer"
  principal_id         = azurerm_user_assigned_identity.github_actions.principal_id
}

# GitHub Actions managed identity gets crypto access for SOPS
resource "azurerm_role_assignment" "github_actions_crypto" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.github_actions.principal_id
}

# Additional reader principals (operators, on-call, etc.)
resource "azurerm_role_assignment" "additional_readers" {
  for_each = toset(var.additional_reader_principal_ids)

  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = each.key
}

# -----------------------------------------------------------------------------
# Key Vault Key for SOPS Encryption
# -----------------------------------------------------------------------------

resource "azurerm_key_vault_key" "sops" {
  name         = "${var.environment}-sops-key"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "verify",
    "wrapKey",
    "unwrapKey",
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P365D"
    notify_before_expiry = "P30D"
  }

  tags = local.common_tags

  depends_on = [azurerm_role_assignment.deployer_admin]
}

# -----------------------------------------------------------------------------
# Diagnostic Settings for Audit Logging
# -----------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  count = var.log_analytics_workspace_id != "" ? 1 : 0

  name                       = "${var.environment}-keyvault-diagnostics"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "AuditEvent"
  }

  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "key_vault_storage" {
  count = var.diagnostics_storage_account_id != "" ? 1 : 0

  name               = "${var.environment}-keyvault-diagnostics-storage"
  target_resource_id = azurerm_key_vault.main.id
  storage_account_id = var.diagnostics_storage_account_id

  enabled_log {
    category = "AuditEvent"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
