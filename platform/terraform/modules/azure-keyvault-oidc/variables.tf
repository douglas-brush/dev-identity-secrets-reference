###############################################################################
# Variables — Azure Key Vault + OIDC Module
###############################################################################

# -----------------------------------------------------------------------------
# Resource Location
# -----------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Name of the Azure resource group to deploy into"
  type        = string

  validation {
    condition     = length(var.resource_group_name) > 0
    error_message = "Resource group name must not be empty."
  }
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string

  validation {
    condition     = length(var.location) > 0
    error_message = "Location must not be empty."
  }
}

# -----------------------------------------------------------------------------
# GitHub OIDC Configuration
# -----------------------------------------------------------------------------

variable "github_org" {
  description = "GitHub organization name for federated identity subject matching"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.github_org))
    error_message = "GitHub organization name must contain only alphanumeric characters and hyphens."
  }
}

variable "allowed_repos" {
  description = "List of GitHub repository names to create federated identity credentials for"
  type        = list(string)

  validation {
    condition     = length(var.allowed_repos) > 0
    error_message = "At least one repository must be specified."
  }
}

variable "default_branch" {
  description = "Default branch name used in federated identity subject claims"
  type        = string
  default     = "main"
}

variable "enable_environment_federation" {
  description = "Whether to create additional federated credentials for GitHub environment-based deployments"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment name"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# Key Vault Configuration
# -----------------------------------------------------------------------------

variable "key_vault_name" {
  description = "Name of the Azure Key Vault (must be globally unique, 3-24 characters)"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.key_vault_name))
    error_message = "Key Vault name must be 3-24 characters, start with a letter, end with a letter or digit, and contain only alphanumeric characters and hyphens."
  }
}

variable "key_vault_sku" {
  description = "SKU of the Key Vault (standard or premium). Premium required for HSM-backed keys."
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "premium"], var.key_vault_sku)
    error_message = "Key Vault SKU must be either 'standard' or 'premium'."
  }
}

variable "enable_purge_protection" {
  description = "Whether to enable purge protection on the Key Vault (recommended for production)"
  type        = bool
  default     = true
}

variable "soft_delete_retention_days" {
  description = "Number of days to retain soft-deleted Key Vault objects (7-90)"
  type        = number
  default     = 90

  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "Soft delete retention must be between 7 and 90 days."
  }
}

# -----------------------------------------------------------------------------
# Network Configuration
# -----------------------------------------------------------------------------

variable "public_network_access_enabled" {
  description = "Whether public network access is enabled for the Key Vault"
  type        = bool
  default     = true
}

variable "network_default_action" {
  description = "Default network action for Key Vault firewall (Allow or Deny)"
  type        = string
  default     = "Allow"

  validation {
    condition     = contains(["Allow", "Deny"], var.network_default_action)
    error_message = "Network default action must be 'Allow' or 'Deny'."
  }
}

variable "allowed_ip_ranges" {
  description = "List of IP ranges allowed to access the Key Vault"
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "List of subnet IDs allowed to access the Key Vault"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# RBAC
# -----------------------------------------------------------------------------

variable "additional_reader_principal_ids" {
  description = "List of Azure AD principal IDs to grant Key Vault Secrets User role"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Diagnostics
# -----------------------------------------------------------------------------

variable "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace for diagnostic settings (empty to skip)"
  type        = string
  default     = ""
}

variable "diagnostics_storage_account_id" {
  description = "ID of the storage account for diagnostic log archival (empty to skip)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Tags
# -----------------------------------------------------------------------------

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
