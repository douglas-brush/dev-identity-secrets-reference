###############################################################################
# Dev Environment — Terraform Configuration
# Wires up AWS, Azure, GCP, and Vault modules for the dev environment.
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  # Uncomment and configure for your backend:
  # backend "s3" {
  #   bucket         = "my-terraform-state"
  #   key            = "dev/identity-secrets/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 6.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80, < 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0, < 7.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = ">= 3.20, < 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Provider Configuration
# -----------------------------------------------------------------------------

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "dev-identity-secrets"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true  # dev only — set false in prod
      recover_soft_deleted_key_vaults = true
    }
  }
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "vault" {
  address = var.vault_address
  # Auth configured via VAULT_TOKEN or VAULT_ADDR env vars
}

# -----------------------------------------------------------------------------
# Local Values
# -----------------------------------------------------------------------------

locals {
  environment = "dev"
  github_org  = var.github_org

  common_tags = {
    Project     = "dev-identity-secrets"
    Environment = local.environment
    ManagedBy   = "terraform"
  }
}

# -----------------------------------------------------------------------------
# AWS Module
# -----------------------------------------------------------------------------

module "aws_kms_oidc" {
  source = "../../modules/aws-kms-oidc"

  environment     = local.environment
  github_org      = local.github_org
  allowed_repos   = var.allowed_repos
  allowed_branches = ["main", "develop"]

  kms_key_alias       = "dev-sops-key"
  kms_deletion_window = 7 # Shorter window for dev

  vault_oidc_enabled = var.enable_vault

  secrets_manager_secrets = var.aws_secrets

  cloudwatch_log_retention_days = 30 # Shorter retention for dev
  enable_cloudtrail             = false

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Azure Module
# -----------------------------------------------------------------------------

module "azure_keyvault_oidc" {
  source = "../../modules/azure-keyvault-oidc"

  environment         = local.environment
  resource_group_name = var.azure_resource_group_name
  location            = var.azure_location

  github_org    = local.github_org
  allowed_repos = var.allowed_repos

  key_vault_name          = var.azure_key_vault_name
  key_vault_sku           = "standard"
  enable_purge_protection = false # Disable for dev to allow teardown
  soft_delete_retention_days = 7

  public_network_access_enabled = true
  network_default_action        = "Allow"

  log_analytics_workspace_id = var.azure_log_analytics_workspace_id

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# GCP Module
# -----------------------------------------------------------------------------

module "gcp_kms_oidc" {
  source = "../../modules/gcp-kms-oidc"

  environment = local.environment
  project_id  = var.gcp_project_id
  region      = var.gcp_region

  github_org           = local.github_org
  allowed_repos        = var.allowed_repos
  restrict_to_branches = false # More permissive for dev

  key_ring_name    = "dev-sops-keyring"
  crypto_key_name  = "dev-sops-key"
  protection_level = "SOFTWARE"

  enable_secret_manager  = true
  secret_manager_secrets = var.gcp_secrets

  enable_audit_logging = true
  enable_apis          = var.gcp_enable_apis

  labels = local.common_tags
}

# -----------------------------------------------------------------------------
# Vault Module
# -----------------------------------------------------------------------------

module "vault_setup" {
  count  = var.enable_vault ? 1 : 0
  source = "../../modules/vault-setup"

  vault_address = var.vault_address
  environment   = local.environment

  # KV v2
  kv_mount_path = "secret"

  # Database engine — disabled by default in dev
  enable_database_engine = var.vault_enable_database

  # PKI engine
  enable_pki_engine  = var.vault_enable_pki
  pki_organization   = var.pki_organization
  pki_domains        = var.pki_domains
  pki_country        = "US"

  # SSH engine
  enable_ssh_engine = var.vault_enable_ssh
  ssh_default_user  = "ubuntu"

  # Transit engine
  enable_transit_engine = var.vault_enable_transit
  transit_keys          = ["app-encryption", "backup-encryption"]

  # OIDC auth — human login
  enable_oidc_auth           = var.vault_enable_oidc
  oidc_discovery_url         = var.oidc_discovery_url
  oidc_client_id             = var.oidc_client_id
  oidc_client_secret         = var.oidc_client_secret
  oidc_allowed_redirect_uris = var.oidc_allowed_redirect_uris

  # GitHub Actions JWT auth
  enable_github_jwt_auth = true
  github_org             = local.github_org
  allowed_repos          = var.allowed_repos

  # Kubernetes auth
  enable_kubernetes_auth = var.vault_enable_kubernetes
  kubernetes_host        = var.kubernetes_host
  kubernetes_ca_cert     = var.kubernetes_ca_cert
  kubernetes_roles       = var.kubernetes_roles

  # Audit
  enable_audit_device = false # Disable file audit in dev
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

variable "allowed_repos" {
  description = "List of GitHub repos allowed to authenticate"
  type        = list(string)
}

variable "aws_secrets" {
  description = "List of AWS Secrets Manager secret names to create"
  type        = list(string)
  default     = []
}

variable "azure_resource_group_name" {
  description = "Azure resource group name"
  type        = string
}

variable "azure_location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "azure_key_vault_name" {
  description = "Azure Key Vault name (globally unique)"
  type        = string
}

variable "azure_log_analytics_workspace_id" {
  description = "Azure Log Analytics workspace ID for diagnostics"
  type        = string
  default     = ""
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gcp_secrets" {
  description = "List of GCP Secret Manager secret names to create"
  type        = list(string)
  default     = []
}

variable "gcp_enable_apis" {
  description = "Whether to enable required GCP APIs"
  type        = bool
  default     = true
}

variable "enable_vault" {
  description = "Whether to deploy the Vault setup module"
  type        = bool
  default     = false
}

variable "vault_address" {
  description = "Vault server address"
  type        = string
  default     = "https://vault.example.com:8200"
}

variable "vault_enable_database" {
  description = "Enable Vault database secrets engine"
  type        = bool
  default     = false
}

variable "vault_enable_pki" {
  description = "Enable Vault PKI secrets engine"
  type        = bool
  default     = false
}

variable "vault_enable_ssh" {
  description = "Enable Vault SSH secrets engine"
  type        = bool
  default     = false
}

variable "vault_enable_transit" {
  description = "Enable Vault transit secrets engine"
  type        = bool
  default     = false
}

variable "vault_enable_oidc" {
  description = "Enable Vault OIDC auth for human login"
  type        = bool
  default     = false
}

variable "vault_enable_kubernetes" {
  description = "Enable Vault Kubernetes auth"
  type        = bool
  default     = false
}

variable "oidc_discovery_url" {
  description = "OIDC discovery URL for Vault auth"
  type        = string
  default     = ""
}

variable "oidc_client_id" {
  description = "OIDC client ID for Vault auth"
  type        = string
  default     = ""
}

variable "oidc_client_secret" {
  description = "OIDC client secret for Vault auth"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_allowed_redirect_uris" {
  description = "OIDC allowed redirect URIs for Vault auth"
  type        = list(string)
  default     = []
}

variable "pki_organization" {
  description = "Organization name for PKI certificates"
  type        = string
  default     = "Example Corp"
}

variable "pki_domains" {
  description = "Allowed domains for PKI certificate issuance"
  type        = list(string)
  default     = ["example.com"]
}

variable "kubernetes_host" {
  description = "Kubernetes API server URL"
  type        = string
  default     = ""
}

variable "kubernetes_ca_cert" {
  description = "Kubernetes CA certificate (PEM)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "kubernetes_roles" {
  description = "Kubernetes auth roles for Vault"
  type = map(object({
    service_account_names = list(string)
    namespaces            = list(string)
    policies              = list(string)
    token_ttl             = optional(number, 3600)
    token_max_ttl         = optional(number, 86400)
    audience              = optional(string, "")
  }))
  default = {}
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "aws_kms_key_arn" {
  description = "AWS KMS key ARN for SOPS"
  value       = module.aws_kms_oidc.kms_key_arn
}

output "aws_github_actions_role_arn" {
  description = "AWS IAM role ARN for GitHub Actions"
  value       = module.aws_kms_oidc.github_actions_role_arn
}

output "azure_key_vault_uri" {
  description = "Azure Key Vault URI"
  value       = module.azure_keyvault_oidc.key_vault_uri
}

output "azure_managed_identity_client_id" {
  description = "Azure managed identity client ID for GitHub Actions"
  value       = module.azure_keyvault_oidc.managed_identity_client_id
}

output "azure_sops_key_url" {
  description = "Azure Key Vault key URL for SOPS"
  value       = module.azure_keyvault_oidc.sops_key_url
}

output "gcp_kms_key_id" {
  description = "GCP KMS crypto key ID for SOPS"
  value       = module.gcp_kms_oidc.kms_key_id
}

output "gcp_workload_identity_provider" {
  description = "GCP Workload Identity provider name for GitHub Actions"
  value       = module.gcp_kms_oidc.workload_identity_provider_name
}

output "gcp_service_account_email" {
  description = "GCP service account email for GitHub Actions"
  value       = module.gcp_kms_oidc.service_account_email
}

output "vault_kv_path" {
  description = "Vault KV v2 mount path"
  value       = var.enable_vault ? module.vault_setup[0].kv_mount_path : ""
}

output "vault_policy_names" {
  description = "Vault policy names"
  value       = var.enable_vault ? module.vault_setup[0].policy_names : {}
}
