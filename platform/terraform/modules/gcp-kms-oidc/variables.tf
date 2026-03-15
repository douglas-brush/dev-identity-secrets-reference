###############################################################################
# Variables — GCP Cloud KMS + Workload Identity Federation Module
###############################################################################

# -----------------------------------------------------------------------------
# Project Configuration
# -----------------------------------------------------------------------------

variable "project_id" {
  description = "GCP project ID"
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, start with a letter, and contain only lowercase letters, digits, and hyphens."
  }
}

variable "region" {
  description = "GCP region for resource deployment"
  type        = string
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "Region must be a valid GCP region format (e.g., us-central1)."
  }
}

# -----------------------------------------------------------------------------
# GitHub OIDC Configuration
# -----------------------------------------------------------------------------

variable "github_org" {
  description = "GitHub organization name for Workload Identity Federation attribute matching"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.github_org))
    error_message = "GitHub organization name must contain only alphanumeric characters and hyphens."
  }
}

variable "allowed_repos" {
  description = "List of GitHub repository names allowed to use Workload Identity Federation"
  type        = list(string)

  validation {
    condition     = length(var.allowed_repos) > 0
    error_message = "At least one repository must be specified."
  }
}

variable "default_branch" {
  description = "Default branch name used in attribute condition for branch restriction"
  type        = string
  default     = "main"
}

variable "restrict_to_branches" {
  description = "Whether to restrict WIF access to the default branch only"
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
# KMS Configuration
# -----------------------------------------------------------------------------

variable "key_ring_name" {
  description = "Name of the Cloud KMS key ring"
  type        = string
  default     = "sops-keyring"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.key_ring_name))
    error_message = "Key ring name must contain only alphanumeric characters, underscores, and hyphens."
  }
}

variable "crypto_key_name" {
  description = "Name of the Cloud KMS crypto key for SOPS"
  type        = string
  default     = "sops-key"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]+$", var.crypto_key_name))
    error_message = "Crypto key name must contain only alphanumeric characters, underscores, and hyphens."
  }
}

variable "key_rotation_period" {
  description = "Rotation period for the crypto key in seconds (e.g., 7776000s = 90 days)"
  type        = string
  default     = "7776000s"

  validation {
    condition     = can(regex("^[0-9]+s$", var.key_rotation_period))
    error_message = "Key rotation period must be specified in seconds (e.g., '7776000s')."
  }
}

variable "protection_level" {
  description = "Protection level for the crypto key (SOFTWARE or HSM)"
  type        = string
  default     = "SOFTWARE"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.protection_level)
    error_message = "Protection level must be either 'SOFTWARE' or 'HSM'."
  }
}

# -----------------------------------------------------------------------------
# Secret Manager
# -----------------------------------------------------------------------------

variable "enable_secret_manager" {
  description = "Whether to create Secret Manager resources"
  type        = bool
  default     = true
}

variable "secret_manager_secrets" {
  description = "List of secret names to create in Secret Manager (prefixed with environment)"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# API Management
# -----------------------------------------------------------------------------

variable "enable_apis" {
  description = "Whether to enable required GCP APIs (set false if already enabled)"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Audit Logging
# -----------------------------------------------------------------------------

variable "enable_audit_logging" {
  description = "Whether to enable data access audit logging for KMS and Secret Manager"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Labels
# -----------------------------------------------------------------------------

variable "labels" {
  description = "Additional labels to apply to all resources"
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k, v in var.labels : can(regex("^[a-z][a-z0-9_-]*$", k))])
    error_message = "Label keys must start with a lowercase letter and contain only lowercase letters, digits, underscores, and hyphens."
  }
}
