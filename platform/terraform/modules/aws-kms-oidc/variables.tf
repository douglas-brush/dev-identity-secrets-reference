###############################################################################
# Variables — AWS KMS + OIDC Module
###############################################################################

# -----------------------------------------------------------------------------
# GitHub OIDC Configuration
# -----------------------------------------------------------------------------

variable "github_org" {
  description = "GitHub organization name for OIDC subject claim matching"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+$", var.github_org))
    error_message = "GitHub organization name must contain only alphanumeric characters and hyphens."
  }
}

variable "allowed_repos" {
  description = "List of GitHub repository names allowed to assume the IAM role"
  type        = list(string)

  validation {
    condition     = length(var.allowed_repos) > 0
    error_message = "At least one repository must be specified."
  }

  validation {
    condition     = alltrue([for r in var.allowed_repos : can(regex("^[a-zA-Z0-9._-]+$", r))])
    error_message = "Repository names must contain only alphanumeric characters, dots, underscores, and hyphens."
  }
}

variable "allowed_branches" {
  description = "List of branch names allowed to assume the IAM role (used in OIDC subject claim)"
  type        = list(string)
  default     = ["main"]

  validation {
    condition     = length(var.allowed_branches) > 0
    error_message = "At least one branch must be specified."
  }
}

variable "github_oidc_thumbprints" {
  description = "TLS certificate thumbprints for the GitHub OIDC provider. GitHub's current thumbprint is included by default."
  type        = list(string)
  default     = ["6938fd4d98bab03faadb97b34396831e3780aea1"]

  validation {
    condition     = length(var.github_oidc_thumbprints) > 0
    error_message = "At least one thumbprint must be provided."
  }
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

variable "kms_key_alias" {
  description = "Alias name for the KMS key (without the alias/ prefix)"
  type        = string
  default     = "sops-key"

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]+$", var.kms_key_alias))
    error_message = "KMS key alias must contain only alphanumeric characters, forward slashes, underscores, and hyphens."
  }
}

variable "kms_deletion_window" {
  description = "Number of days before KMS key is deleted after scheduled deletion (7-30)"
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window >= 7 && var.kms_deletion_window <= 30
    error_message = "KMS deletion window must be between 7 and 30 days."
  }
}

# -----------------------------------------------------------------------------
# Vault Integration (optional)
# -----------------------------------------------------------------------------

variable "vault_oidc_enabled" {
  description = "Whether to create IAM resources for Vault AWS secrets engine integration"
  type        = bool
  default     = false
}

variable "vault_server_role_arn" {
  description = "ARN of the IAM role/user that Vault uses to assume the Vault integration role"
  type        = string
  default     = ""

  validation {
    condition     = var.vault_server_role_arn == "" || can(regex("^arn:aws:iam::", var.vault_server_role_arn))
    error_message = "Vault server role ARN must be a valid IAM ARN."
  }
}

variable "vault_external_id" {
  description = "External ID for the Vault STS AssumeRole condition"
  type        = string
  default     = ""
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Secrets Manager
# -----------------------------------------------------------------------------

variable "secrets_manager_secrets" {
  description = "List of secret names to create in Secrets Manager under the environment prefix"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# CloudWatch / CloudTrail
# -----------------------------------------------------------------------------

variable "cloudwatch_log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.cloudwatch_log_retention_days)
    error_message = "CloudWatch log retention must be a valid retention period."
  }
}

variable "enable_cloudtrail" {
  description = "Whether to enable CloudTrail for KMS key audit logging"
  type        = bool
  default     = false
}

variable "cloudtrail_s3_bucket" {
  description = "S3 bucket name for CloudTrail logs (required if enable_cloudtrail is true)"
  type        = string
  default     = ""
}

variable "cloudtrail_cloudwatch_role_arn" {
  description = "IAM role ARN for CloudTrail to write to CloudWatch Logs (required if enable_cloudtrail is true)"
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# IAM
# -----------------------------------------------------------------------------

variable "max_session_duration" {
  description = "Maximum session duration (in seconds) for the GitHub Actions IAM role"
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 900 && var.max_session_duration <= 43200
    error_message = "Max session duration must be between 900 and 43200 seconds."
  }
}

# -----------------------------------------------------------------------------
# Tags
# -----------------------------------------------------------------------------

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
