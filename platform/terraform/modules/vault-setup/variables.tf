###############################################################################
# Variables — Vault Setup Module
###############################################################################

# -----------------------------------------------------------------------------
# Vault Connection
# -----------------------------------------------------------------------------

variable "vault_address" {
  description = "Address of the Vault server (e.g., https://vault.example.com:8200)"
  type        = string

  validation {
    condition     = can(regex("^https?://", var.vault_address))
    error_message = "Vault address must start with http:// or https://."
  }
}

variable "environment" {
  description = "Deployment environment name"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# KV v2 Engine
# -----------------------------------------------------------------------------

variable "kv_mount_path" {
  description = "Mount path for the KV v2 secrets engine"
  type        = string
  default     = "secret"
}

# -----------------------------------------------------------------------------
# Database Engine
# -----------------------------------------------------------------------------

variable "enable_database_engine" {
  description = "Whether to enable the database secrets engine"
  type        = bool
  default     = false
}

variable "database_mount_path" {
  description = "Mount path for the database secrets engine"
  type        = string
  default     = "database"
}

variable "database_default_lease_ttl" {
  description = "Default lease TTL for database credentials in seconds"
  type        = number
  default     = 3600
}

variable "database_max_lease_ttl" {
  description = "Maximum lease TTL for database credentials in seconds"
  type        = number
  default     = 86400
}

variable "database_connections" {
  description = "Map of database connections to configure"
  type = map(object({
    connection_url          = string
    username                = string
    password                = string
    allowed_roles           = list(string)
    max_open_connections    = optional(number, 5)
    max_idle_connections    = optional(number, 3)
    max_connection_lifetime = optional(string, "0s")
    verify_connection       = optional(bool, true)
  }))
  default   = {}
  sensitive = true
}

variable "database_roles" {
  description = "Map of database roles to configure"
  type = map(object({
    db_connection_name  = string
    creation_statements = list(string)
    default_ttl         = optional(number, 3600)
    max_ttl             = optional(number, 86400)
  }))
  default = {}
}

# -----------------------------------------------------------------------------
# PKI Engine
# -----------------------------------------------------------------------------

variable "enable_pki_engine" {
  description = "Whether to enable the PKI secrets engine (root + intermediate CA)"
  type        = bool
  default     = false
}

variable "pki_root_mount_path" {
  description = "Mount path for the root PKI CA"
  type        = string
  default     = "pki"
}

variable "pki_intermediate_mount_path" {
  description = "Mount path for the intermediate PKI CA"
  type        = string
  default     = "pki_int"
}

variable "pki_organization" {
  description = "Organization name for PKI certificates"
  type        = string
  default     = ""
}

variable "pki_country" {
  description = "Country code for PKI certificates (ISO 3166-1 alpha-2)"
  type        = string
  default     = "US"

  validation {
    condition     = can(regex("^[A-Z]{2}$", var.pki_country))
    error_message = "Country must be a 2-letter ISO 3166-1 alpha-2 code."
  }
}

variable "pki_province" {
  description = "State/province for PKI certificates"
  type        = string
  default     = ""
}

variable "pki_locality" {
  description = "City/locality for PKI certificates"
  type        = string
  default     = ""
}

variable "pki_domains" {
  description = "List of allowed domains for PKI certificate issuance"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# SSH Engine
# -----------------------------------------------------------------------------

variable "enable_ssh_engine" {
  description = "Whether to enable the SSH secrets engine"
  type        = bool
  default     = false
}

variable "ssh_mount_path" {
  description = "Mount path for the SSH secrets engine"
  type        = string
  default     = "ssh"
}

variable "ssh_default_user" {
  description = "Default SSH username for signed certificates"
  type        = string
  default     = "ubuntu"
}

# -----------------------------------------------------------------------------
# Transit Engine
# -----------------------------------------------------------------------------

variable "enable_transit_engine" {
  description = "Whether to enable the transit encryption engine"
  type        = bool
  default     = false
}

variable "transit_mount_path" {
  description = "Mount path for the transit secrets engine"
  type        = string
  default     = "transit"
}

variable "transit_keys" {
  description = "List of transit encryption key names to create"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# OIDC Auth (Human login)
# -----------------------------------------------------------------------------

variable "enable_oidc_auth" {
  description = "Whether to enable OIDC auth method for human users"
  type        = bool
  default     = false
}

variable "oidc_discovery_url" {
  description = "OIDC discovery URL (e.g., https://accounts.google.com or Keycloak realm URL)"
  type        = string
  default     = ""
}

variable "oidc_client_id" {
  description = "OIDC client ID for Vault"
  type        = string
  default     = ""
}

variable "oidc_client_secret" {
  description = "OIDC client secret for Vault"
  type        = string
  default     = ""
  sensitive   = true
}

variable "oidc_groups_claim" {
  description = "JWT claim to use for group membership"
  type        = string
  default     = "groups"
}

variable "oidc_allowed_redirect_uris" {
  description = "List of allowed redirect URIs for OIDC auth"
  type        = list(string)
  default     = []
}

variable "oidc_admin_bound_claims" {
  description = "Bound claims map for the OIDC admin role (e.g., group membership)"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# JWT Auth (GitHub Actions)
# -----------------------------------------------------------------------------

variable "enable_github_jwt_auth" {
  description = "Whether to enable JWT auth method for GitHub Actions OIDC"
  type        = bool
  default     = false
}

variable "github_org" {
  description = "GitHub organization name for JWT auth bound claims"
  type        = string
  default     = ""
}

variable "allowed_repos" {
  description = "List of GitHub repository names for JWT auth roles"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Kubernetes Auth
# -----------------------------------------------------------------------------

variable "enable_kubernetes_auth" {
  description = "Whether to enable Kubernetes auth method"
  type        = bool
  default     = false
}

variable "kubernetes_host" {
  description = "Kubernetes API server URL"
  type        = string
  default     = ""
}

variable "kubernetes_ca_cert" {
  description = "PEM-encoded CA certificate for the Kubernetes API server"
  type        = string
  default     = ""
  sensitive   = true
}

variable "kubernetes_roles" {
  description = "Map of Kubernetes auth roles to configure"
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
# Policies
# -----------------------------------------------------------------------------

variable "custom_policies" {
  description = "Map of custom Vault policy names to their HCL policy documents"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# Audit
# -----------------------------------------------------------------------------

variable "enable_audit_device" {
  description = "Whether to enable the file audit device"
  type        = bool
  default     = false
}

variable "audit_log_path" {
  description = "File path for the audit log"
  type        = string
  default     = "/vault/logs/audit.log"
}
