###############################################################################
# Vault Setup Module
# Configures secrets engines, auth methods, policies, and roles for a
# complete HashiCorp Vault deployment.
###############################################################################

# -----------------------------------------------------------------------------
# KV v2 Secrets Engine
# -----------------------------------------------------------------------------

resource "vault_mount" "kv" {
  path        = var.kv_mount_path
  type        = "kv-v2"
  description = "KV v2 secrets engine for ${var.environment} environment"

  options = {
    version = "2"
  }
}

# -----------------------------------------------------------------------------
# Database Secrets Engine
# -----------------------------------------------------------------------------

resource "vault_mount" "database" {
  count = var.enable_database_engine ? 1 : 0

  path                      = var.database_mount_path
  type                      = "database"
  description               = "Database secrets engine for ${var.environment}"
  default_lease_ttl_seconds = var.database_default_lease_ttl
  max_lease_ttl_seconds     = var.database_max_lease_ttl
}

resource "vault_database_secret_backend_connection" "postgres" {
  for_each = var.enable_database_engine ? var.database_connections : {}

  backend       = vault_mount.database[0].path
  name          = each.key
  allowed_roles = each.value.allowed_roles

  postgresql {
    connection_url          = each.value.connection_url
    max_open_connections    = each.value.max_open_connections
    max_idle_connections    = each.value.max_idle_connections
    max_connection_lifetime = each.value.max_connection_lifetime
    username                = each.value.username
    password                = each.value.password
  }

  verify_connection = each.value.verify_connection
}

resource "vault_database_secret_backend_role" "postgres" {
  for_each = var.enable_database_engine ? var.database_roles : {}

  backend             = vault_mount.database[0].path
  name                = each.key
  db_name             = each.value.db_connection_name
  creation_statements = each.value.creation_statements
  default_ttl         = each.value.default_ttl
  max_ttl             = each.value.max_ttl

  depends_on = [vault_database_secret_backend_connection.postgres]
}

# -----------------------------------------------------------------------------
# PKI Secrets Engine — Root CA
# -----------------------------------------------------------------------------

resource "vault_mount" "pki_root" {
  count = var.enable_pki_engine ? 1 : 0

  path                      = var.pki_root_mount_path
  type                      = "pki"
  description               = "Root PKI CA for ${var.environment}"
  default_lease_ttl_seconds = 86400      # 1 day
  max_lease_ttl_seconds     = 315360000  # 10 years
}

resource "vault_pki_secret_backend_root_cert" "root" {
  count = var.enable_pki_engine ? 1 : 0

  backend     = vault_mount.pki_root[0].path
  type        = "internal"
  common_name = "${var.pki_organization} Root CA"
  ttl         = "315360000" # 10 years
  format      = "pem"

  organization = var.pki_organization
  ou           = "Infrastructure"
  country      = var.pki_country
  province     = var.pki_province
  locality     = var.pki_locality

  key_type = "rsa"
  key_bits = 4096
}

resource "vault_pki_secret_backend_config_urls" "root" {
  count = var.enable_pki_engine ? 1 : 0

  backend = vault_mount.pki_root[0].path
  issuing_certificates = [
    "${var.vault_address}/v1/${vault_mount.pki_root[0].path}/ca",
  ]
  crl_distribution_points = [
    "${var.vault_address}/v1/${vault_mount.pki_root[0].path}/crl",
  ]
}

# -----------------------------------------------------------------------------
# PKI Secrets Engine — Intermediate CA
# -----------------------------------------------------------------------------

resource "vault_mount" "pki_intermediate" {
  count = var.enable_pki_engine ? 1 : 0

  path                      = var.pki_intermediate_mount_path
  type                      = "pki"
  description               = "Intermediate PKI CA for ${var.environment}"
  default_lease_ttl_seconds = 86400     # 1 day
  max_lease_ttl_seconds     = 157680000 # 5 years
}

resource "vault_pki_secret_backend_intermediate_cert_request" "intermediate" {
  count = var.enable_pki_engine ? 1 : 0

  backend     = vault_mount.pki_intermediate[0].path
  type        = "internal"
  common_name = "${var.pki_organization} Intermediate CA"

  key_type = "rsa"
  key_bits = 4096
}

resource "vault_pki_secret_backend_root_sign_intermediate" "intermediate" {
  count = var.enable_pki_engine ? 1 : 0

  backend     = vault_mount.pki_root[0].path
  csr         = vault_pki_secret_backend_intermediate_cert_request.intermediate[0].csr
  common_name = "${var.pki_organization} Intermediate CA"
  ttl         = "157680000" # 5 years
  format      = "pem_bundle"

  organization = var.pki_organization
  ou           = "Infrastructure"
  country      = var.pki_country
  province     = var.pki_province
  locality     = var.pki_locality
}

resource "vault_pki_secret_backend_intermediate_set_signed" "intermediate" {
  count = var.enable_pki_engine ? 1 : 0

  backend     = vault_mount.pki_intermediate[0].path
  certificate = vault_pki_secret_backend_root_sign_intermediate.intermediate[0].certificate
}

resource "vault_pki_secret_backend_config_urls" "intermediate" {
  count = var.enable_pki_engine ? 1 : 0

  backend = vault_mount.pki_intermediate[0].path
  issuing_certificates = [
    "${var.vault_address}/v1/${vault_mount.pki_intermediate[0].path}/ca",
  ]
  crl_distribution_points = [
    "${var.vault_address}/v1/${vault_mount.pki_intermediate[0].path}/crl",
  ]
}

resource "vault_pki_secret_backend_role" "server_certs" {
  count = var.enable_pki_engine ? 1 : 0

  backend          = vault_mount.pki_intermediate[0].path
  name             = "server-certs"
  allowed_domains  = var.pki_domains
  allow_subdomains = true
  allow_glob_domains = false
  allow_bare_domains = false
  allow_ip_sans    = true
  server_flag      = true
  client_flag      = false
  max_ttl          = "2592000" # 30 days
  ttl              = "604800"  # 7 days

  key_type  = "rsa"
  key_bits  = 2048
  key_usage = ["DigitalSignature", "KeyEncipherment"]

  organization = [var.pki_organization]
  country      = [var.pki_country]

  no_store = false

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.intermediate]
}

# -----------------------------------------------------------------------------
# SSH Secrets Engine
# -----------------------------------------------------------------------------

resource "vault_mount" "ssh" {
  count = var.enable_ssh_engine ? 1 : 0

  path                      = var.ssh_mount_path
  type                      = "ssh"
  description               = "SSH signed certificates engine for ${var.environment}"
  default_lease_ttl_seconds = 3600  # 1 hour
  max_lease_ttl_seconds     = 86400 # 1 day
}

resource "vault_ssh_secret_backend_ca" "ssh" {
  count = var.enable_ssh_engine ? 1 : 0

  backend              = vault_mount.ssh[0].path
  generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "default" {
  count = var.enable_ssh_engine ? 1 : 0

  backend                 = vault_mount.ssh[0].path
  name                    = "default"
  key_type                = "ca"
  allow_user_certificates = true
  allowed_users           = "*"
  default_user            = var.ssh_default_user
  ttl                     = "1800"  # 30 minutes
  max_ttl                 = "86400" # 1 day

  default_extensions = {
    permit-pty = ""
  }

  allowed_extensions = "permit-pty,permit-port-forwarding"
}

# -----------------------------------------------------------------------------
# Transit Secrets Engine
# -----------------------------------------------------------------------------

resource "vault_mount" "transit" {
  count = var.enable_transit_engine ? 1 : 0

  path        = var.transit_mount_path
  type        = "transit"
  description = "Transit encryption engine for ${var.environment}"
}

resource "vault_transit_secret_backend_key" "encryption" {
  for_each = var.enable_transit_engine ? toset(var.transit_keys) : toset([])

  backend          = vault_mount.transit[0].path
  name             = each.key
  type             = "aes256-gcm96"
  deletion_allowed = var.environment != "prod"
  exportable       = false

  auto_rotate_period = 7776000 # 90 days in seconds
}

# -----------------------------------------------------------------------------
# Auth Method — OIDC (Human login)
# -----------------------------------------------------------------------------

resource "vault_jwt_auth_backend" "oidc" {
  count = var.enable_oidc_auth ? 1 : 0

  path               = "oidc"
  type               = "oidc"
  description        = "OIDC auth for human users"
  oidc_discovery_url = var.oidc_discovery_url
  oidc_client_id     = var.oidc_client_id
  oidc_client_secret = var.oidc_client_secret
  default_role       = "default"

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "8h"
    token_type        = "default-service"
  }
}

resource "vault_jwt_auth_backend_role" "oidc_default" {
  count = var.enable_oidc_auth ? 1 : 0

  backend        = vault_jwt_auth_backend.oidc[0].path
  role_name      = "default"
  role_type      = "oidc"
  token_policies = ["default", "secrets-reader"]

  user_claim            = "email"
  groups_claim          = var.oidc_groups_claim
  allowed_redirect_uris = var.oidc_allowed_redirect_uris
  oidc_scopes           = ["openid", "profile", "email"]

  token_ttl     = 3600  # 1 hour
  token_max_ttl = 28800 # 8 hours
}

resource "vault_jwt_auth_backend_role" "oidc_admin" {
  count = var.enable_oidc_auth ? 1 : 0

  backend        = vault_jwt_auth_backend.oidc[0].path
  role_name      = "admin"
  role_type      = "oidc"
  token_policies = ["default", "admin"]

  user_claim            = "email"
  groups_claim          = var.oidc_groups_claim
  bound_claims          = var.oidc_admin_bound_claims
  allowed_redirect_uris = var.oidc_allowed_redirect_uris
  oidc_scopes           = ["openid", "profile", "email", "groups"]

  token_ttl     = 3600  # 1 hour
  token_max_ttl = 14400 # 4 hours
}

# -----------------------------------------------------------------------------
# Auth Method — JWT (GitHub Actions)
# -----------------------------------------------------------------------------

resource "vault_jwt_auth_backend" "github_actions" {
  count = var.enable_github_jwt_auth ? 1 : 0

  path               = "jwt/github"
  type               = "jwt"
  description        = "JWT auth for GitHub Actions OIDC"
  oidc_discovery_url = "https://token.actions.githubusercontent.com"
  bound_issuer       = "https://token.actions.githubusercontent.com"

  tune {
    default_lease_ttl = "15m"
    max_lease_ttl     = "1h"
    token_type        = "default-service"
  }
}

resource "vault_jwt_auth_backend_role" "github_actions" {
  for_each = var.enable_github_jwt_auth ? { for repo in var.allowed_repos : repo => repo } : {}

  backend        = vault_jwt_auth_backend.github_actions[0].path
  role_name      = replace(each.key, "/", "-")
  role_type      = "jwt"
  token_policies = ["default", "github-actions-${var.environment}"]

  user_claim = "repository"

  bound_claims = {
    repository = "${var.github_org}/${each.key}"
  }

  bound_audiences = ["https://github.com/${var.github_org}"]
  claim_mappings = {
    repository   = "repository"
    actor        = "actor"
    ref          = "ref"
    workflow     = "workflow"
    environment  = "environment"
    run_id       = "run_id"
  }

  token_ttl     = 900  # 15 minutes
  token_max_ttl = 3600 # 1 hour
}

# -----------------------------------------------------------------------------
# Auth Method — Kubernetes
# -----------------------------------------------------------------------------

resource "vault_auth_backend" "kubernetes" {
  count = var.enable_kubernetes_auth ? 1 : 0

  type        = "kubernetes"
  path        = "kubernetes"
  description = "Kubernetes auth for ${var.environment}"

  tune {
    default_lease_ttl = "1h"
    max_lease_ttl     = "24h"
    token_type        = "default-service"
  }
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  count = var.enable_kubernetes_auth ? 1 : 0

  backend            = vault_auth_backend.kubernetes[0].path
  kubernetes_host    = var.kubernetes_host
  kubernetes_ca_cert = var.kubernetes_ca_cert
}

resource "vault_kubernetes_auth_backend_role" "app" {
  for_each = var.enable_kubernetes_auth ? var.kubernetes_roles : {}

  backend                          = vault_auth_backend.kubernetes[0].path
  role_name                        = each.key
  bound_service_account_names      = each.value.service_account_names
  bound_service_account_namespaces = each.value.namespaces
  token_policies                   = each.value.policies
  token_ttl                        = each.value.token_ttl
  token_max_ttl                    = each.value.token_max_ttl
  audience                         = each.value.audience
}

# -----------------------------------------------------------------------------
# Policies
# -----------------------------------------------------------------------------

resource "vault_policy" "admin" {
  name   = "admin"
  policy = <<-EOT
    # Full admin policy
    path "*" {
      capabilities = ["create", "read", "update", "delete", "list", "sudo"]
    }
  EOT
}

resource "vault_policy" "secrets_reader" {
  name   = "secrets-reader"
  policy = <<-EOT
    # Read-only access to KV secrets for the environment
    path "${var.kv_mount_path}/data/${var.environment}/*" {
      capabilities = ["read", "list"]
    }

    path "${var.kv_mount_path}/metadata/${var.environment}/*" {
      capabilities = ["read", "list"]
    }

    # Allow listing mounts
    path "sys/mounts" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_policy" "secrets_writer" {
  name   = "secrets-writer"
  policy = <<-EOT
    # Read-write access to KV secrets for the environment
    path "${var.kv_mount_path}/data/${var.environment}/*" {
      capabilities = ["create", "read", "update", "delete", "list"]
    }

    path "${var.kv_mount_path}/metadata/${var.environment}/*" {
      capabilities = ["read", "list", "delete"]
    }

    path "${var.kv_mount_path}/delete/${var.environment}/*" {
      capabilities = ["update"]
    }

    path "${var.kv_mount_path}/undelete/${var.environment}/*" {
      capabilities = ["update"]
    }

    path "sys/mounts" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_policy" "github_actions" {
  name   = "github-actions-${var.environment}"
  policy = <<-EOT
    # GitHub Actions CI/CD policy for ${var.environment}

    # Read secrets from KV
    path "${var.kv_mount_path}/data/${var.environment}/*" {
      capabilities = ["read", "list"]
    }

    path "${var.kv_mount_path}/metadata/${var.environment}/*" {
      capabilities = ["read", "list"]
    }

    # Request database credentials
    ${var.enable_database_engine ? "path \"${var.database_mount_path}/creds/*\" {\n      capabilities = [\"read\"]\n    }" : "# Database engine disabled"}

    # Request PKI certificates
    ${var.enable_pki_engine ? "path \"${var.pki_intermediate_mount_path}/issue/server-certs\" {\n      capabilities = [\"create\", \"update\"]\n    }" : "# PKI engine disabled"}

    # Use transit for encryption/decryption
    ${var.enable_transit_engine ? "path \"${var.transit_mount_path}/encrypt/*\" {\n      capabilities = [\"update\"]\n    }\n\n    path \"${var.transit_mount_path}/decrypt/*\" {\n      capabilities = [\"update\"]\n    }" : "# Transit engine disabled"}

    # Renew and revoke own tokens
    path "auth/token/renew-self" {
      capabilities = ["update"]
    }

    path "auth/token/revoke-self" {
      capabilities = ["update"]
    }

    # Lookup own token
    path "auth/token/lookup-self" {
      capabilities = ["read"]
    }
  EOT
}

resource "vault_policy" "kubernetes_app" {
  count = var.enable_kubernetes_auth ? 1 : 0

  name   = "kubernetes-app-${var.environment}"
  policy = <<-EOT
    # Kubernetes application policy for ${var.environment}

    # Read secrets
    path "${var.kv_mount_path}/data/${var.environment}/*" {
      capabilities = ["read"]
    }

    # Request database credentials
    ${var.enable_database_engine ? "path \"${var.database_mount_path}/creds/*\" {\n      capabilities = [\"read\"]\n    }" : "# Database engine disabled"}

    # Request PKI certificates
    ${var.enable_pki_engine ? "path \"${var.pki_intermediate_mount_path}/issue/server-certs\" {\n      capabilities = [\"create\", \"update\"]\n    }" : "# PKI engine disabled"}

    # SSH signed keys
    ${var.enable_ssh_engine ? "path \"${var.ssh_mount_path}/sign/default\" {\n      capabilities = [\"create\", \"update\"]\n    }" : "# SSH engine disabled"}

    # Transit operations
    ${var.enable_transit_engine ? "path \"${var.transit_mount_path}/encrypt/*\" {\n      capabilities = [\"update\"]\n    }\n\n    path \"${var.transit_mount_path}/decrypt/*\" {\n      capabilities = [\"update\"]\n    }" : "# Transit engine disabled"}

    # Token self-management
    path "auth/token/renew-self" {
      capabilities = ["update"]
    }

    path "auth/token/lookup-self" {
      capabilities = ["read"]
    }
  EOT
}

# Custom policies from variable
resource "vault_policy" "custom" {
  for_each = var.custom_policies

  name   = each.key
  policy = each.value
}

# -----------------------------------------------------------------------------
# Audit Device
# -----------------------------------------------------------------------------

resource "vault_audit" "file" {
  count = var.enable_audit_device ? 1 : 0

  type = "file"

  options = {
    file_path = var.audit_log_path
    format    = "json"
    log_raw   = false
  }
}
