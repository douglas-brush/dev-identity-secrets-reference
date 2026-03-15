# Vault Setup Module

Configures a complete HashiCorp Vault deployment including secrets engines (KV v2, Database, PKI, SSH, Transit), auth methods (OIDC, JWT/GitHub Actions, Kubernetes), scoped policies, and file-based audit logging. This module provides a production-ready Vault configuration for multi-environment secrets management.

## Usage

```hcl
module "vault_setup" {
  source = "./modules/vault-setup"

  vault_address = "https://vault.example.com:8200"
  environment   = "prod"
  kv_mount_path = "secret"

  # Database secrets engine
  enable_database_engine = true
  database_connections = {
    app-db = {
      connection_url = "postgresql://{{username}}:{{password}}@db.example.com:5432/appdb"
      username       = "vault_admin"
      password       = "initial-password"
      allowed_roles  = ["app-readonly", "app-readwrite"]
    }
  }
  database_roles = {
    app-readonly = {
      db_connection_name  = "app-db"
      creation_statements = ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"]
    }
  }

  # PKI engine
  enable_pki_engine = true
  pki_organization  = "My Organization"
  pki_domains       = ["example.com", "internal.example.com"]

  # GitHub Actions JWT auth
  enable_github_jwt_auth = true
  github_org             = "my-org"
  allowed_repos          = ["infra-repo", "app-repo"]

  # OIDC auth for humans
  enable_oidc_auth            = true
  oidc_discovery_url          = "https://auth.example.com/realms/main"
  oidc_client_id              = "vault"
  oidc_client_secret          = "client-secret"
  oidc_allowed_redirect_uris  = ["https://vault.example.com:8200/ui/vault/auth/oidc/oidc/callback"]

  # Kubernetes auth
  enable_kubernetes_auth = true
  kubernetes_host        = "https://kubernetes.default.svc"
  kubernetes_roles = {
    web-app = {
      service_account_names = ["web-app"]
      namespaces            = ["production"]
      policies              = ["secrets-reader", "github-actions-prod"]
    }
  }

  # Audit
  enable_audit_device = true
  audit_log_path      = "/vault/logs/audit.log"
}
```

## Inputs

| Name | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `vault_address` | `string` | n/a | yes | Address of the Vault server (e.g., `https://vault.example.com:8200`) |
| `environment` | `string` | n/a | yes | Deployment environment name (`dev`, `staging`, or `prod`) |
| `kv_mount_path` | `string` | `"secret"` | no | Mount path for the KV v2 secrets engine |
| `enable_database_engine` | `bool` | `false` | no | Whether to enable the database secrets engine |
| `database_mount_path` | `string` | `"database"` | no | Mount path for the database secrets engine |
| `database_default_lease_ttl` | `number` | `3600` | no | Default lease TTL for database credentials in seconds |
| `database_max_lease_ttl` | `number` | `86400` | no | Maximum lease TTL for database credentials in seconds |
| `database_connections` | `map(object({...}))` | `{}` | no | Map of database connections to configure (sensitive; see object schema below) |
| `database_roles` | `map(object({...}))` | `{}` | no | Map of database roles to configure (see object schema below) |
| `enable_pki_engine` | `bool` | `false` | no | Whether to enable the PKI secrets engine (root + intermediate CA) |
| `pki_root_mount_path` | `string` | `"pki"` | no | Mount path for the root PKI CA |
| `pki_intermediate_mount_path` | `string` | `"pki_int"` | no | Mount path for the intermediate PKI CA |
| `pki_organization` | `string` | `""` | no | Organization name for PKI certificates |
| `pki_country` | `string` | `"US"` | no | Country code for PKI certificates (ISO 3166-1 alpha-2) |
| `pki_province` | `string` | `""` | no | State/province for PKI certificates |
| `pki_locality` | `string` | `""` | no | City/locality for PKI certificates |
| `pki_domains` | `list(string)` | `[]` | no | List of allowed domains for PKI certificate issuance |
| `enable_ssh_engine` | `bool` | `false` | no | Whether to enable the SSH secrets engine |
| `ssh_mount_path` | `string` | `"ssh"` | no | Mount path for the SSH secrets engine |
| `ssh_default_user` | `string` | `"ubuntu"` | no | Default SSH username for signed certificates |
| `enable_transit_engine` | `bool` | `false` | no | Whether to enable the transit encryption engine |
| `transit_mount_path` | `string` | `"transit"` | no | Mount path for the transit secrets engine |
| `transit_keys` | `list(string)` | `[]` | no | List of transit encryption key names to create |
| `enable_oidc_auth` | `bool` | `false` | no | Whether to enable OIDC auth method for human users |
| `oidc_discovery_url` | `string` | `""` | no | OIDC discovery URL (e.g., Keycloak realm URL) |
| `oidc_client_id` | `string` | `""` | no | OIDC client ID for Vault |
| `oidc_client_secret` | `string` | `""` | no | OIDC client secret for Vault (sensitive) |
| `oidc_groups_claim` | `string` | `"groups"` | no | JWT claim to use for group membership |
| `oidc_allowed_redirect_uris` | `list(string)` | `[]` | no | List of allowed redirect URIs for OIDC auth |
| `oidc_admin_bound_claims` | `map(string)` | `{}` | no | Bound claims map for the OIDC admin role |
| `enable_github_jwt_auth` | `bool` | `false` | no | Whether to enable JWT auth method for GitHub Actions OIDC |
| `github_org` | `string` | `""` | no | GitHub organization name for JWT auth bound claims |
| `allowed_repos` | `list(string)` | `[]` | no | List of GitHub repository names for JWT auth roles |
| `enable_kubernetes_auth` | `bool` | `false` | no | Whether to enable Kubernetes auth method |
| `kubernetes_host` | `string` | `""` | no | Kubernetes API server URL |
| `kubernetes_ca_cert` | `string` | `""` | no | PEM-encoded CA certificate for the Kubernetes API server (sensitive) |
| `kubernetes_roles` | `map(object({...}))` | `{}` | no | Map of Kubernetes auth roles to configure (see object schema below) |
| `custom_policies` | `map(string)` | `{}` | no | Map of custom Vault policy names to their HCL policy documents |
| `enable_audit_device` | `bool` | `false` | no | Whether to enable the file audit device |
| `audit_log_path` | `string` | `"/vault/logs/audit.log"` | no | File path for the audit log |

### Complex Object Schemas

**`database_connections`** values:
```hcl
{
  connection_url          = string           # PostgreSQL connection URL with {{username}}/{{password}} templates
  username                = string           # Admin username for Vault to manage credentials
  password                = string           # Admin password (sensitive)
  allowed_roles           = list(string)     # Roles allowed to use this connection
  max_open_connections    = optional(number)  # Default: 5
  max_idle_connections    = optional(number)  # Default: 3
  max_connection_lifetime = optional(string)  # Default: "0s"
  verify_connection       = optional(bool)    # Default: true
}
```

**`database_roles`** values:
```hcl
{
  db_connection_name  = string           # Name of the database connection
  creation_statements = list(string)     # SQL statements to create the role
  default_ttl         = optional(number) # Default: 3600
  max_ttl             = optional(number) # Default: 86400
}
```

**`kubernetes_roles`** values:
```hcl
{
  service_account_names = list(string)     # Kubernetes service account names
  namespaces            = list(string)     # Allowed namespaces
  policies              = list(string)     # Vault policies to attach
  token_ttl             = optional(number) # Default: 3600
  token_max_ttl         = optional(number) # Default: 86400
  audience              = optional(string) # Default: ""
}
```

## Outputs

| Name | Description |
|------|-------------|
| `kv_mount_path` | Mount path of the KV v2 secrets engine |
| `database_mount_path` | Mount path of the database secrets engine (empty if disabled) |
| `pki_root_mount_path` | Mount path of the root PKI CA (empty if disabled) |
| `pki_intermediate_mount_path` | Mount path of the intermediate PKI CA (empty if disabled) |
| `ssh_mount_path` | Mount path of the SSH secrets engine (empty if disabled) |
| `transit_mount_path` | Mount path of the transit secrets engine (empty if disabled) |
| `policy_names` | Map of all created policy names |
| `oidc_auth_path` | Path of the OIDC auth method (empty if disabled) |
| `github_jwt_auth_path` | Path of the GitHub Actions JWT auth method (empty if disabled) |
| `kubernetes_auth_path` | Path of the Kubernetes auth method (empty if disabled) |
| `oidc_role_names` | List of OIDC auth role names |
| `github_actions_role_names` | Map of GitHub repo names to their JWT auth role names |
| `kubernetes_role_names` | Map of Kubernetes auth role names |
| `pki_root_ca_certificate` | PEM-encoded root CA certificate (sensitive; empty if PKI disabled) |
| `pki_intermediate_ca_certificate` | PEM-encoded intermediate CA certificate (sensitive; empty if PKI disabled) |
| `ssh_ca_public_key` | SSH CA public key for client verification (empty if SSH disabled) |

## Prerequisites

- Terraform >= 1.5.0
- Vault provider >= 3.20, < 5.0
- A running, unsealed Vault server with a valid token configured in the provider
- For database engine: network connectivity from Vault to the target PostgreSQL databases
- For PKI engine: the `pki_organization` variable must be set
- For Kubernetes auth: the Vault server must be able to reach the Kubernetes API, and the CA cert must be provided
- For OIDC auth: a pre-configured OIDC client in your identity provider (e.g., Keycloak, Okta, Google)

## Notes on Integration

- The KV v2 engine is always created. All other engines (database, PKI, SSH, transit) are opt-in via `enable_*` variables.
- Built-in policies are scoped per environment: `secrets-reader` and `secrets-writer` grant access under `{kv_mount_path}/data/{environment}/*`. The `github-actions-{environment}` policy conditionally includes database, PKI, and transit paths based on which engines are enabled.
- OIDC auth creates two roles: `default` (with `secrets-reader` policy, 8h max TTL) and `admin` (with `admin` policy, 4h max TTL, restricted by `oidc_admin_bound_claims`).
- GitHub Actions JWT auth creates one role per repository in `allowed_repos`, bound to `{github_org}/{repo}` with 15-minute default TTL and 1-hour max TTL.
- PKI creates a two-tier CA hierarchy (10-year root, 5-year intermediate) with a `server-certs` role allowing subdomain issuance for configured `pki_domains` (30-day max, 7-day default TTL).
- SSH engine generates a signing CA key pair and creates a `default` role with 30-minute TTL for user certificates.
- Transit keys use AES-256-GCM96 with 90-day auto-rotation. Deletion is only allowed in non-prod environments.
- The audit device writes JSON-formatted logs. Raw request/response data is not logged (`log_raw = false`).
