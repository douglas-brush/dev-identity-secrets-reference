# GCP Cloud KMS + Workload Identity Federation Module

Provisions a Cloud KMS key ring and crypto key for SOPS encryption, a Workload Identity Pool and OIDC Provider for GitHub Actions, a dedicated service account with WIF binding, Secret Manager secrets with KMS encryption, and data access audit logging. This module enables keyless CI/CD authentication from GitHub Actions to GCP using Workload Identity Federation.

## Usage

```hcl
module "gcp_kms_oidc" {
  source = "./modules/gcp-kms-oidc"

  project_id  = "my-project-id"
  region      = "us-central1"
  environment = "prod"

  github_org    = "my-org"
  allowed_repos = ["infra-repo", "app-repo"]

  key_ring_name    = "sops-keyring"
  crypto_key_name  = "sops-key"
  protection_level = "SOFTWARE"

  enable_secret_manager  = true
  secret_manager_secrets = ["db-password", "api-key"]

  enable_audit_logging = true

  labels = {
    project = "identity-reference"
  }
}
```

## Inputs

| Name | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `project_id` | `string` | n/a | yes | GCP project ID |
| `region` | `string` | `"us-central1"` | no | GCP region for resource deployment |
| `github_org` | `string` | n/a | yes | GitHub organization name for Workload Identity Federation attribute matching |
| `allowed_repos` | `list(string)` | n/a | yes | List of GitHub repository names allowed to use Workload Identity Federation |
| `default_branch` | `string` | `"main"` | no | Default branch name used in attribute condition for branch restriction |
| `restrict_to_branches` | `bool` | `true` | no | Whether to restrict WIF access to the default branch only |
| `environment` | `string` | n/a | yes | Deployment environment name (`dev`, `staging`, or `prod`) |
| `key_ring_name` | `string` | `"sops-keyring"` | no | Name of the Cloud KMS key ring |
| `crypto_key_name` | `string` | `"sops-key"` | no | Name of the Cloud KMS crypto key for SOPS |
| `key_rotation_period` | `string` | `"7776000s"` | no | Rotation period for the crypto key in seconds (e.g., `7776000s` = 90 days) |
| `protection_level` | `string` | `"SOFTWARE"` | no | Protection level for the crypto key (`SOFTWARE` or `HSM`) |
| `enable_secret_manager` | `bool` | `true` | no | Whether to create Secret Manager resources |
| `secret_manager_secrets` | `list(string)` | `[]` | no | List of secret names to create in Secret Manager (prefixed with environment) |
| `enable_apis` | `bool` | `true` | no | Whether to enable required GCP APIs (set false if already enabled) |
| `enable_audit_logging` | `bool` | `true` | no | Whether to enable data access audit logging for KMS and Secret Manager |
| `labels` | `map(string)` | `{}` | no | Additional labels to apply to all resources |

## Outputs

| Name | Description |
|------|-------------|
| `kms_key_ring_id` | ID of the Cloud KMS key ring |
| `kms_key_ring_name` | Name of the Cloud KMS key ring |
| `kms_key_id` | ID of the Cloud KMS crypto key for SOPS |
| `kms_key_name` | Name of the Cloud KMS crypto key for SOPS |
| `workload_identity_pool_id` | ID of the Workload Identity Pool |
| `workload_identity_pool_name` | Full resource name of the Workload Identity Pool |
| `workload_identity_provider_id` | ID of the Workload Identity Pool Provider |
| `workload_identity_provider_name` | Full resource name of the Workload Identity Pool Provider |
| `service_account_email` | Email address of the GitHub Actions service account |
| `service_account_id` | Fully qualified ID of the GitHub Actions service account |
| `service_account_name` | Full resource name of the GitHub Actions service account |
| `secret_ids` | Map of secret names to their Secret Manager secret IDs |

## Prerequisites

- Terraform >= 1.5.0
- Google provider >= 5.0, < 7.0
- A GCP project with billing enabled
- If `enable_apis` is false, the following APIs must be pre-enabled: Cloud KMS, IAM, IAM Credentials, Secret Manager, STS, Cloud Resource Manager
- Permissions to create KMS resources, Workload Identity Pools, service accounts, and Secret Manager secrets

## Notes on Integration

- The module automatically enables required GCP APIs when `enable_apis` is true. Set to false if APIs are managed separately.
- The WIF attribute condition restricts access by repository owner. When `restrict_to_branches` is true, access is further limited to the `default_branch`.
- The service account is bound to the Workload Identity Pool at the organization level (`attribute.repository_owner`), and granted `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the SOPS key.
- Secret Manager secrets are prefixed with the environment name and encrypted using the KMS crypto key via customer-managed encryption with automatic replication.
- When `enable_secret_manager` is true, the service account receives `roles/secretmanager.secretAccessor` scoped by an IAM condition to secrets matching the `{environment}-*` prefix.
- Audit logging covers `ADMIN_READ`, `DATA_READ`, and `DATA_WRITE` events for both Cloud KMS and Secret Manager services.
