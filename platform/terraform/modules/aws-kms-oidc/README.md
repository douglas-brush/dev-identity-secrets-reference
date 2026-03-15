# AWS KMS + OIDC Module

Provisions AWS KMS for SOPS encryption, a GitHub Actions OIDC identity provider, federated IAM roles, Secrets Manager secrets, and CloudWatch/CloudTrail audit logging. This module enables keyless CI/CD authentication from GitHub Actions to AWS using OpenID Connect federation.

## Usage

```hcl
module "aws_kms_oidc" {
  source = "./modules/aws-kms-oidc"

  github_org       = "my-org"
  allowed_repos    = ["infra-repo", "app-repo"]
  allowed_branches = ["main"]
  environment      = "prod"
  kms_key_alias    = "sops-key"

  secrets_manager_secrets = ["db-password", "api-key"]

  enable_cloudtrail              = true
  cloudtrail_s3_bucket           = "my-cloudtrail-bucket"
  cloudtrail_cloudwatch_role_arn = "arn:aws:iam::123456789012:role/cloudtrail-cw"

  vault_oidc_enabled    = true
  vault_server_role_arn = "arn:aws:iam::123456789012:role/vault-server"
  vault_external_id     = "vault-external-id"

  tags = {
    Project = "identity-reference"
  }
}
```

## Inputs

| Name | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `github_org` | `string` | n/a | yes | GitHub organization name for OIDC subject claim matching |
| `allowed_repos` | `list(string)` | n/a | yes | List of GitHub repository names allowed to assume the IAM role |
| `allowed_branches` | `list(string)` | `["main"]` | no | List of branch names allowed to assume the IAM role (used in OIDC subject claim) |
| `github_oidc_thumbprints` | `list(string)` | `["6938fd..."]` | no | TLS certificate thumbprints for the GitHub OIDC provider |
| `environment` | `string` | n/a | yes | Deployment environment name (`dev`, `staging`, or `prod`) |
| `kms_key_alias` | `string` | `"sops-key"` | no | Alias name for the KMS key (without the `alias/` prefix) |
| `kms_deletion_window` | `number` | `30` | no | Number of days before KMS key is deleted after scheduled deletion (7-30) |
| `vault_oidc_enabled` | `bool` | `false` | no | Whether to create IAM resources for Vault AWS secrets engine integration |
| `vault_server_role_arn` | `string` | `""` | no | ARN of the IAM role/user that Vault uses to assume the Vault integration role |
| `vault_external_id` | `string` | `""` | no | External ID for the Vault STS AssumeRole condition (sensitive) |
| `secrets_manager_secrets` | `list(string)` | `[]` | no | List of secret names to create in Secrets Manager under the environment prefix |
| `cloudwatch_log_retention_days` | `number` | `90` | no | Number of days to retain CloudWatch logs |
| `enable_cloudtrail` | `bool` | `false` | no | Whether to enable CloudTrail for KMS key audit logging |
| `cloudtrail_s3_bucket` | `string` | `""` | no | S3 bucket name for CloudTrail logs (required if `enable_cloudtrail` is true) |
| `cloudtrail_cloudwatch_role_arn` | `string` | `""` | no | IAM role ARN for CloudTrail to write to CloudWatch Logs (required if `enable_cloudtrail` is true) |
| `max_session_duration` | `number` | `3600` | no | Maximum session duration in seconds for the GitHub Actions IAM role (900-43200) |
| `tags` | `map(string)` | `{}` | no | Additional tags to apply to all resources |

## Outputs

| Name | Description |
|------|-------------|
| `kms_key_arn` | ARN of the KMS key used for SOPS encryption |
| `kms_key_id` | ID of the KMS key used for SOPS encryption |
| `kms_key_alias_arn` | ARN of the KMS key alias |
| `oidc_provider_arn` | ARN of the GitHub Actions OIDC identity provider |
| `oidc_provider_url` | URL of the GitHub Actions OIDC identity provider |
| `github_actions_role_arn` | ARN of the IAM role for GitHub Actions to assume via OIDC |
| `github_actions_role_name` | Name of the IAM role for GitHub Actions |
| `vault_role_arn` | ARN of the IAM role for Vault integration (empty if Vault OIDC is disabled) |
| `secrets_manager_arns` | Map of secret names to their Secrets Manager ARNs |
| `cloudwatch_log_group_arn` | ARN of the CloudWatch log group for KMS audit logging |
| `cloudwatch_log_group_name` | Name of the CloudWatch log group for KMS audit logging |

## Prerequisites

- Terraform >= 1.5.0
- AWS provider >= 5.0, < 6.0
- An AWS account with permissions to create KMS keys, IAM roles/policies, OIDC providers, Secrets Manager secrets, CloudWatch log groups, and optionally CloudTrail trails
- If `enable_cloudtrail` is true, an existing S3 bucket and IAM role for CloudTrail must be provided

## Notes on Integration

- The OIDC trust policy restricts token exchange to the specified `github_org`, `allowed_repos`, and `allowed_branches` combinations. Wildcard subjects are generated per-repo for flexible matching.
- KMS key rotation is enabled by default. All Secrets Manager secrets are encrypted with the provisioned KMS key.
- Secrets Manager recovery window is automatically set to 30 days for `prod` and 7 days for other environments.
- When `vault_oidc_enabled` is true, an additional IAM role is created that allows Vault to manage IAM users and access keys scoped to the `vault-*` prefix.
- CloudTrail, when enabled, tracks all KMS data events (encrypt/decrypt) for the SOPS key and writes to both S3 and CloudWatch Logs.
- All resources are tagged with `Module`, `Environment`, and `ManagedBy` labels merged with any custom `tags` provided.
