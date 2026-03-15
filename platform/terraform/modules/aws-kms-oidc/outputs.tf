###############################################################################
# Outputs — AWS KMS + OIDC Module
###############################################################################

output "kms_key_arn" {
  description = "ARN of the KMS key used for SOPS encryption"
  value       = aws_kms_key.sops.arn
}

output "kms_key_id" {
  description = "ID of the KMS key used for SOPS encryption"
  value       = aws_kms_key.sops.key_id
}

output "kms_key_alias_arn" {
  description = "ARN of the KMS key alias"
  value       = aws_kms_alias.sops.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub Actions OIDC identity provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "oidc_provider_url" {
  description = "URL of the GitHub Actions OIDC identity provider"
  value       = aws_iam_openid_connect_provider.github_actions.url
}

output "github_actions_role_arn" {
  description = "ARN of the IAM role for GitHub Actions to assume via OIDC"
  value       = aws_iam_role.github_actions.arn
}

output "github_actions_role_name" {
  description = "Name of the IAM role for GitHub Actions"
  value       = aws_iam_role.github_actions.name
}

output "vault_role_arn" {
  description = "ARN of the IAM role for Vault integration (empty if Vault OIDC is disabled)"
  value       = var.vault_oidc_enabled ? aws_iam_role.vault[0].arn : ""
}

output "secrets_manager_arns" {
  description = "Map of secret names to their Secrets Manager ARNs"
  value = {
    for name, secret in aws_secretsmanager_secret.app_secrets :
    name => secret.arn
  }
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for KMS audit logging"
  value       = aws_cloudwatch_log_group.audit.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for KMS audit logging"
  value       = aws_cloudwatch_log_group.audit.name
}
