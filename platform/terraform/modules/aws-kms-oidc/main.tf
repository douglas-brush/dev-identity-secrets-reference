###############################################################################
# AWS KMS + OIDC Module
# Provisions KMS for SOPS, GitHub Actions OIDC, IAM roles, Secrets Manager,
# and CloudWatch audit logging.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition

  # Build subject claim conditions for OIDC trust
  oidc_subjects = flatten([
    for repo in var.allowed_repos : [
      for branch in var.allowed_branches :
      "repo:${var.github_org}/${repo}:ref:refs/heads/${branch}"
    ]
  ])

  oidc_subjects_wildcard = [
    for repo in var.allowed_repos :
    "repo:${var.github_org}/${repo}:*"
  ]

  common_tags = merge(var.tags, {
    Module      = "aws-kms-oidc"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# -----------------------------------------------------------------------------
# KMS Key for SOPS encryption
# -----------------------------------------------------------------------------

resource "aws_kms_key" "sops" {
  description             = "SOPS encryption key for ${var.environment} environment"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = true
  is_enabled              = true

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "sops-key-policy"
    Statement = [
      {
        Sid    = "EnableRootAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowGitHubActionsEncryptDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.github_actions.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowKeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
        ]
        Resource = "*"
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "sops" {
  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.sops.key_id
}

# -----------------------------------------------------------------------------
# GitHub Actions OIDC Identity Provider
# -----------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.github_oidc_thumbprints

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# IAM Role for GitHub Actions (OIDC federated)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "github_actions" {
  name        = "${var.environment}-github-actions-oidc"
  description = "IAM role assumed by GitHub Actions via OIDC for ${var.environment}"
  path        = "/ci/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubOIDC"
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = local.oidc_subjects
          }
        }
      },
    ]
  })

  max_session_duration = var.max_session_duration

  tags = local.common_tags
}

resource "aws_iam_role_policy" "github_actions_kms" {
  name = "sops-kms-access"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSOPSOperations"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
        ]
        Resource = [aws_kms_key.sops.arn]
      },
    ]
  })
}

resource "aws_iam_role_policy" "github_actions_secrets_manager" {
  name = "secrets-manager-access"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecretsRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds",
        ]
        Resource = [
          "arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret:${var.environment}/*"
        ]
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# IAM Role for Vault integration (optional)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "vault" {
  count = var.vault_oidc_enabled ? 1 : 0

  name        = "${var.environment}-vault-integration"
  description = "IAM role for Vault AWS secrets engine in ${var.environment}"
  path        = "/vault/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowVaultAssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.vault_server_role_arn
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.vault_external_id
          }
        }
      },
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "vault_secrets" {
  count = var.vault_oidc_enabled ? 1 : 0

  name = "vault-secrets-engine"
  role = aws_iam_role.vault[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowVaultIAMOperations"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys",
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:ListGroupsForUser",
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup",
        ]
        Resource = [
          "arn:${local.partition}:iam::${local.account_id}:user/vault-*"
        ]
      },
      {
        Sid    = "AllowSTSOperations"
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# Secrets Manager
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "app_secrets" {
  for_each = toset(var.secrets_manager_secrets)

  name        = "${var.environment}/${each.key}"
  description = "Application secret: ${each.key} for ${var.environment}"
  kms_key_id  = aws_kms_key.sops.arn

  recovery_window_in_days = var.environment == "prod" ? 30 : 7

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_policy" "app_secrets" {
  for_each = toset(var.secrets_manager_secrets)

  secret_arn = aws_secretsmanager_secret.app_secrets[each.key].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGitHubActionsRead"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.github_actions.arn
        }
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyUnencryptedAccess"
        Effect = "Deny"
        Principal = "*"
        Action   = "secretsmanager:*"
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "kms:ViaService" = "secretsmanager.${local.region}.amazonaws.com"
          }
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group for audit
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/kms/${var.environment}/sops-audit"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = aws_kms_key.sops.arn

  tags = local.common_tags
}

resource "aws_cloudtrail" "kms_audit" {
  count = var.enable_cloudtrail ? 1 : 0

  name                       = "${var.environment}-kms-sops-audit"
  s3_bucket_name             = var.cloudtrail_s3_bucket
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.audit.arn}:*"
  cloud_watch_logs_role_arn  = var.cloudtrail_cloudwatch_role_arn
  enable_logging             = true
  is_multi_region_trail      = false
  enable_log_file_validation = true

  event_selector {
    read_write_type           = "All"
    include_management_events = false

    data_resource {
      type   = "AWS::KMS::Key"
      values = [aws_kms_key.sops.arn]
    }
  }

  tags = local.common_tags
}
