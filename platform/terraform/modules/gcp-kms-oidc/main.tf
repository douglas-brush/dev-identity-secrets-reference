###############################################################################
# GCP Cloud KMS + Workload Identity Federation Module
# Provisions KMS key ring/key for SOPS, Workload Identity Pool/Provider for
# GitHub Actions, service account with WIF binding, and Secret Manager.
###############################################################################

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  common_labels = merge(var.labels, {
    module      = "gcp-kms-oidc"
    environment = var.environment
    managed-by  = "terraform"
  })

  # Attribute condition for WIF — restricts to specific repos
  repo_conditions = join(" || ", [
    for repo in var.allowed_repos :
    "assertion.repository == '${var.github_org}/${repo}'"
  ])

  attribute_condition = var.restrict_to_branches ? join(" && ", compact([
    "(${local.repo_conditions})",
    "assertion.ref == 'refs/heads/${var.default_branch}'",
  ])) : "(${local.repo_conditions})"
}

# -----------------------------------------------------------------------------
# Enable required APIs
# -----------------------------------------------------------------------------

resource "google_project_service" "apis" {
  for_each = toset(var.enable_apis ? [
    "cloudkms.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "secretmanager.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ] : [])

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# Cloud KMS Key Ring and Crypto Key for SOPS
# -----------------------------------------------------------------------------

resource "google_kms_key_ring" "sops" {
  name     = var.key_ring_name
  location = var.region
  project  = var.project_id

  depends_on = [google_project_service.apis]
}

resource "google_kms_crypto_key" "sops" {
  name     = var.crypto_key_name
  key_ring = google_kms_key_ring.sops.id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = var.key_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.protection_level
  }

  labels = local.common_labels

  lifecycle {
    prevent_destroy = false # Set to true in production
  }
}

# -----------------------------------------------------------------------------
# Workload Identity Pool
# -----------------------------------------------------------------------------

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "${var.environment}-github-pool"
  display_name              = "GitHub Actions Pool (${var.environment})"
  description               = "Workload Identity Pool for GitHub Actions OIDC in ${var.environment}"
  disabled                  = false

  depends_on = [google_project_service.apis]
}

# -----------------------------------------------------------------------------
# Workload Identity Pool Provider (OIDC)
# -----------------------------------------------------------------------------

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "${var.environment}-github-oidc"
  display_name                       = "GitHub OIDC Provider (${var.environment})"
  description                        = "OIDC provider for GitHub Actions"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.actor"            = "assertion.actor"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
    "attribute.ref"              = "assertion.ref"
    "attribute.environment"      = "assertion.environment"
  }

  attribute_condition = local.attribute_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# -----------------------------------------------------------------------------
# Service Account for GitHub Actions
# -----------------------------------------------------------------------------

resource "google_service_account" "github_actions" {
  project      = var.project_id
  account_id   = "${var.environment}-github-actions"
  display_name = "GitHub Actions Service Account (${var.environment})"
  description  = "Service account used by GitHub Actions via Workload Identity Federation"
}

# Bind the service account to the Workload Identity Pool
resource "google_service_account_iam_member" "wif_binding" {
  service_account_id = google_service_account.github_actions.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_owner/${var.github_org}"
}

# Grant KMS encrypt/decrypt to the service account
resource "google_kms_crypto_key_iam_member" "github_actions_sops" {
  crypto_key_id = google_kms_crypto_key.sops.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.github_actions.email}"
}

# Grant Secret Manager access to the service account
resource "google_project_iam_member" "github_actions_secret_accessor" {
  count = var.enable_secret_manager ? 1 : 0

  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.github_actions.email}"

  condition {
    title       = "restrict-to-environment-secrets"
    description = "Only allow access to secrets with the environment label"
    expression  = "resource.name.startsWith('projects/${var.project_id}/secrets/${var.environment}-')"
  }
}

# -----------------------------------------------------------------------------
# Secret Manager Resources
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "app_secrets" {
  for_each = var.enable_secret_manager ? toset(var.secret_manager_secrets) : toset([])

  project   = var.project_id
  secret_id = "${var.environment}-${each.key}"

  labels = local.common_labels

  replication {
    auto {
      customer_managed_encryption {
        kms_key_name = google_kms_crypto_key.sops.id
      }
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_iam_member" "github_actions" {
  for_each = var.enable_secret_manager ? toset(var.secret_manager_secrets) : toset([])

  project   = var.project_id
  secret_id = google_secret_manager_secret.app_secrets[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.github_actions.email}"
}

# -----------------------------------------------------------------------------
# Audit Logging Configuration
# -----------------------------------------------------------------------------

resource "google_project_iam_audit_config" "kms_audit" {
  count = var.enable_audit_logging ? 1 : 0

  project = var.project_id
  service = "cloudkms.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

resource "google_project_iam_audit_config" "secretmanager_audit" {
  count = var.enable_audit_logging && var.enable_secret_manager ? 1 : 0

  project = var.project_id
  service = "secretmanager.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
