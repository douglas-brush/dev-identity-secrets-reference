###############################################################################
# Outputs — GCP Cloud KMS + Workload Identity Federation Module
###############################################################################

output "kms_key_ring_id" {
  description = "ID of the Cloud KMS key ring"
  value       = google_kms_key_ring.sops.id
}

output "kms_key_ring_name" {
  description = "Name of the Cloud KMS key ring"
  value       = google_kms_key_ring.sops.name
}

output "kms_key_id" {
  description = "ID of the Cloud KMS crypto key for SOPS"
  value       = google_kms_crypto_key.sops.id
}

output "kms_key_name" {
  description = "Name of the Cloud KMS crypto key for SOPS"
  value       = google_kms_crypto_key.sops.name
}

output "workload_identity_pool_id" {
  description = "ID of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.github.workload_identity_pool_id
}

output "workload_identity_pool_name" {
  description = "Full resource name of the Workload Identity Pool"
  value       = google_iam_workload_identity_pool.github.name
}

output "workload_identity_provider_id" {
  description = "ID of the Workload Identity Pool Provider"
  value       = google_iam_workload_identity_pool_provider.github.workload_identity_pool_provider_id
}

output "workload_identity_provider_name" {
  description = "Full resource name of the Workload Identity Pool Provider"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_email" {
  description = "Email address of the GitHub Actions service account"
  value       = google_service_account.github_actions.email
}

output "service_account_id" {
  description = "Fully qualified ID of the GitHub Actions service account"
  value       = google_service_account.github_actions.id
}

output "service_account_name" {
  description = "Full resource name of the GitHub Actions service account"
  value       = google_service_account.github_actions.name
}

output "secret_ids" {
  description = "Map of secret names to their Secret Manager secret IDs"
  value = {
    for name, secret in google_secret_manager_secret.app_secrets :
    name => secret.id
  }
}
