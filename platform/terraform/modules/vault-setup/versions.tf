###############################################################################
# Provider Requirements — Vault Setup Module
###############################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 3.20, < 5.0"
    }
  }
}
