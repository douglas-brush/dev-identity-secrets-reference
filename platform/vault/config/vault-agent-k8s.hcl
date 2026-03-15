# Vault Agent — Kubernetes Sidecar Configuration
# Used as an init/sidecar container for secret delivery to pods.

auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role = "APP_ROLE_NAME"
    }
  }

  sink "file" {
    config = {
      path = "/home/vault/.vault-token"
      mode = 0600
    }
  }
}

cache {
  use_auto_auth_token = true
}

template {
  source      = "/vault/templates/app-secrets.ctmpl"
  destination = "/vault/secrets/app.env"
  perms       = "0600"
  command     = "pkill -HUP app || true"
}

template {
  source      = "/vault/templates/db-creds.ctmpl"
  destination = "/vault/secrets/db.env"
  perms       = "0600"
}
