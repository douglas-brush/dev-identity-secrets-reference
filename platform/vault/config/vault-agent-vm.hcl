# Vault Agent — VM Configuration
# Runs as a systemd service on VMs for secret delivery.

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/etc/vault-agent/role-id"
      secret_id_file_path                 = "/etc/vault-agent/secret-id"
      remove_secret_id_file_after_reading = true
    }
  }

  sink "file" {
    config = {
      path = "/run/vault/.vault-token"
      mode = 0600
    }
  }
}

cache {
  use_auto_auth_token = true
}

template {
  source      = "/etc/vault-agent/templates/app-secrets.ctmpl"
  destination = "/run/app/secrets.env"
  perms       = "0600"
  command     = "systemctl reload app.service || true"

  error_on_missing_key = true

  wait {
    min = "5s"
    max = "30s"
  }
}

template {
  source      = "/etc/vault-agent/templates/db-creds.ctmpl"
  destination = "/run/app/db.env"
  perms       = "0600"
}
