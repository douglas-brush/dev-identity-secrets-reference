# Vault Agent configuration for local development.
# Auto-authenticates via AppRole, renews tokens, and templates secrets.

pid_file = "/tmp/vault/agent.pid"

vault {
  address = "http://vault:8200"
}

# ── Auto-Auth: AppRole ──────────────────────────────────────────────
auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/tmp/vault/role-id"
      secret_id_file_path = "/tmp/vault/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault/agent-token"
      mode = 0640
    }
  }
}

# ── API Proxy ───────────────────────────────────────────────────────
# Applications can reach Vault through the agent at :8100
# without managing their own tokens.
api_proxy {
  use_auto_auth_token = true
}

listener "tcp" {
  address     = "0.0.0.0:8100"
  tls_disable = true
}

# ── Template: KV Application Config ────────────────────────────────
template {
  source      = "/tmp/vault/templates/app-config.ctmpl"
  destination = "/tmp/secrets/app-config.json"
  perms       = "0640"
  error_on_missing_key = false
  exec {
    command = ["sh", "-c", "echo '[vault-agent] Rendered app-config.json'"]
  }
}

# ── Template: Database Credentials ──────────────────────────────────
template {
  contents    = <<-EOT
    {{- with secret "database/creds/dev-demo-app" }}
    {
      "db_host": "postgres",
      "db_port": 5432,
      "db_name": "demo",
      "db_user": "{{ .Data.username }}",
      "db_pass": "{{ .Data.password }}",
      "lease_id": "{{ .LeaseID }}",
      "lease_duration": {{ .LeaseDuration }},
      "renewable": {{ .Renewable }}
    }
    {{- end }}
  EOT
  destination = "/tmp/secrets/db-creds.json"
  perms       = "0640"
  error_on_missing_key = false
}

# ── Template: PKI Certificate Bundle ───────────────────────────────
template {
  contents    = <<-EOT
    {{- with pkiCert "pki_int/issue/dev-services"
        "common_name=vault-agent.dev.local"
        "alt_names=vault-agent.svc.local,localhost"
        "ip_sans=127.0.0.1"
        "ttl=24h" }}
    {{ .Cert }}
    {{ .CA }}
    {{- end }}
  EOT
  destination = "/tmp/secrets/tls-cert.pem"
  perms       = "0644"
  error_on_missing_key = false
}

template {
  contents    = <<-EOT
    {{- with pkiCert "pki_int/issue/dev-services"
        "common_name=vault-agent.dev.local"
        "alt_names=vault-agent.svc.local,localhost"
        "ip_sans=127.0.0.1"
        "ttl=24h" }}
    {{ .Key }}
    {{- end }}
  EOT
  destination = "/tmp/secrets/tls-key.pem"
  perms       = "0600"
  error_on_missing_key = false
}

# ── Template: Environment file ──────────────────────────────────────
template {
  contents    = <<-EOT
    {{- with secret "kv/data/dev/apps/demo-app/config" }}
    DB_HOST={{ .Data.data.db_host }}
    DB_PORT={{ .Data.data.db_port }}
    DB_NAME={{ .Data.data.db_name }}
    API_KEY={{ .Data.data.api_key }}
    {{- end }}
    {{- with secret "database/creds/dev-demo-app" }}
    DB_USER={{ .Data.username }}
    DB_PASS={{ .Data.password }}
    {{- end }}
  EOT
  destination = "/tmp/secrets/app.env"
  perms       = "0640"
  error_on_missing_key = false
}
