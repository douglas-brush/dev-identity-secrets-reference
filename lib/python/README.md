# secrets-sdk

Python SDK for developer identity and secrets management. Typed wrappers for HashiCorp Vault, SOPS encryption, configuration validation, and secret rotation policy enforcement.

## Install

```bash
pip install -e ".[dev]"
```

## Quick Start

### Vault Client

```python
from secrets_sdk import VaultClient

client = VaultClient()  # reads VAULT_ADDR, VAULT_TOKEN from env
client.auth_token()

# KV v2
data = client.kv_read("dev/apps/myapp")
client.kv_write("dev/apps/myapp", {"api_key": "new-value"})

# Dynamic database credentials
lease = client.db_creds("dev-readonly")
print(lease.data["username"], lease.data["password"])

# Transit encrypt/decrypt
encrypted = client.transit_encrypt("my-key", "sensitive data")
decrypted = client.transit_decrypt("my-key", encrypted.ciphertext)

# PKI certificate issuance
cert = client.pki_issue("web-server", "app.example.com", ttl="720h")

# SSH certificate signing
ssh_cert = client.ssh_sign("dev-admin", public_key="ssh-rsa AAAA...")

# Health check
report = client.health()
print(report.summary())
```

### SOPS Helpers

```python
from secrets_sdk.sops import decrypt_file, encrypt_file, SopsConfig

data = decrypt_file("secrets/dev/app.enc.yaml")
encrypt_file("secrets/dev/app.enc.yaml", {"password": "rotated"})

config = SopsConfig.from_file(".sops.yaml")
print(config.has_cloud_kms())
```

### Config Validation

```python
from secrets_sdk.config import validate_repo_structure, scan_plaintext_secrets

issues = validate_repo_structure(".")
findings = scan_plaintext_secrets("src/")
```

### CLI

```bash
secrets-sdk doctor --root .
secrets-sdk vault-health
secrets-sdk scan ./src
secrets-sdk rotate-check --path dev/apps/myapp --max-age 90
secrets-sdk decrypt secrets/dev/app.enc.yaml
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```
