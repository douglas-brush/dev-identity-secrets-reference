# secrets-sdk

Python SDK for developer identity and secrets management. Typed wrappers for HashiCorp Vault, SOPS encryption, configuration validation, secret rotation policy enforcement, and SIRM (Security Incident Response Management).

## Installation

```bash
# From the lib/python directory
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Quick Start

### Vault Client

```python
from secrets_sdk import VaultClient

client = VaultClient()  # reads VAULT_ADDR, VAULT_TOKEN from env
client.auth_token()

# KV v2 read/write
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

### Config Validation and Secret Scanning

```python
from secrets_sdk.config import validate_repo_structure, scan_plaintext_secrets

issues = validate_repo_structure(".")
findings = scan_plaintext_secrets("src/")
```

### Rotation Policy

```python
from secrets_sdk import VaultClient
from secrets_sdk.rotation import check_secret_age, check_secrets_batch

client = VaultClient()
client.auth_token()

report = check_secret_age(client, "dev/apps/myapp", max_age_days=90)
print(report.needs_rotation, report.age_days)

reports = check_secrets_batch(client, ["dev/apps/a", "dev/apps/b"])
```

### SIRM (Security Incident Response Management)

```python
from secrets_sdk.sirm import SIRMSession, SIRMBootstrap, SessionReport

# Bootstrap a new incident response session
bootstrap = SIRMBootstrap(operator="analyst", session_dir="./sessions")
session = bootstrap.bootstrap()

# Or create a session directly
session = SIRMSession.create(operator="analyst", session_dir="./sessions")
session.activate()

# Add timeline events, evidence, findings
session.save()

# Generate reports
report = SessionReport(session=session)
print(report.to_markdown())
print(report.to_json())

# Seal for tamper evidence
session.close(reason="Investigation complete")
seal_hash = session.seal()
assert session.verify_seal()
```

## CLI Usage

All commands support `--help` for detailed options.

### Repository Health Check

```bash
secrets-sdk doctor --root .
secrets-sdk doctor --root . --json-output
```

### Vault Health

```bash
secrets-sdk vault-health
secrets-sdk vault-health --addr http://vault:8200 --json-output
```

### Secret Scanning

```bash
secrets-sdk scan ./src
secrets-sdk scan ./src --pattern "AWS Access Key" --json-output
```

### Rotation Check

```bash
secrets-sdk rotate-check --path dev/apps/myapp --max-age 90
secrets-sdk rotate-check --path dev/apps/a --path dev/apps/b --json-output
```

### SOPS Decrypt

```bash
secrets-sdk decrypt secrets/dev/app.enc.yaml
secrets-sdk decrypt secrets/dev/app.enc.yaml --output-format yaml
```

### SIRM Commands

```bash
# Initialize a new incident response session
secrets-sdk sirm-init --operator analyst --session-dir ./sessions --repo-root .
secrets-sdk sirm-init --operator analyst --classification SECRET --json-output

# Check session status
secrets-sdk sirm-status ./sessions/session-*.json
secrets-sdk sirm-status ./sessions/session-*.json --json-output

# Seal a session with tamper-evidence hash
secrets-sdk sirm-seal ./sessions/session-*.json --reason "Investigation complete"

# Generate session report
secrets-sdk sirm-report ./sessions/session-*.json
secrets-sdk sirm-report ./sessions/session-*.json --format json
```

## API Reference

### Core Modules

| Module | Description |
|--------|-------------|
| `secrets_sdk.vault` | `VaultClient` — auth (token, AppRole, OIDC), KV v2, dynamic DB creds, PKI, SSH, Transit, health |
| `secrets_sdk.sops` | `decrypt_file`, `encrypt_file`, `decrypt_value`, `SopsConfig` |
| `secrets_sdk.config` | `validate_repo_structure`, `validate_sops_yaml`, `validate_vault_policy`, `scan_plaintext_secrets` |
| `secrets_sdk.rotation` | `check_secret_age`, `check_secrets_batch`, `rotate_sops_keys`, `RotationPolicy` |
| `secrets_sdk.models` | Pydantic models: `SecretMetadata`, `LeaseInfo`, `CertInfo`, `HealthReport`, `AuditEvent`, `AgeReport`, etc. |
| `secrets_sdk.exceptions` | Typed exception hierarchy rooted at `SecretsSDKError` |

### SIRM Subpackage

| Module | Description |
|--------|-------------|
| `secrets_sdk.sirm.session` | `SIRMSession` — lifecycle management, persistence, sealing |
| `secrets_sdk.sirm.bootstrap` | `SIRMBootstrap` — 5-phase session initialization |
| `secrets_sdk.sirm.evidence` | `EvidenceChain` — evidence registration, SHA-256 integrity, custody tracking |
| `secrets_sdk.sirm.timeline` | `Timeline` — event correlation, multi-format export (JSON, CSV, Markdown) |
| `secrets_sdk.sirm.context` | `ContextLoader` — git state, platform info, environment capture |
| `secrets_sdk.sirm.reporter` | `SessionReport` — Markdown and JSON report generation |
| `secrets_sdk.sirm.models` | SIRM-specific Pydantic models and enums |

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Run with coverage:

```bash
pytest tests/ -v --cov=secrets_sdk --cov-report=term-missing
```

Type checking:

```bash
pip install mypy types-PyYAML
mypy secrets_sdk/ --ignore-missing-imports
```
