# Go Secrets SDK

Go reference implementation for developer identity and secrets management. Mirrors the Python SDK patterns with idiomatic Go conventions.

## Install

```bash
go get github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go
```

### CLI

```bash
go install github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/cmd/secrets-sdk@latest
```

## Packages

### `vault` — HashiCorp Vault Client

High-level Vault client with typed operations for KV v2, dynamic credentials, PKI, SSH, Transit, and token lifecycle.

```go
import "github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/vault"

client := vault.NewClient("http://127.0.0.1:8200",
    vault.WithToken("hvs.xxx"),
    vault.WithKVMount("secret"),
    vault.WithNamespace("admin/team1"),
)
```

#### Authentication

```go
// Token auth
err := client.AuthToken(ctx, "hvs.xxx")

// AppRole auth
err := client.AuthAppRole(ctx, "role-id", "secret-id", "approle")

// OIDC/JWT auth (headless — set VAULT_OIDC_TOKEN or pass JWT)
err := client.AuthOIDC(ctx, "role-name", "eyJhbG...", "oidc")
```

#### KV v2 Operations

```go
// Read (version 0 = latest)
data, err := client.KVRead(ctx, "myapp/config", 0)

// Write
meta, err := client.KVWrite(ctx, "myapp/config", map[string]interface{}{
    "username": "admin",
    "password": "secret",
})

// Delete
err := client.KVDelete(ctx, "myapp/old-config")
```

#### Dynamic Credentials

```go
lease, err := client.DynamicCreds(ctx, "database", "readonly")
// lease.Data["username"], lease.Data["password"]
// lease.LeaseID, lease.LeaseDuration, lease.Renewable
```

#### PKI Certificate Issuance

```go
cert, err := client.PKIIssue(ctx, "pki", "web-server", "example.com", &vault.PKIIssueOpts{
    AltNames: []string{"www.example.com"},
    TTL:      "720h",
})
// cert.Certificate, cert.PrivateKey, cert.CAChain, cert.SerialNumber
```

#### SSH Certificate Signing

```go
sshCert, err := client.SSHSign(ctx, "ssh", "default", publicKeyString)
// sshCert.SignedKey, sshCert.SerialNumber
```

#### Transit Encrypt/Decrypt

```go
encrypted, err := client.TransitEncrypt(ctx, "transit", "my-key", []byte("sensitive data"))
// encrypted.Ciphertext = "vault:v1:..."

decrypted, err := client.TransitDecrypt(ctx, "transit", "my-key", encrypted.Ciphertext)
// decrypted.Plaintext = "sensitive data"
```

#### Token Lifecycle

```go
// One-time renewal
auth, err := client.RenewToken(ctx, "1h")

// Background renewal goroutine
cancel := client.RenewTokenBackground(ctx, 30*time.Minute, "1h")
defer cancel()
```

#### Health Check

```go
report := client.Health(ctx)
fmt.Println(report.Summary())
// [HEALTHY] vault_connectivity: healthy | vault_auth: healthy
fmt.Println(report.OverallStatus()) // "healthy"
```

### `sops` — SOPS Decryption

Wraps the `sops` CLI binary for decrypting encrypted secrets files.

```go
import "github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/sops"

// Decrypt a file (auto-detects format from extension)
data, err := sops.DecryptFile("secrets/prod/db.enc.yaml", "")

// Decrypt with explicit format
data, err := sops.DecryptFile("secrets/prod/db.enc.yaml", "json")

// Decrypt raw bytes
data, err := sops.DecryptBytes(encryptedBytes, "json")

// Parse .sops.yaml config
cfg, err := sops.ParseSopsConfig(".sops.yaml")
hasCloud := cfg.HasCloudKMS()
```

### `config` — Validation

Repository structure validation, plaintext secret scanning, and Vault policy checking.

```go
import "github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/config"

// Validate repo structure
issues := config.ValidateRepoStructure("/path/to/repo")

// Scan for plaintext secrets
findings, err := config.ScanPlaintextSecrets("/path/to/scan")

// Validate Vault HCL policy
issues := config.ValidateVaultPolicy("policies/app.hcl")
```

## CLI Commands

```bash
# Validate repository structure
secrets-sdk doctor --root /path/to/repo
secrets-sdk doctor --root /path/to/repo --json

# Check Vault health
secrets-sdk vault-health --addr http://127.0.0.1:8200
secrets-sdk vault-health --json

# Scan for plaintext secrets
secrets-sdk scan /path/to/scan
secrets-sdk scan /path/to/scan --json

# Decrypt SOPS file
secrets-sdk decrypt secrets/prod/db.enc.yaml
secrets-sdk decrypt secrets/prod/db.enc.yaml --output-format yaml
```

## Error Types

All Vault errors are typed for programmatic handling:

| Error Type | When |
|---|---|
| `*vault.AuthError` | Authentication failure (bad token, invalid AppRole, OIDC failure) |
| `*vault.SecretNotFoundError` | KV path does not exist |
| `*vault.ConnectionError` | Vault server unreachable |
| `*vault.LeaseError` | Lease renew/revoke failure |
| `*sops.NotInstalledError` | `sops` binary not on PATH |
| `*sops.DecryptError` | SOPS decryption failure |

## Testing

```bash
cd lib/go
go test ./...
```

Tests use `net/http/httptest` for Vault API mocking and temp directories for config validation. No external services required.

## Requirements

- Go 1.22+
- `sops` binary on PATH (for decrypt operations)
- HashiCorp Vault (for vault operations)
