# @brush-cyber/secrets-sdk (TypeScript)

TypeScript SDK for developer identity and secrets management. Provides typed access to HashiCorp Vault, SOPS encryption/decryption, configuration validation, secret rotation policy, and a CLI toolkit.

## Install

```bash
npm install @brush-cyber/secrets-sdk
```

## Quick Start

```typescript
import { VaultClient, scanPlaintextSecrets, checkSecretAge } from "@brush-cyber/secrets-sdk";

// Vault operations
const vault = new VaultClient({ addr: "http://127.0.0.1:8200" });
await vault.authToken("s.my-token");

// KV v2 CRUD
const secret = await vault.kvRead("dev/apps/myapp");
await vault.kvWrite("dev/apps/myapp", { password: "new-value" });
const keys = await vault.kvList("dev/apps");

// Dynamic database credentials
const lease = await vault.dbCreds("dev-app");
console.log(lease.data.username, lease.data.password);

// PKI certificate issuance
const cert = await vault.pkiIssue("web-server", "app.example.com", ["api.example.com"]);

// SSH key signing
const signed = await vault.sshSign("dev-admin", "ssh-rsa AAAA...");

// Transit encrypt/decrypt
const encrypted = await vault.transitEncrypt("my-key", "sensitive data");
const decrypted = await vault.transitDecrypt("my-key", encrypted.ciphertext!);

// Token auto-renewal
vault.startTokenRenewal(1800000, "1h"); // every 30 min
vault.stopTokenRenewal();

// Health check
const health = await vault.health();
console.log(healthReportSummary(health));

// Scan for plaintext secrets
const findings = scanPlaintextSecrets("./src");

// Check rotation age
const report = await checkSecretAge(vault, "dev/apps/myapp", 90);
```

## API Reference

### VaultClient

| Method | Description |
|--------|-------------|
| `authToken(token?)` | Authenticate with a Vault token |
| `authAppRole(roleId?, secretId?, mountPoint?)` | Authenticate with AppRole |
| `authOidc(role?, mountPoint?)` | Authenticate with OIDC/JWT |
| `kvRead(path, version?)` | Read a KV v2 secret |
| `kvWrite(path, data)` | Write a KV v2 secret |
| `kvList(path?)` | List secrets at a path |
| `kvMetadata(path)` | Read secret metadata |
| `dbCreds(role, mountPoint?)` | Generate dynamic DB credentials |
| `pkiIssue(role, cn, altNames?, ttl?, mount?)` | Issue a PKI certificate |
| `sshSign(role, pubkey, principals?, ttl?, type?, mount?)` | Sign an SSH key |
| `transitEncrypt(keyName, plaintext, mount?)` | Encrypt via Transit |
| `transitDecrypt(keyName, ciphertext, mount?)` | Decrypt via Transit |
| `tokenRenew(increment?)` | Renew current token |
| `tokenRevokeSelf()` | Revoke current token |
| `leaseRenew(leaseId, increment?)` | Renew a lease |
| `leaseRevoke(leaseId)` | Revoke a lease |
| `startTokenRenewal(intervalMs?, increment?)` | Start auto-renewal via setInterval |
| `stopTokenRenewal()` | Stop auto-renewal |
| `health()` | Check Vault health |

### SOPS

| Function | Description |
|----------|-------------|
| `decryptFile(path, format?)` | Decrypt a SOPS-encrypted file |
| `encryptFile(path, data, outputPath?, configPath?)` | Encrypt data to a SOPS file |
| `parseSopsConfig(path)` | Parse a .sops.yaml configuration |

### Config Validation

| Function | Description |
|----------|-------------|
| `validateRepoStructure(root)` | Validate repository layout |
| `validateSopsYaml(path)` | Validate .sops.yaml |
| `validateVaultPolicy(path)` | Validate Vault HCL policy |
| `scanPlaintextSecrets(path, patterns?, excludeDirs?)` | Scan for hardcoded secrets |

### Rotation

| Function | Description |
|----------|-------------|
| `checkSecretAge(client, path, maxAgeDays?)` | Check secret age |
| `checkSecretsBatch(client, paths, policies?)` | Batch age check |
| `createRotationPolicy(name, opts?)` | Create a rotation policy |

### Models

All TypeScript interfaces are exported:

- `SecretMetadata`, `LeaseInfo`, `CertInfo`, `SSHCertInfo`, `TransitResult`
- `AuditEvent`, `AuditEventType`
- `HealthCheck`, `HealthReport`, `HealthStatus`
- `SecretFinding`, `AgeReport`
- `SopsConfig`, `SopsCreationRule`, `RotationPolicy`

### Exceptions

All error classes extend `Error`:

- `SecretsSDKError` (base)
- `VaultError`, `VaultAuthError`, `VaultSecretNotFound`, `VaultConnectionError`, `VaultLeaseError`
- `SopsError`, `SopsDecryptError`, `SopsEncryptError`, `SopsNotInstalledError`
- `ConfigValidationError`, `RotationError`

## CLI

```bash
npx secrets-sdk doctor --root .
npx secrets-sdk vault-health --addr http://127.0.0.1:8200
npx secrets-sdk scan ./src
npx secrets-sdk rotate-check --path dev/apps/myapp --max-age 90
npx secrets-sdk decrypt secrets/dev/app.enc.yaml
```

All commands support `--json-output` for machine-readable output.

## Development

```bash
npm install
npm run build
npm test
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | Vault server URL (default: `http://127.0.0.1:8200`) |
| `VAULT_TOKEN` | Vault authentication token |
| `VAULT_NAMESPACE` | Vault namespace (enterprise) |
| `VAULT_SKIP_VERIFY` | Skip TLS verification (`1` or `true`) |
| `VAULT_ROLE_ID` | AppRole role ID |
| `VAULT_SECRET_ID` | AppRole secret ID |
| `VAULT_OIDC_TOKEN` | OIDC/JWT token for headless auth |
