# SDK Design Guide

This document describes the design patterns, interface contracts, and conventions shared across all three SDKs (Python, Go, TypeScript). Any new SDK language must follow these patterns.

---

## Common Interface Patterns

All SDKs expose the same logical surface through language-idiomatic implementations:

| Capability | Python | Go | TypeScript |
|-----------|--------|-----|-----------|
| Vault client | `VaultClient` class | `VaultClient` struct | `VaultClient` class |
| Auth: token | `auth_token()` | `AuthToken()` | `authToken()` |
| Auth: AppRole | `auth_approle()` | `AuthAppRole()` | `authAppRole()` |
| Auth: OIDC/JWT | `auth_oidc()` | `AuthOIDC()` | `authOIDC()` |
| KV read | `kv_read(path, version)` | `KVRead(ctx, path, version)` | `kvRead(path, version?)` |
| KV write | `kv_write(path, data)` | `KVWrite(ctx, path, data)` | `kvWrite(path, data)` |
| KV delete | `kv_delete(path)` | `KVDelete(ctx, path)` | `kvDelete(path)` |
| Dynamic creds | `dynamic_creds(mount, role)` | `DynamicCreds(ctx, mount, role)` | `dynamicCreds(mount, role)` |
| PKI issue | `pki_issue(mount, role, cn, opts)` | `PKIIssue(ctx, mount, role, cn, opts)` | `pkiIssue(mount, role, cn, opts?)` |
| SSH sign | `ssh_sign(mount, role, pubkey)` | `SSHSign(ctx, mount, role, pubkey)` | `sshSign(mount, role, pubkey)` |
| Transit encrypt | `transit_encrypt(mount, key, plaintext)` | `TransitEncrypt(ctx, mount, key, plaintext)` | `transitEncrypt(mount, key, plaintext)` |
| Transit decrypt | `transit_decrypt(mount, key, ciphertext)` | `TransitDecrypt(ctx, mount, key, ciphertext)` | `transitDecrypt(mount, key, ciphertext)` |
| Token renew | `renew_token(increment)` | `RenewToken(ctx, increment)` | `renewToken(increment?)` |
| Health | `health()` | `Health(ctx)` | `health()` |
| SOPS decrypt | `sops.decrypt_file(path)` | `sops.DecryptFile(path)` | `decryptFile(path)` |
| SOPS encrypt | `sops.encrypt_file(path, config)` | N/A | `encryptFile(path, config)` |
| Config validate | `config.validate_*()` | `config.Validate*()` | `validate*()` |
| Rotation check | `rotation.check_secret_age()` | N/A | `checkSecretAge()` |

### Naming Convention by Language

- **Python**: `snake_case` for methods and fields. Classes are `PascalCase`.
- **Go**: `PascalCase` for exported methods and types. `context.Context` as first parameter on all I/O methods.
- **TypeScript**: `camelCase` for methods and fields. Classes and interfaces are `PascalCase`.

---

## Client Construction

### Pattern: Environment-first configuration

All SDKs default to environment variables, with explicit parameters taking precedence.

**Resolution order** (highest to lowest priority):

1. Explicit constructor parameter
2. Environment variable
3. Hardcoded default

**Shared environment variables:**

| Variable | Purpose | Default |
|----------|---------|---------|
| `VAULT_ADDR` | Vault server URL | `http://127.0.0.1:8200` |
| `VAULT_TOKEN` | Authentication token | (none) |
| `VAULT_NAMESPACE` | Enterprise namespace | (none) |
| `VAULT_SKIP_VERIFY` | Disable TLS verification (`1` or `true`) | `false` |
| `VAULT_ROLE_ID` | AppRole role ID | (none) |
| `VAULT_SECRET_ID` | AppRole secret ID | (none) |
| `VAULT_OIDC_TOKEN` | JWT for OIDC auth | (none) |

### Pattern: Functional options (Go)

```go
client := vault.NewClient("",
    vault.WithToken("s.xxx"),
    vault.WithNamespace("team-a"),
    vault.WithKVMount("kv-v2"),
)
```

### Pattern: Options object (TypeScript)

```typescript
const client = new VaultClient({
    addr: "https://vault.example.com",
    kvMount: "kv-v2",
});
```

### Pattern: Constructor parameters with defaults (Python)

```python
client = VaultClient(
    addr="https://vault.example.com",
    kv_mount="kv-v2",
)
```

---

## Error Handling Conventions

### Hierarchy

All SDKs implement the same error hierarchy:

```
SecretsSDKError (base)
├── VaultError
│   ├── VaultAuthError(method, detail)
│   ├── VaultSecretNotFound(path)
│   ├── VaultConnectionError(addr, detail)
│   └── VaultLeaseError(lease_id, operation, detail)
├── SopsError
│   ├── SopsDecryptError(path, detail)
│   ├── SopsEncryptError(path, detail)
│   └── SopsNotInstalledError()
├── ConfigValidationError(issues[])
└── RotationError(detail)
```

### Error Message Format

Error messages are consistent across languages:

| Error | Message template |
|-------|-----------------|
| `VaultAuthError` | `Vault authentication failed using {method}: {detail}` |
| `VaultSecretNotFound` | `Secret not found at path: {path}` |
| `VaultConnectionError` | `Cannot connect to Vault at {addr}: {detail}` |
| `VaultLeaseError` | `Lease {operation} failed for {lease_id}: {detail}` |
| `SopsDecryptError` | `SOPS decryption failed for {path}: {detail}` |
| `SopsEncryptError` | `SOPS encryption failed for {path}: {detail}` |
| `SopsNotInstalledError` | `sops binary not found on PATH. Install from https://github.com/getsops/sops` |
| `ConfigValidationError` | `Configuration validation found {n} issue(s):\n  - {issue1}\n  - {issue2}` |
| `RotationError` | `Secret rotation failed: {detail}` |

### Language-Specific Error Patterns

**Python**: Exception classes inheriting from `Exception`. Each error carries typed fields (`method`, `path`, `addr`, etc.) as instance attributes.

**Go**: Concrete struct types implementing the `error` interface. Each error type has exported fields. Use type assertion for matching:

```go
if authErr, ok := err.(*vault.AuthError); ok {
    log.Printf("auth method: %s, detail: %s", authErr.Method, authErr.Detail)
}
```

**TypeScript**: Error classes extending `Error` with `Object.setPrototypeOf` for correct prototype chain. Each error carries `readonly` properties. Use `instanceof` for matching:

```typescript
if (err instanceof VaultAuthError) {
    console.error(`auth method: ${err.method}, detail: ${err.detail}`);
}
```

---

## Authentication Flow

All SDKs support three authentication methods in the same priority order:

### 1. Token Authentication

Simplest path. Used for local development and pre-authenticated contexts.

```
Client receives token (explicit or VAULT_TOKEN)
  → GET /v1/auth/token/lookup-self to verify
  → Token stored on client instance
  → All subsequent requests include X-Vault-Token header
```

### 2. AppRole Authentication

Used for machine-to-machine auth in CI and service contexts.

```
Client receives role_id + secret_id (explicit or VAULT_ROLE_ID / VAULT_SECRET_ID)
  → POST /v1/auth/{mount}/login with { role_id, secret_id }
  → Extract client_token from response.auth
  → Token stored on client instance
```

### 3. OIDC/JWT Authentication

Used for CI OIDC federation (GitHub Actions, GitLab CI) and headless environments.

```
Client receives role + JWT (explicit or VAULT_OIDC_TOKEN)
  → POST /v1/auth/{mount}/login with { role, jwt }
  → Extract client_token from response.auth
  → Token stored on client instance
```

### Token Lifecycle

- **Renewal**: `renew_token(increment)` calls `POST /v1/auth/token/renew-self`.
- **Background renewal**: SDKs support automatic periodic renewal (Go goroutine, Python thread, TypeScript `setInterval`).
- **Revocation**: SDKs support `revoke_token()` calling `POST /v1/auth/token/revoke-self`.

---

## Configuration via Environment Variables

SDKs must never require a configuration file. All configuration is via environment variables with explicit overrides.

### Required for Operation

| Variable | Required By |
|----------|-------------|
| `VAULT_ADDR` | All Vault operations (default: `http://127.0.0.1:8200`) |

### Required for Authentication (one set)

| Auth Method | Variables |
|------------|-----------|
| Token | `VAULT_TOKEN` |
| AppRole | `VAULT_ROLE_ID` + `VAULT_SECRET_ID` |
| OIDC | `VAULT_OIDC_TOKEN` |

### Optional

| Variable | Purpose |
|----------|---------|
| `VAULT_NAMESPACE` | Vault Enterprise namespace |
| `VAULT_SKIP_VERIFY` | Skip TLS verification |
| `SOPS_AGE_KEY_FILE` | Age key file for SOPS |
| `SOPS_PGP_FP` | PGP fingerprint for SOPS |

---

## Audit Events

All SDKs emit structured audit events for every Vault operation. Events include:

| Field | Type | Description |
|-------|------|-------------|
| `type` | enum | Operation type: `kv_read`, `kv_write`, `kv_delete`, `dynamic_creds`, `pki_issue`, `ssh_sign`, `transit_encrypt`, `transit_decrypt`, `auth`, `token_renew` |
| `timestamp` | ISO 8601 UTC | When the operation occurred |
| `path` | string | Vault path or mount/role |
| `success` | boolean | Whether the operation succeeded |
| `detail` | string | Additional context (error message on failure) |
| `duration_ms` | float | Operation latency |

Events are stored in-memory on the client instance and accessible via `audit_log()` / `AuditLog()` / `auditLog()`. Callers can forward these to their SIEM.

---

## Testing Patterns

### Mock Strategies by Language

**Python** (pytest + pytest-mock):

```python
# Inject a mock hvac client via the `client` constructor parameter
mock_hvac = MagicMock()
mock_hvac.secrets.kv.v2.read_secret_version.return_value = {
    "data": {"data": {"api_key": "test-key"}, "metadata": {"version": 1}}
}
vault = VaultClient(client=mock_hvac)
result = vault.kv_read("myapp/config")
assert result["api_key"] == "test-key"
```

The Python SDK accepts an optional `client` parameter in the constructor, allowing full replacement of the `hvac` client with a mock.

**Go** (standard `testing` + `net/http/httptest`):

```go
// Use httptest.NewServer to create a fake Vault API
server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "data": map[string]interface{}{
            "data": map[string]interface{}{"api_key": "test-key"},
        },
    })
}))
defer server.Close()

client := vault.NewClient(server.URL, vault.WithToken("test-token"))
data, err := client.KVRead(context.Background(), "myapp/config", 0)
```

The Go SDK uses a standard `*http.Client` which can be replaced via `WithHTTPClient()`. The simplest mock strategy is `httptest.NewServer`.

**TypeScript** (jest):

```typescript
// Inject a mock VaultBackend via the `backend` constructor option
const mockBackend: VaultBackend = {
    read: jest.fn().mockResolvedValue({
        data: { data: { api_key: "test-key" }, metadata: { version: 1 } },
    }),
    write: jest.fn(),
    delete: jest.fn(),
    list: jest.fn(),
    health: jest.fn(),
    tokenLookupSelf: jest.fn(),
    tokenRenewSelf: jest.fn(),
    tokenRevokeSelf: jest.fn(),
};
const client = new VaultClient({ backend: mockBackend });
const data = await client.kvRead("myapp/config");
expect(data.api_key).toBe("test-key");
```

The TypeScript SDK accepts a `VaultBackend` interface in the constructor, enabling full replacement of the underlying `node-vault` client.

### Test Coverage Expectations

| Category | Minimum |
|----------|---------|
| Auth methods (token, AppRole, OIDC) | All three, success + failure |
| KV operations (read, write, delete) | Happy path + not-found + permission denied |
| Dynamic creds | Success + engine not found |
| PKI issue | Success + invalid role |
| SSH sign | Success + invalid key |
| Transit encrypt/decrypt | Round-trip success + invalid key |
| Health | Healthy, degraded, unhealthy, no-auth |
| Error hierarchy | Every error type instantiates and formats correctly |
| SOPS | Decrypt success + file not found + SOPS not installed |
| Config validation | Valid + each invalid case |

---

## Adding New SDK Methods

When adding a new method to the SDK surface (e.g., a new Vault engine, a new SOPS operation):

1. **Define in all three SDKs** simultaneously. The interface table in this document must stay in sync.
2. **Follow the naming convention** for each language.
3. **Add the appropriate error type** if the new method has a unique failure mode.
4. **Add the audit event type** to the `AuditEventType` enum.
5. **Add typed models** if the new method returns structured data.
6. **Write tests** covering success, expected failure, and connection failure.
7. **Update this document** with the new method in the interface table.
8. **Update `__init__.py`** (Python), `index.ts` (TypeScript), and exported symbols to include new types.
9. **Add an example** in `examples/<language>/` demonstrating the new method.

### Method Implementation Checklist

- [ ] Python implementation in `secrets_sdk/<module>.py`
- [ ] Python tests in `lib/python/tests/`
- [ ] Python type annotations and mypy strict pass
- [ ] Go implementation in `lib/go/<package>/`
- [ ] Go tests
- [ ] Go doc comments on all exported symbols
- [ ] TypeScript implementation in `lib/typescript/src/<module>.ts`
- [ ] TypeScript tests in `lib/typescript/tests/`
- [ ] TypeScript strict mode pass
- [ ] Audit event type added
- [ ] Models added to all SDKs
- [ ] Error type added (if needed)
- [ ] Interface table in this document updated
- [ ] Examples added

---

## SDK File Structure

### Python (`lib/python/`)

```
lib/python/
├── secrets_sdk/
│   ├── __init__.py       # Public API exports
│   ├── vault.py          # VaultClient
│   ├── sops.py           # SOPS decrypt/encrypt
│   ├── config.py         # Config validation + plaintext scanning
│   ├── rotation.py       # Rotation policy + age checks
│   ├── models.py         # Pydantic data models
│   ├── exceptions.py     # Exception hierarchy
│   ├── cli.py            # Click-based CLI
│   ├── sirm/             # SIRM subpackage
│   └── py.typed          # PEP 561 marker
├── tests/
├── pyproject.toml
└── README.md
```

### Go (`lib/go/`)

```
lib/go/
├── vault/
│   ├── client.go         # VaultClient + all Vault operations
│   └── client_test.go
├── sops/
│   ├── decrypt.go        # SOPS decrypt
│   └── decrypt_test.go
├── config/
│   └── ...               # Config validation
├── cmd/                  # CLI entrypoints
├── go.mod
├── go.sum
└── README.md
```

### TypeScript (`lib/typescript/`)

```
lib/typescript/
├── src/
│   ├── index.ts          # Public API exports
│   ├── vault.ts          # VaultClient
│   ├── sops.ts           # SOPS decrypt/encrypt
│   ├── config.ts         # Config validation
│   ├── rotation.ts       # Rotation policy + age checks
│   ├── models.ts         # Type definitions
│   └── exceptions.ts     # Error hierarchy
├── tests/
├── dist/                 # Compiled output
├── package.json
├── tsconfig.json
├── jest.config.js
└── README.md
```
