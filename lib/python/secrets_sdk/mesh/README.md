# Secrets Mesh

Multi-provider secret access layer with fallback chains, caching, and audit logging.

## Overview

The Secrets Mesh provides a unified interface for accessing secrets across multiple backends. Instead of coupling application code to a single secret store, the mesh abstracts provider selection, implements automatic fallback when a provider is unavailable, and adds read-through caching to reduce backend load.

## Architecture

```
Application Code
       |
  SecretsMesh (orchestrator)
       |
  +---------+---------+---------+
  | Priority 10       | Priority 50       | Priority 100      |
  | VaultProvider      | FileProvider       | EnvProvider        |
  | (production)       | (SOPS files)       | (local dev)        |
  +---------+---------+---------+
       |
  TTLCache (read-through, LRU eviction)
       |
  Audit Log (all access recorded)
```

## Providers

### VaultProvider

Wraps the existing `VaultClient` for KV v2 operations. Best for production environments with centralized secret management.

```python
from secrets_sdk.vault import VaultClient
from secrets_sdk.mesh import SecretsMesh, VaultProvider

client = VaultClient(addr="https://vault.example.com:8200")
client.auth_token()

mesh = SecretsMesh(cache_ttl=60)
mesh.register(VaultProvider(client, prefix="app/config"), priority=10)
```

### EnvProvider

Reads secrets from environment variables with prefix mapping. Ideal for local development, CI pipelines, and container environments.

```python
from secrets_sdk.mesh import SecretsMesh, EnvProvider

mesh = SecretsMesh()
mesh.register(EnvProvider(prefix="MYAPP"), priority=50)

# get_secret("db_password") reads MYAPP_DB_PASSWORD
secret = mesh.get_secret("db_password")
```

### FileProvider

Reads from SOPS-encrypted files. Operates in directory mode (one file per secret) or single-file mode (keys within one encrypted file).

```python
from secrets_sdk.mesh import SecretsMesh, FileProvider

mesh = SecretsMesh()
mesh.register(FileProvider("secrets/dev/app.enc.yaml"), priority=30)
```

## Fallback Chains

Providers are tried in priority order (lower number = higher priority). If one fails, the next is attempted:

```python
mesh = SecretsMesh(cache_ttl=120)
mesh.register(VaultProvider(vault_client), priority=10)   # Try Vault first
mesh.register(FileProvider("secrets/"), priority=50)       # Fall back to SOPS files
mesh.register(EnvProvider(prefix="APP"), priority=100)     # Last resort: env vars

secret = mesh.get_secret("api_key")  # Tries Vault -> Files -> Env
```

## Caching

Read-through TTL cache with LRU eviction:

```python
mesh = SecretsMesh(cache_ttl=300, cache_max_size=500)

# First call hits provider, subsequent calls use cache
secret1 = mesh.get_secret("db_pass")        # Provider hit
secret2 = mesh.get_secret("db_pass")        # Cache hit
secret3 = mesh.get_secret("db_pass", skip_cache=True)  # Force refresh

# Invalidate specific or all cached secrets
mesh.invalidate_cache("db_pass")
mesh.invalidate_cache()  # Clear all
```

## Health Monitoring

```python
status = mesh.health_check()
print(status.summary())
# [HEALTHY] vault:healthy | file:healthy | env:healthy

for p in status.providers:
    print(f"  {p.provider_name}: {p.status.value} ({p.latency_ms:.1f}ms)")
```

## Audit Logging

All operations are recorded in the audit log:

```python
mesh.get_secret("api_key")
mesh.put_secret("new_key", "value")

for entry in mesh.audit_log:
    print(entry.as_log_line())
# ts=2025-06-01T12:00:00+00:00 op=get_secret status=OK key=api_key provider=vault
```

## CLI

Check mesh status from the command line:

```bash
secrets-sdk mesh-status --providers vault,env --json-output
```

## Custom Providers

Implement `SecretProvider` to create custom backends:

```python
from secrets_sdk.mesh import SecretProvider, SecretValue, ProviderHealth, ProviderStatus

class RedisProvider(SecretProvider):
    @property
    def name(self) -> str:
        return "redis"

    def get_secret(self, key: str) -> SecretValue:
        value = self.redis.get(f"secrets:{key}")
        if value is None:
            raise KeyError(key)
        return SecretValue(key=key, value=value, provider=self.name)

    # ... implement remaining methods
```
