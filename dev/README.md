# Local Development Environment

Docker Compose stack for testing all patterns in this reference architecture without any cloud infrastructure.

## Prerequisites

- Docker Engine 20.10+ and Docker Compose v2
- `vault` CLI ([install](https://developer.hashicorp.com/vault/install))
- `jq` for JSON parsing
- `openssl` (for PKI demo inspection)

## Quick Start

```bash
cd dev/
make up        # Start Vault + PostgreSQL
make setup     # Bootstrap all engines, policies, PKI, demo data
make demo      # Walk through every pattern interactively
```

Or non-interactively:

```bash
make up && make setup && make demo-auto
```

## What's Included

| Service    | Port  | Purpose                                      |
|------------|-------|----------------------------------------------|
| Vault      | 8200  | Secret management (dev mode, root token)     |
| PostgreSQL | 5432  | Target database for dynamic credentials demo |

### Vault Engines Configured

| Engine     | Mount Path | Purpose                                |
|------------|------------|----------------------------------------|
| KV v2      | `kv/`      | Static secrets with versioning         |
| Database   | `database/`| Dynamic PostgreSQL credential generation |
| PKI Root   | `pki/`     | Root certificate authority             |
| PKI Int    | `pki_int/` | Intermediate CA for service certs      |
| SSH        | `ssh/`     | SSH certificate authority              |
| Transit    | `transit/` | Encryption-as-a-service                |

### Auth Methods

| Method   | Path       | Purpose                  |
|----------|------------|--------------------------|
| AppRole  | `approle/` | Machine identity auth    |

### Policies Loaded

All policies from `platform/vault/policies/` are loaded automatically:

- `admin-emergency` — Break-glass access (scoped, no destructive ops)
- `ci-issuer` — CI pipeline secret access
- `db-dynamic` — Dynamic database credential retrieval
- `developer-read` — Developer read access (scoped to identity)
- `pki-admin` — PKI certificate operations
- `rotation-operator` — Automated secret rotation
- `ssh-ca-operator` — SSH CA signing
- `transit-app` — Transit encrypt/decrypt/sign

## Testing Each Pattern

### KV Secrets

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token

vault kv put kv/dev/apps/demo-app/mykey value=hello
vault kv get kv/dev/apps/demo-app/mykey
vault kv metadata get kv/dev/apps/demo-app/mykey
```

### Dynamic Database Credentials

```bash
# Generate credentials (1h TTL)
vault read database/creds/dev-demo-app

# Test them
psql -h localhost -U <generated-user> -d demo -c "SELECT * FROM users;"

# Read-only variant
vault read database/creds/dev-readonly
```

### PKI Certificate Issuance

```bash
vault write pki_int/issue/dev-services \
  common_name="myapp.dev.local" \
  alt_names="myapp.svc.local" \
  ttl="24h"
```

### SSH Certificate Signing

```bash
ssh-keygen -t ed25519 -f /tmp/test_key -N ""
vault write -field=signed_key ssh/sign/dev-admin \
  public_key=@/tmp/test_key.pub > /tmp/test_key-cert.pub
ssh-keygen -L -f /tmp/test_key-cert.pub
```

### Transit Encryption

```bash
# Encrypt
vault write transit/encrypt/demo-app \
  plaintext=$(echo -n "my secret data" | base64)

# Decrypt
vault write transit/decrypt/demo-app \
  ciphertext="vault:v1:..."

# Key rotation
vault write -f transit/keys/demo-app/rotate
```

### AppRole Authentication

```bash
# Get role-id (stable)
vault read auth/approle/role/demo-app/role-id

# Generate secret-id (one-time)
vault write -f auth/approle/role/demo-app/secret-id

# Login
vault write auth/approle/login \
  role_id=<role-id> \
  secret_id=<secret-id>
```

## Connecting the Python SDK

From the repo root:

```bash
cd lib/python
pip install -e ".[dev]"

# Set environment
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token

# The SDK uses hvac under the hood — it will connect to the local Vault
python -c "
import hvac
client = hvac.Client(url='http://localhost:8200', token='dev-root-token')
print('Vault sealed:', client.sys.is_sealed())
print('KV read:', client.secrets.kv.v2.read_secret_version(path='dev/apps/demo-app/config', mount_point='kv'))
"
```

## Makefile Targets

| Target       | Description                                        |
|--------------|----------------------------------------------------|
| `make up`    | Start Vault + PostgreSQL                           |
| `make down`  | Stop the stack                                     |
| `make setup` | Bootstrap Vault (engines, policies, data)          |
| `make demo`  | Run interactive demo of all patterns               |
| `make demo-auto` | Run demo non-interactively                     |
| `make logs`  | Tail all service logs                              |
| `make clean` | Stop and remove all volumes                        |
| `make reset` | Clean + up + setup (full restart)                  |
| `make status`| Show service health                                |
| `make shell-vault` | Shell into Vault container                   |
| `make shell-pg`    | psql into PostgreSQL                         |

## Troubleshooting

**Vault not starting**
Check port 8200 is free: `lsof -i :8200`. Kill conflicting processes or change `VAULT_PORT` in `.env`.

**PostgreSQL connection refused**
Check port 5432 is free. If you have a local PostgreSQL, change `POSTGRES_PORT` in `.env`.

**Setup script fails on database config**
PostgreSQL may not be ready yet. Wait a few seconds and re-run `make setup` — the script is idempotent.

**"permission denied" on setup.sh or demo.sh**
Run `chmod +x dev/vault/setup.sh dev/demo.sh`.

**Reset everything**
`make reset` destroys volumes and re-bootstraps from scratch.

**Vault UI shows "sealed"**
Dev mode Vault auto-unseals. If you see this, the container may have restarted. Run `make reset`.
