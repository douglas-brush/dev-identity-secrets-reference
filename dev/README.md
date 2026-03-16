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
make up        # Start Vault + PostgreSQL + Vault Agent
make setup     # Bootstrap all engines, policies, PKI, demo data
make demo      # Walk through every pattern interactively
```

Or non-interactively:

```bash
make up && make setup && make demo-auto
```

## What's Included

| Service      | Port  | Purpose                                       |
|--------------|-------|-----------------------------------------------|
| Vault        | 8200  | Secret management (dev mode, root token)      |
| PostgreSQL   | 5432  | Target database for dynamic credentials demo  |
| Vault Agent  | 8100  | Sidecar — auto-auth, token renewal, templating |
| Prometheus   | 9090  | Metrics collection (monitoring profile)       |
| Grafana      | 3000  | Dashboards & visualization (monitoring profile) |

### Vault Agent Sidecar

The Vault Agent runs as a sidecar service that:

- **Auto-authenticates** via AppRole (no manual token management)
- **Renews tokens** automatically before expiry
- **Templates secrets** to `/tmp/secrets/` as JSON and env files
- **Proxies API requests** on `:8100` — apps connect here instead of directly to Vault

Rendered secret files:
- `app-config.json` — KV application config
- `db-creds.json` — Dynamic database credentials (auto-renewed)
- `tls-cert.pem` / `tls-key.pem` — PKI certificates (auto-rotated)
- `app.env` — Environment file with all credentials

```bash
# View rendered secrets
make agent-secrets

# Tail agent logs
make agent-logs

# Use the agent proxy (no token needed)
curl http://localhost:8100/v1/kv/data/dev/apps/demo-app/config
```

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

## Monitoring Stack

The monitoring stack runs under an optional Docker Compose profile. It is not started by default.

### Starting Monitoring

```bash
make monitoring-up    # Start Prometheus + Grafana alongside the core stack
make grafana          # Open the Vault Health dashboard in your browser
make prometheus       # Open Prometheus UI
```

### Stopping Monitoring

```bash
make monitoring-down  # Stop only Prometheus + Grafana
```

### Grafana

- **URL:** http://localhost:3000
- **Credentials:** admin / admin (anonymous viewer access enabled)
- **Pre-loaded dashboard:** Vault Health & Operations

The dashboard includes panels for:
- Seal status and HA status
- Uptime, memory, goroutines
- Token creation, lookup, and store rates
- Auth method login rate
- Active lease count and lease expiry rate
- HTTP request rate and latency percentiles (p50/p90/p99)
- Audit log write rate and failures
- Secret engine usage by mount (KV, database, transit, PKI)
- Transit encrypt/decrypt throughput

### Prometheus

- **URL:** http://localhost:9090
- Scrapes Vault metrics at `/v1/sys/metrics` every 10s
- Data retained for 7 days

### Configuration Files

| File | Purpose |
|------|---------|
| `prometheus/prometheus.yml` | Scrape targets and intervals |
| `grafana/datasources.yml` | Prometheus datasource config |
| `grafana/dashboards.yml` | Dashboard provisioning |
| `grafana/dashboards/vault-health.json` | Vault Health & Operations dashboard |

## Seed Demo Data

Populate Vault with realistic demo data across all engines:

```bash
make seed-demo-data
```

This creates:
- **10+ KV secrets** across `dev/`, `staging/`, `prod/` paths (web-frontend, payment-service, notification-service, auth-service, shared infra)
- **3 additional database roles** (analytics, migration, backup) beyond the 2 from setup
- **5 PKI certificates** for service identities (api, gateway, auth, payments, notifications)
- **5 additional Transit keys** for different use cases (PII encryption, HMAC, document signing, backup encryption, auto-rotating config key)
- **3 AppRole identities** for demo applications (web-frontend, payment-service, analytics-pipeline)
- Vault Agent bootstrap credentials

The script is idempotent and safe to re-run.

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

| Target              | Description                                          |
|---------------------|------------------------------------------------------|
| `make up`           | Start Vault + PostgreSQL + Vault Agent               |
| `make down`         | Stop the stack                                       |
| `make setup`        | Bootstrap Vault (engines, policies, data)            |
| `make demo`         | Run interactive demo of all patterns                 |
| `make demo-auto`    | Run demo non-interactively                           |
| `make seed-demo-data` | Seed Vault with realistic demo data               |
| `make monitoring-up` | Start Prometheus + Grafana                          |
| `make monitoring-down` | Stop Prometheus + Grafana                         |
| `make grafana`      | Open Grafana Vault dashboard in browser              |
| `make prometheus`   | Open Prometheus UI in browser                        |
| `make agent-logs`   | Tail Vault Agent logs                                |
| `make agent-secrets`| Show rendered secrets from Vault Agent               |
| `make logs`         | Tail all service logs                                |
| `make clean`        | Stop and remove all volumes                          |
| `make reset`        | Clean + up + setup (full restart)                    |
| `make status`       | Show service health                                  |
| `make shell-vault`  | Shell into Vault container                           |
| `make shell-pg`     | psql into PostgreSQL                                 |

## Environment Variables

Configurable via `.env` (copy from `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_PORT` | 8200 | Vault API port |
| `VAULT_DEV_ROOT_TOKEN` | dev-root-token | Dev mode root token |
| `VAULT_LOG_LEVEL` | info | Vault log level |
| `VAULT_AGENT_PORT` | 8100 | Vault Agent proxy port |
| `POSTGRES_PORT` | 5432 | PostgreSQL port |
| `POSTGRES_USER` | postgres | PostgreSQL user |
| `POSTGRES_PASSWORD` | postgres | PostgreSQL password |
| `POSTGRES_DB` | demo | PostgreSQL database |
| `PROMETHEUS_PORT` | 9090 | Prometheus port |
| `GRAFANA_PORT` | 3000 | Grafana port |
| `GRAFANA_USER` | admin | Grafana admin user |
| `GRAFANA_PASSWORD` | admin | Grafana admin password |

## Troubleshooting

**Vault not starting**
Check port 8200 is free: `lsof -i :8200`. Kill conflicting processes or change `VAULT_PORT` in `.env`.

**PostgreSQL connection refused**
Check port 5432 is free. If you have a local PostgreSQL, change `POSTGRES_PORT` in `.env`.

**Setup script fails on database config**
PostgreSQL may not be ready yet. Wait a few seconds and re-run `make setup` — the script is idempotent.

**Vault Agent not rendering secrets**
The agent needs AppRole credentials. Run `make seed-demo-data` to write role-id/secret-id to the agent volume, or check `make agent-logs` for auth errors.

**Prometheus not scraping Vault**
Vault must have telemetry enabled. In dev mode, metrics are available at `/v1/sys/metrics`. Check `make status` to confirm Vault is healthy.

**Grafana shows "No data"**
Wait 30-60 seconds for Prometheus to collect initial metrics. Check Prometheus targets at http://localhost:9090/targets to confirm the Vault target is UP.

**"permission denied" on setup.sh or demo.sh**
Run `chmod +x dev/vault/setup.sh dev/demo.sh dev/scripts/seed-demo-data.sh`.

**Reset everything**
`make reset` destroys volumes and re-bootstraps from scratch.

**Vault UI shows "sealed"**
Dev mode Vault auto-unseals. If you see this, the container may have restarted. Run `make reset`.
