# Application Integration Examples

Working examples showing how applications consume secrets from Vault across five languages. Each example implements the same integration pattern: authenticate, read static secrets, acquire dynamic database credentials, and renew leases in the background.

## Examples

| Language | Entry Point | Auth Methods | Health Endpoint | Renewal Strategy |
|----------|-------------|-------------|-----------------|------------------|
| **Python** | `python/vault_app.py` | AppRole, OIDC | No (daemon mode) | Background thread, re-auth after 3 failures |
| **Node.js** | `node/vault-app.js` | AppRole, OIDC | `GET /health` on `:8080` | setTimeout loop, re-auth after 3 failures |
| **Go** | `go/main.go` | AppRole, OIDC | `GET /health` on `:8080` | Goroutine with context cancellation |
| **.NET** | `dotnet/Program.cs` | AppRole, OIDC | `GET /health` on `:5000` | Background Task, re-acquires DB creds on failure |
| **Shell** | `shell/vault-env.sh` | AppRole, OIDC | No (wraps a command) | Background subshell, re-auth after 3 failures |

## When to Use Each

**Python** — Data pipelines, ML workloads, backend services where `hvac` is already in the dependency tree. The daemon-mode pattern (no HTTP server) suits workers and batch jobs.

**Node.js** — Web APIs and event-driven services. The Express health endpoint integrates directly with load balancer health checks and readiness probes.

**Go** — Performance-critical services, CLI tools, infrastructure components. Uses the official HashiCorp Vault client with zero additional dependencies beyond the standard library.

**.NET** — Enterprise services on .NET 8+. Uses VaultSharp with Minimal API for a low-ceremony health endpoint. Fits into existing ASP.NET deployment patterns.

**Shell** — Wrapping legacy applications or any binary that reads config from environment variables. Authenticates, exports secrets as `APP_*` env vars, then `exec`s the target command. No code changes to the wrapped application.

## Common Environment Variables

All examples read the same set of environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VAULT_ADDR` | Yes | — | Vault server URL |
| `VAULT_AUTH_METHOD` | No | `approle` | `approle` or `oidc` |
| `VAULT_ROLE` | No | `myapp` | Vault role name |
| `VAULT_ROLE_ID` | If AppRole | — | AppRole role ID |
| `VAULT_SECRET_ID` | If AppRole | — | AppRole secret ID (single-use) |
| `VAULT_OIDC_TOKEN` | If OIDC | — | Pre-obtained OIDC JWT |
| `VAULT_KV_PATH` | No | `kv/data/dev/apps/myapp/config` | KV v2 secret path |
| `VAULT_DB_ROLE` | No | `myapp-db` | Database secret engine role |
| `VAULT_NAMESPACE` | No | — | Vault namespace (enterprise) |
| `PORT` | No | `8080` | Health endpoint listen port |

## Common Patterns

Every example follows the same five-step integration sequence:

1. **Authenticate** — AppRole (machine-to-machine) or OIDC (identity-based). Auth method is selected at runtime via `VAULT_AUTH_METHOD`.

2. **Start renewal** — A background process renews the auth token and any tracked leases at 2/3 of the TTL. This provides margin for transient network failures.

3. **Read KV v2 secrets** — Static configuration (API keys, feature flags, connection strings) is read once and exported as `APP_*` environment variables.

4. **Acquire dynamic DB credentials** — Short-lived database credentials are requested from the database secret engine. The lease is tracked for renewal.

5. **Run the application** — The health endpoint (where present) exposes secret metadata (never values) for observability: whether secrets are loaded, credential usernames, lease expiry times, and recent renewal errors.

## Security Model

- **Secret ID delivery** — AppRole `secret_id` values should be single-use and delivered by a trusted init container or orchestrator, never baked into images.
- **TLS verification** — All examples verify TLS by default using the system CA bundle. Set `VAULT_CACERT` (or language equivalent) for custom CA bundles.
- **No secrets in logs** — Only usernames, lease durations, and key names are logged. Secret values are never written to stdout/stderr.
- **Graceful degradation** — Health endpoints return HTTP 503 when credentials are expired or renewal has failed, allowing load balancers to route traffic away.
- **Namespace isolation** — All examples support Vault Enterprise namespaces via `VAULT_NAMESPACE`.

## Quick Start

### AppRole Authentication

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_AUTH_METHOD=approle
export VAULT_ROLE_ID=db02de05-fa39-4855-059b-67221c5c2f63
export VAULT_SECRET_ID=6a174c20-f6de-a53c-74d2-6018fcceff64
export VAULT_KV_PATH=kv/data/dev/apps/myapp/config
export VAULT_DB_ROLE=myapp-db
```

### Python

```bash
cd python
pip install -r requirements.txt
python vault_app.py
```

### Node.js

```bash
cd node
npm install
node vault-app.js
```

### Go

```bash
cd go
go run main.go
```

### .NET

```bash
cd dotnet
dotnet run
```

### Shell Wrapper

```bash
cd shell
./vault-env.sh my-app --flag1 --flag2
```

## Existing Examples

The `examples/` directory also contains other reference material:

- `app/` — Application onboarding guide for the secrets platform
- `mtls/` — Mutual TLS patterns: Vault PKI setup, Envoy sidecar, nginx, and direct app examples (Python, Go)
- `policies/` — Branch protection checklists
- `siem/` — Vault audit log integration configs for Splunk and ELK
- `vm/` — Cloud-init and systemd configurations for Vault Agent on VMs
