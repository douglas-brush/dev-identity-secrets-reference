# Direct Application mTLS Examples

These examples show how to implement mTLS directly in application code using Vault-issued certificates. Use this pattern when:

- You cannot or do not want to run a sidecar proxy (Envoy, nginx)
- The application needs fine-grained control over TLS behavior
- You want to extract client certificate fields for authorization logic
- You are building a CLI tool or daemon that communicates over mTLS

## Files

| File | Language | Description |
|------|----------|-------------|
| `python-mtls-server.py` | Python 3 | HTTPS server requiring client certificates |
| `python-mtls-client.py` | Python 3 | HTTPS client presenting a client certificate |
| `go-mtls-server.go` | Go | HTTPS server with mutual TLS authentication |

## Prerequisites

1. Vault PKI certificates issued using `../vault-pki-mtls.sh`:

```bash
cd ..
./vault-pki-mtls.sh setup
./vault-pki-mtls.sh issue-both
```

This creates `./certs/` with server and client certificates signed by the Vault CA.

2. Python 3.7+ (for the Python examples — no external dependencies)
3. Go 1.21+ (for the Go example)

## Quick start

### Terminal 1 — Start the Python mTLS server

```bash
export MTLS_SERVER_CERT=../certs/server.pem
export MTLS_SERVER_KEY=../certs/server-key.pem
export MTLS_CA_BUNDLE=../certs/ca-bundle.pem
python3 python-mtls-server.py
```

### Terminal 2 — Connect with the Python mTLS client

```bash
export MTLS_CLIENT_CERT=../certs/client.pem
export MTLS_CLIENT_KEY=../certs/client-key.pem
export MTLS_CA_BUNDLE=../certs/ca-bundle.pem
export MTLS_SERVER_URL=https://localhost:8443
python3 python-mtls-client.py
```

Expected output:

```json
{
  "message": "mTLS authentication successful",
  "client": {
    "subject_cn": "api-client.internal",
    "issuer_cn": "Example Corp Intermediate CA",
    "serial": "...",
    "not_before": "...",
    "not_after": "..."
  },
  "server_time": "2024-01-15T10:30:00+00:00"
}
```

### Alternative — Start the Go mTLS server

```bash
export MTLS_SERVER_CERT=../certs/server.pem
export MTLS_SERVER_KEY=../certs/server-key.pem
export MTLS_CA_BUNDLE=../certs/ca-bundle.pem
go run go-mtls-server.go
```

The Python client works identically against the Go server.

### Testing with curl

```bash
# With client certificate — should succeed
curl --cacert ../certs/ca-bundle.pem \
     --cert ../certs/client.pem \
     --key ../certs/client-key.pem \
     https://localhost:8443/whoami

# Without client certificate — should fail with SSL error
curl --cacert ../certs/ca-bundle.pem \
     https://localhost:8443/whoami
```

## Certificate rotation

These examples load certificates at startup. For production, implement one of:

**File watcher** — Monitor certificate files for changes and reload the TLS config. In Go, use `tls.Config.GetCertificate` or `GetConfigForClient` callbacks to load fresh certificates on each connection. In Python, recreate the `SSLContext` and update the server socket.

**Restart on rotation** — Vault Agent or a sidecar process writes new certificates and restarts the application. Simple but causes brief downtime.

**Signal-based reload** — Send SIGHUP to the process to trigger TLS config reload. Common in long-running daemons.

For zero-downtime rotation without application changes, use the sidecar pattern (`../envoy-sidecar/` or `../nginx-mtls.conf`) instead.

## Authorization beyond authentication

mTLS proves the client's identity. Authorization — what the client is allowed to do — requires additional logic. Common patterns:

1. **CN-based routing** — Extract the client certificate's Common Name and map it to permissions. Simple but brittle.
2. **SAN-based RBAC** — Use Subject Alternative Names (DNS, URI, or SPIFFE ID) as the identity claim for role-based access control.
3. **Certificate field extraction** — Pass `X-Client-Cert-Subject` headers to backend services (as shown in `../nginx-mtls.conf`) and let the backend enforce authorization.
4. **OPA/policy engine** — Send the client certificate fields to Open Policy Agent for fine-grained authorization decisions.
