# mTLS and Workload Identity Guide

## Purpose

This document covers how to establish cryptographic workload identity and mutual TLS across heterogeneous environments — VMs, containers, serverless functions, and bare-metal hosts — without requiring a specific orchestrator. Vault's PKI secrets engine serves as the universal certificate authority, and mTLS provides the authentication layer for service-to-service communication.

## The workload identity problem

Every service-to-service call needs to answer two questions:

1. **Who is the caller?** (authentication)
2. **Is the caller allowed to do this?** (authorization)

In Kubernetes, the platform provides identity through ServiceAccounts and projected tokens. Outside Kubernetes, there is no default identity layer. VMs, containers on bare Docker, ECS tasks, Lambda functions, and systemd services all lack a built-in way to prove who they are.

Without a standard identity mechanism, teams fall back to:

- Shared secrets (API keys, passwords) that are hard to rotate and easy to leak
- IP-based allowlists that break when infrastructure changes
- VPN tunnels that provide network-level trust but no per-service identity
- Self-signed certificates managed manually with no rotation or revocation

All of these create operational fragility and expand the blast radius of a compromise.

## Workload identity without Kubernetes

### VM-based workloads

VMs prove their identity to Vault through platform-native attestation:

| Cloud | Auth Method | Identity Source |
|-------|-------------|-----------------|
| AWS | `aws` IAM auth | EC2 instance metadata / IAM role |
| GCP | `gcp` auth | GCE metadata / service account |
| Azure | `azure` auth | Managed identity / IMDS |
| On-premises | `approle` or `cert` | Delivered by configuration management (Ansible, Puppet) or cloud-init |

The pattern:

1. VM boots and has a platform-native identity (instance role, managed identity)
2. Vault Agent runs on the VM and authenticates using the platform identity
3. Vault Agent requests a workload certificate from the PKI engine
4. Vault Agent writes the certificate to disk and keeps it rotated
5. The application uses the certificate for mTLS connections

For on-premises VMs without cloud metadata, bootstrap with `approle`:

1. Configuration management delivers a one-time-use `secret_id` to the VM
2. Vault Agent authenticates with `role_id` (baked into the image) + `secret_id` (delivered at provisioning)
3. After initial auth, Vault Agent maintains the session through token renewal
4. Subsequent certificate issuance uses the Vault token, not the original AppRole credentials

### Container workloads (non-Kubernetes)

Docker containers, ECS tasks, and similar runtimes:

| Runtime | Auth Method | Identity Source |
|---------|-------------|-----------------|
| Docker (bare) | `approle` | Secret ID injected via orchestrator or init container |
| ECS | `aws` IAM auth | Task IAM role from ECS metadata |
| Cloud Run | `gcp` auth | Service account attached to revision |
| Nomad | `jwt` auth | Nomad workload identity JWT |

The same pattern applies: the runtime provides a bootstrap identity, Vault exchanges it for a workload certificate.

### Serverless functions

Serverless functions are short-lived and may not justify a persistent Vault Agent. Options:

1. **Function-scoped auth** — The function authenticates to Vault on each invocation using cloud IAM (AWS Lambda IAM role, GCP service account). Request a very short TTL certificate (minutes) for the duration of the invocation. Overhead is acceptable for functions that run seconds to minutes.

2. **Pre-provisioned certificates** — A CI/CD pipeline or deployment hook requests a certificate from Vault and injects it into the function's environment or secret store. The certificate TTL matches the deployment cycle. Rotation happens on re-deploy.

3. **API gateway termination** — Place an mTLS-terminating API gateway in front of the function. The gateway handles certificate management; the function receives authenticated metadata in headers.

### Bare-metal and legacy systems

For systems that cannot run Vault Agent:

1. **Consul Template** — Watches Vault PKI leases and renders certificate files. Lighter than Vault Agent.
2. **Cron-based rotation** — A scheduled job calls the Vault API to issue new certificates and restarts the service. Acceptable when the system supports graceful TLS reload.
3. **Push-based delivery** — A central automation system (Ansible, Salt) periodically fetches certificates from Vault and distributes them to targets via SSH.

## Vault PKI as the universal CA

### Architecture

```
┌─────────────────────────────────────┐
│          Vault PKI Engine           │
│                                     │
│   ┌───────────┐   ┌─────────────┐  │
│   │  Root CA   │──▶│Intermediate │  │
│   │ (offline   │   │    CA       │  │
│   │  or Vault) │   │ (issuing)   │  │
│   └───────────┘   └──────┬──────┘  │
│                          │         │
└──────────────────────────┼─────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
         ┌────▼────┐  ┌───▼────┐  ┌───▼────┐
         │ VM certs │  │Container│  │Serverless│
         │ via Agent│  │certs    │  │certs via │
         │          │  │via init │  │IAM auth  │
         └─────────┘  └────────┘  └──────────┘
```

### Root CA management

Two options:

1. **Vault-managed root** — The root CA private key lives in Vault. Simpler to set up. Acceptable when Vault's security posture is sufficient for your threat model.

2. **External root** — Generate the root CA offline (air-gapped HSM or ceremony). Import only the root certificate into Vault. Create an intermediate CA in Vault and sign it with the external root. The root private key never touches Vault. Required for high-assurance environments (FedRAMP High, financial services).

### PKI role design

PKI roles constrain certificate issuance. Design roles per service class:

| Role | Allowed Domains | Server Flag | Client Flag | Max TTL | Use Case |
|------|-----------------|-------------|-------------|---------|----------|
| `server-internal` | `*.internal` | yes | no | 72h | Server certificates for internal services |
| `client-internal` | `*.internal` | no | yes | 24h | Client certificates for service-to-service auth |
| `dual-internal` | `*.internal` | yes | yes | 24h | Services that are both servers and clients |
| `server-external` | `*.example.com` | yes | no | 720h | External-facing services (longer TTL for DNS propagation) |

Bind roles to Vault policies so that each service identity can only request certificates for its own name:

```hcl
# Policy: web-api can only issue certs for web-api.internal
path "pki_int/issue/server-internal" {
  capabilities = ["update"]
  allowed_parameters = {
    "common_name" = ["web-api.internal"]
    "alt_names"   = ["web-api.internal,web-api"]
  }
}
```

## Certificate-based auth to Vault itself

Vault supports TLS certificate authentication — a service presents its Vault-issued certificate to authenticate to Vault and obtain a Vault token. This creates a bootstrapping loop that works well for certificate rotation:

1. Service starts with an initial certificate (from first provisioning)
2. Service authenticates to Vault using `cert` auth method with the certificate
3. Vault returns a token scoped to the service's policy
4. Service uses the token to request a fresh certificate from PKI
5. Next rotation cycle: use the new certificate to re-authenticate

Configuration:

```bash
# Enable cert auth
vault auth enable cert

# Create a cert auth role — trust certificates issued by our intermediate CA
vault write auth/cert/certs/internal-services \
    display_name="internal-services" \
    certificate=@intermediate-ca.pem \
    allowed_common_names="*.internal" \
    token_ttl=1h \
    token_max_ttl=4h \
    token_policies="service-default"
```

This eliminates the need for AppRole or cloud IAM auth after initial bootstrap — the certificate itself becomes the authentication credential.

## mTLS deployment patterns

### Sidecar pattern

A proxy (Envoy, nginx, HAProxy) runs alongside the application and handles all TLS operations.

```
Client ──mTLS──▶ Envoy Sidecar ──plaintext──▶ App (localhost)
```

**Advantages:**
- Application is TLS-unaware — no code changes, no TLS libraries to update
- Certificate rotation is transparent (Envoy SDS, nginx reload)
- Consistent TLS configuration across all services regardless of language
- Centralized logging of TLS metadata (peer identity, cipher suite)

**Disadvantages:**
- Additional resource overhead (CPU, memory, latency) per service
- Operational complexity of managing sidecar lifecycle
- Debugging requires understanding the proxy layer

**Best for:** Polyglot environments, legacy applications, teams that want to separate security concerns from application code.

See: `examples/mtls/envoy-sidecar/envoy.yaml`, `examples/mtls/nginx-mtls.conf`

### Library pattern

The application uses a TLS-aware library (language SDK) that handles certificate loading, rotation, and mTLS handshakes.

```
Client (TLS lib) ──mTLS──▶ Server (TLS lib)
```

**Advantages:**
- No additional processes or proxies
- Lower latency (no extra network hop through sidecar)
- Full control over TLS behavior in application code
- Can implement connection-level authorization based on peer cert fields

**Disadvantages:**
- Every application must implement TLS correctly
- Language-specific — each language has different TLS APIs and quirks
- Certificate rotation requires application-level coordination

**Best for:** Performance-sensitive services, applications that need certificate field extraction for authorization, CLI tools.

See: `examples/mtls/app-direct/`

### Direct pattern (Vault Agent + application TLS)

Vault Agent manages certificates on disk. The application loads them using native TLS configuration (no Vault SDK needed).

```
Vault Agent ──writes certs──▶ Filesystem ──reads──▶ App (native TLS)
```

**Advantages:**
- Application uses standard TLS configuration (no Vault dependency in code)
- Vault Agent handles authentication, issuance, and rotation
- Works with any application that supports TLS certificate configuration
- Certificates are just files — standard debugging with `openssl x509`

**Disadvantages:**
- Application must handle certificate reload (SIGHUP, file watcher, restart)
- Vault Agent is an additional process to manage
- File permissions must be carefully set (private keys readable only by the app)

**Best for:** Applications that already support TLS configuration via files, VM-based deployments, environments where you want to decouple secret management from application code.

See: `examples/vm/` for Vault Agent configuration patterns.

## Rotation and revocation strategies

### Rotation cadence

| Certificate Type | Recommended TTL | Rotation Trigger | Rationale |
|-----------------|-----------------|------------------|-----------|
| Internal service (server) | 24h | At 2/3 TTL (16h) | Short enough that revocation is rarely needed |
| Internal service (client) | 12-24h | At 2/3 TTL | Client certs can be shorter since they are always outbound |
| External-facing | 30-90 days | At 2/3 TTL or on deploy | Longer TTL for DNS/CDN propagation; use OCSP/CRL for revocation |
| Intermediate CA | 1-5 years | Manual ceremony | Rotation requires re-issuing all leaf certificates |
| Root CA | 10-20 years | Manual ceremony | Cross-signing for smooth transitions |

### Rotation implementation

**Vault Agent template** — The recommended approach for most deployments:

```hcl
template {
  contents    = "{{ with pkiCert \"pki_int/issue/server-internal\" \"common_name=web-api.internal\" \"ttl=24h\" }}{{ .Cert }}{{ .CA }}{{ .Key }}{{ end }}"
  destination = "/etc/certs/web-api.pem"
  perms       = 0600
  command     = "systemctl reload web-api"
}
```

Vault Agent monitors the certificate lease and re-renders the template before expiry. The `command` triggers a graceful reload of the application.

**Go `GetCertificate` callback** — For Go applications, implement dynamic certificate loading:

```go
tlsConfig := &tls.Config{
    GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
        // Load the current certificate from disk or cache
        // This is called on every TLS handshake, so always returns
        // the latest certificate even after rotation
        return loadCurrentCert()
    },
}
```

### Revocation strategy

With short-lived certificates (< 24h), revocation is usually unnecessary. The certificate expires before a CRL or OCSP response could propagate to all verifiers. This is a deliberate design choice that simplifies operations.

For longer-lived certificates or compliance requirements that mandate revocation capability:

1. **Vault CRL** — Vault generates a CRL at `/v1/pki_int/crl`. Configure clients to check it periodically. CRL distribution works for small-to-medium environments but does not scale to thousands of services checking frequently.

2. **OCSP** — Vault can serve as an OCSP responder. Clients check certificate validity in real-time. More scalable than CRL but adds latency to every connection unless OCSP stapling is used.

3. **OCSP stapling** — The server fetches its own OCSP response from Vault and staples it to the TLS handshake. Clients verify the stapled response without contacting the CA. Best approach for external-facing services. See `examples/mtls/nginx-mtls.conf` for configuration.

4. **Certificate pinning** — Services maintain a local list of trusted certificate serial numbers or public keys. On revocation, remove the entry and services reject the certificate on next connection. Operational complexity is high; prefer short TTLs instead.

### Emergency revocation

When a private key is compromised:

1. Revoke the certificate in Vault: `vault write pki_int/revoke serial_number=<serial>`
2. Rotate the CRL: `vault read pki_int/crl/rotate`
3. Issue a new certificate for the affected service
4. If using short TTLs, the compromised certificate expires soon regardless

For a compromised intermediate CA:

1. Revoke the intermediate certificate from the root CA
2. Generate a new intermediate CA
3. Re-issue all leaf certificates (this is a significant operational event)
4. Consider cross-signing to provide a grace period for rotation

## Observability

### What to monitor

| Metric | Source | Alert Threshold |
|--------|--------|----------------|
| Certificate expiry | Vault Agent logs, Prometheus cert exporter | < 1/3 of TTL remaining |
| Issuance failures | Vault audit log | Any failure |
| CRL freshness | Vault CRL endpoint | > 2x rotation interval |
| TLS handshake errors | Application/proxy logs | Spike above baseline |
| Client cert verification failures | Proxy access logs | Any unexpected failure |

### Vault audit log integration

Every certificate issuance produces a Vault audit log entry containing:

- Requesting identity (auth method, role, entity)
- PKI role used
- Common name and SANs requested
- TTL granted
- Serial number issued

Forward these to your SIEM for compliance and incident investigation. See `examples/siem/` for Splunk and ELK integration patterns.

## Migration path

For organizations moving from no mTLS to full mTLS:

### Phase 1 — Establish the CA hierarchy

- Deploy Vault PKI engine with root and intermediate CAs
- Create PKI roles for your service classes
- Issue test certificates and verify the chain

### Phase 2 — Deploy in permissive mode

- Configure servers to request (but not require) client certificates
- Use `ssl_verify_client optional` in nginx or `tls.VerifyClientCertIfGiven` in Go
- Log which services present certificates and which do not
- Build a service inventory from the logs

### Phase 3 — Enforce mTLS for new services

- All new services must use mTLS from day one
- Existing services that have been verified in Phase 2 switch to required mode
- Set a deadline for remaining services

### Phase 4 — Full enforcement

- Switch all services to require client certificates
- Monitor for handshake failures and remediate
- Establish rotation automation and runbooks

This phased approach avoids a big-bang cutover and lets teams adopt incrementally.
