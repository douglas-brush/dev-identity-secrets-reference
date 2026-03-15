# Mutual TLS (mTLS) Patterns

Mutual TLS authenticates **both** sides of every connection. Unlike standard TLS where only the server proves its identity, mTLS requires the client to present a certificate too. This is the foundation of zero-trust service-to-service communication: no implicit trust based on network position, every request is authenticated cryptographically.

## Why mTLS matters for zero-trust

Traditional perimeter security assumes that anything inside the network is trusted. That assumption fails when:

- An attacker pivots laterally after initial compromise
- A misconfigured service exposes internal APIs
- Multi-tenant environments share network segments
- Compliance frameworks (SOC 2, FedRAMP, PCI DSS) require encrypted internal traffic with mutual authentication

mTLS eliminates implicit trust. Every service must prove its identity with a certificate signed by a trusted CA before any data flows. Combined with short-lived certificates and automated rotation, this creates a continuously verified communication layer.

## How Vault PKI enables mTLS without a service mesh

HashiCorp Vault's PKI secrets engine acts as an internal certificate authority. It issues short-lived X.509 certificates on demand, eliminating the need for a full service mesh when your requirements are straightforward.

**What Vault PKI provides:**

- **Root and intermediate CA hierarchy** — Vault manages the CA chain. Root CA stays offline (or in Vault with restricted access), intermediates issue leaf certificates.
- **On-demand certificate issuance** — Services request certificates via the Vault API at startup or on a schedule. No manual CSR workflows.
- **Short TTLs** — Issue certificates with 24-hour or shorter lifetimes. Short-lived certificates reduce the blast radius of a compromised key and eliminate the need for CRL/OCSP infrastructure in many cases.
- **Role-based issuance** — PKI roles constrain which SANs, key types, and TTLs a given Vault identity can request. A web frontend role cannot request a certificate for the database service.
- **Audit trail** — Every certificate issuance is logged in Vault's audit log with the requesting identity, role, and parameters.

**What Vault PKI does NOT provide:**

- Traffic routing, retries, circuit breaking (that is what a service mesh does)
- Automatic sidecar injection
- L7 traffic policies

## Decision tree: Vault PKI vs. service mesh vs. SPIFFE

```
Do you need L7 traffic management (retries, circuit breaking, traffic splitting)?
├── Yes → Service mesh (Istio, Linkerd, Consul Connect)
│         The mesh handles mTLS transparently plus gives you traffic policies.
│         Vault can still be the root CA backing the mesh's certificate issuance.
│
└── No → Do you need a universal identity framework across heterogeneous platforms?
         ├── Yes → SPIFFE/SPIRE
         │         SPIFFE provides a standard identity format (SPIFFE ID + SVID)
         │         that works across Kubernetes, VMs, bare metal, and serverless.
         │         Vault can act as an upstream CA for SPIRE.
         │
         └── No → Vault PKI direct
                   Simplest option. Services request certificates directly from
                   Vault and configure TLS themselves. Works everywhere Vault
                   is reachable. Best for:
                   - VM-based deployments
                   - Small-to-medium service counts
                   - Environments where adding a mesh is disproportionate overhead
                   - Legacy applications that already support TLS configuration
```

**Hybrid approaches are common.** A Kubernetes cluster might run a service mesh for in-cluster traffic while VM workloads use Vault PKI directly. Vault serves as the root CA for both, providing a single trust anchor.

## Certificate lifecycle for service-to-service auth

### Issuance

1. Service authenticates to Vault (AppRole, OIDC, cloud IAM, cert auth)
2. Service requests a certificate from the PKI engine for its identity (e.g., `web-api.prod.internal`)
3. Vault validates the request against the PKI role constraints
4. Vault returns the signed certificate, private key, and CA chain
5. Service configures its TLS listener and/or client with the new material

### Rotation

Short-lived certificates (< 24h TTL) should be rotated proactively:

- **Sidecar pattern** — Vault Agent or Envoy SDS fetches new certificates before expiry and writes them to a shared volume or serves them via API. The application does not handle rotation.
- **Library pattern** — Application uses a Vault client library that renews certificates in a background thread. The TLS configuration is updated in-place.
- **Direct pattern** — Application sets a timer at 2/3 of the certificate TTL, requests a new certificate from Vault, and reloads its TLS config.

### Revocation

With short-lived certificates, revocation is often unnecessary — the certificate expires before a revocation list could propagate. For longer-lived certificates:

- Vault supports CRL (Certificate Revocation List) generation
- OCSP responder can be configured for real-time revocation checks
- Tidy operations clean up expired certificates from Vault storage

### Trust chain verification

Both sides of an mTLS connection must:

1. Present their own certificate + key
2. Verify the peer's certificate against the trusted CA bundle
3. Optionally verify SANs or other certificate fields for authorization
4. Reject expired, revoked, or untrusted certificates

## Examples in this directory

| File / Directory | Description |
|------------------|-------------|
| `vault-pki-mtls.sh` | End-to-end Vault PKI setup: CA hierarchy, role creation, cert issuance, rotation |
| `envoy-sidecar/envoy.yaml` | Envoy proxy config with SDS for transparent mTLS sidecaring |
| `nginx-mtls.conf` | nginx configuration for mTLS with client cert verification and OCSP |
| `app-direct/` | Direct application mTLS in Python and Go using Vault-issued certs |

## Related documentation

- `docs/16-mtls-workload-identity-guide.md` — Architecture guide for workload identity and mTLS deployment patterns
- `docs/02-reference-architecture.md` — Overall secrets management reference architecture
- `examples/vm/` — Vault Agent patterns for VM-based certificate delivery
