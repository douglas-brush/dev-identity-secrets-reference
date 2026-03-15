# SPIFFE/SPIRE Integration

> **Reference Example -- Not Production-Ready**
>
> The manifests in this directory are reference examples that illustrate the
> architecture and component relationships for a SPIFFE/SPIRE deployment on
> Kubernetes. They contain placeholder values (trust domain, cluster name,
> resource sizing) that **must** be replaced with environment-specific
> configuration before use. See [What You Must Change](#what-you-must-change)
> below.

## What is SPIFFE?

SPIFFE (Secure Production Identity Framework for Everyone) provides
cryptographic workload identity. Instead of static credentials, workloads
receive short-lived X.509 certificates (SVIDs) that prove their identity.
SPIRE is the reference implementation.

## When to Use SPIFFE/SPIRE

Use SPIFFE/SPIRE when you need:

- **Zero-trust service-to-service authentication** -- mTLS between workloads
  without managing certificates manually
- **Cross-cluster or cross-cloud identity** -- workloads in different clusters
  or clouds need to authenticate to each other via federation
- **Identity-based authorization** -- access control decisions based on
  verified workload identity rather than network position
- **Replacement for static service credentials** -- eliminate shared secrets,
  API keys, or static certificates for inter-service communication

Do NOT use SPIFFE/SPIRE when:

- **cert-manager is sufficient** -- if you only need TLS certificates for
  ingress or simple mTLS within a single cluster, cert-manager is simpler
- **Cloud-native identity covers your case** -- if all workloads are in a
  single cloud and can use IRSA/Workload Identity natively
- **You lack operational capacity** -- SPIRE requires operational investment
  (server HA, trust bundle distribution, registration management)

## Architecture

```
+---------------------------------------------+
|                SPIRE Server                  |
|  - Issues SVIDs to attested agents           |
|  - Manages registration entries              |
|  - Maintains trust bundle                    |
|  - Supports federation with other domains    |
+--------------------+------------------------+
                     | Node Attestation (k8s PSAT)
                     |
+--------------------v------------------------+
|          SPIRE Agent (DaemonSet)             |
|  - Runs on every node                        |
|  - Attests workloads via k8s API             |
|  - Issues SVIDs to matched workloads         |
|  - Exposes Workload API (Unix socket)        |
+--------------------+------------------------+
                     | Workload API (Unix socket)
                     |
          +----------v----------+
          |  SPIFFE CSI Driver   |  <-- Recommended: exposes socket as CSI volume
          |  (or hostPath mount) |
          +----------+----------+
                     |
          +----------v----------+
          |  Workload Pod        |
          |  - Gets X.509 SVID   |
          |  - Auto-rotated       |
          |  - No static creds    |
          +---------------------+
```

## What Is Included

| File | Purpose | Status |
|------|---------|--------|
| `spire-server.yaml` | SPIRE Server StatefulSet, ConfigMap, RBAC, Service, trust bundle ConfigMap | Reference -- requires environment-specific values |
| `spire-agent.yaml` | SPIRE Agent DaemonSet, ConfigMap, RBAC | Reference -- requires environment-specific values |
| `spiffe-csi-driver.yaml` | CSI driver DaemonSet for exposing Workload API to pods | Reference -- generally usable as-is |
| `clusterspiffeid-example.yaml` | ClusterSPIFFEID examples for automatic workload registration | Reference -- application-specific, adapt to your workloads |

## What Is NOT Included

This reference does **not** cover:

- **SPIRE Controller Manager deployment** -- required for `ClusterSPIFFEID`
  CRDs to function. Install separately via the
  [spire-controller-manager Helm chart](https://github.com/spiffe/spire-controller-manager)
  or manifests.
- **SPIRE CRD definitions** -- the `ClusterSPIFFEID` and
  `ClusterFederatedTrustDomain` CRDs must be installed before applying
  these manifests. They ship with the SPIRE Controller Manager.
- **High availability** -- the server uses `replicas: 1` with SQLite. Production
  deployments should use PostgreSQL and multiple replicas behind a leader
  election mechanism.
- **External datastore (PostgreSQL)** -- the reference uses SQLite, which does
  not support HA or durable storage beyond the PVC.
- **UpstreamAuthority plugin** -- the reference uses SPIRE's self-signed CA.
  Production deployments should chain to an organizational PKI using the
  `disk`, `vault`, `aws_pca`, or `gcp_cas` UpstreamAuthority plugins.
- **Key management hardening** -- the reference uses `KeyManager "disk"`. For
  production, consider `KeyManager "aws_kms"`, `"gcp_kms"`, or `"vault"`.
- **Federation configuration** -- the server config contains a commented-out
  federation block. Cross-domain trust requires configuring bundle endpoints
  and `ClusterFederatedTrustDomain` resources.
- **Network policies** -- you should restrict which pods can reach the SPIRE
  Server gRPC port and which namespaces the agent serves.
- **Monitoring and alerting** -- SPIRE exposes Prometheus metrics; scrape
  configuration and alert rules are environment-specific.
- **Backup and recovery** -- the SPIRE datastore and key material require
  backup procedures not shown here.

## What You Must Change

Before deploying, replace these placeholder values:

| Placeholder | Location | Replace With |
|-------------|----------|--------------|
| `trust_domain = "example.com"` | `spire-server.yaml`, `spire-agent.yaml` | Your organization's trust domain (e.g., `prod.mycompany.com`) |
| `cluster = "my-cluster"` / `clusters = { "my-cluster" = ... }` | Both server and agent configs | Your actual Kubernetes cluster name |
| `database_type = "sqlite3"` | `spire-server.yaml` | `"postgres"` for production with appropriate `connection_string` |
| `KeyManager "disk"` | `spire-server.yaml` | Cloud KMS or Vault-backed KeyManager for production |
| Resource requests/limits | All manifests | Right-size based on workload count and attestation volume |
| `ca_ttl`, `default_x509_svid_ttl`, `default_jwt_svid_ttl` | `spire-server.yaml` | Values appropriate for your security policy |
| Image tags (`1.9.6`, `0.2.6`) | All manifests | Pin to your tested version; do not use `latest` |

## Deployment Order

If adapting these manifests for use:

1. Install SPIRE CRDs (from spire-controller-manager)
2. Apply `spire-server.yaml` (creates namespace, RBAC, server, bundle ConfigMap)
3. Wait for the server to become ready and populate `spire-bundle` ConfigMap
4. Apply `spire-agent.yaml` (agents wait for bundle, then connect to server)
5. Apply `spiffe-csi-driver.yaml` (registers CSI driver with kubelet)
6. Deploy SPIRE Controller Manager (manages ClusterSPIFFEID lifecycle)
7. Apply `clusterspiffeid-example.yaml` (or your own ClusterSPIFFEID resources)
8. Label target namespaces with `spiffe.io/workload-identity: "true"`

## Consuming SVIDs in Workloads

Mount the SPIFFE CSI volume in your pod spec:

```yaml
volumes:
  - name: spiffe-workload-api
    csi:
      driver: csi.spiffe.io
      readOnly: true
containers:
  - name: app
    volumeMounts:
      - name: spiffe-workload-api
        mountPath: /spiffe-workload-api
        readOnly: true
    env:
      - name: SPIFFE_ENDPOINT_SOCKET
        value: "unix:///spiffe-workload-api/agent.sock"
```

Use a SPIFFE-aware SDK (`go-spiffe`, `java-spiffe`, `py-spiffe`, etc.) to
fetch SVIDs from the Workload API socket. The SDK handles rotation
automatically.

## Trust Bundle Distribution

The SPIRE Server automatically populates the `spire-bundle` ConfigMap with
the current trust bundle via the `k8sbundle` notifier plugin. Workloads that
need to validate peer SVIDs should either:

- Use the Workload API (preferred -- handles rotation automatically)
- Mount the `spire-bundle` ConfigMap for legacy applications

## Federation

To federate with another SPIFFE trust domain:

1. Enable the `federation` block in the SPIRE Server configuration
2. Exchange trust bundles between SPIRE Servers (manual bootstrap or SPIFFE
   Bundle Endpoint)
3. Create `ClusterFederatedTrustDomain` resources pointing to remote bundle
   endpoints
4. Add `federatesWith` to relevant `ClusterSPIFFEID` entries

This enables workloads in different trust domains to authenticate each other
without shared secrets.

## Production Readiness Checklist

Before running SPIRE in production, verify:

- [ ] Trust domain is set to your organization's domain
- [ ] Cluster name matches your actual cluster
- [ ] Datastore is PostgreSQL (not SQLite) with HA
- [ ] UpstreamAuthority chains to your organizational PKI
- [ ] KeyManager uses cloud KMS or Vault
- [ ] Server runs multiple replicas with leader election
- [ ] Network policies restrict access to SPIRE Server
- [ ] Prometheus metrics are scraped and alerting is configured
- [ ] Backup procedures exist for datastore and key material
- [ ] SVID TTLs align with your security policy
- [ ] SPIRE Controller Manager is deployed for ClusterSPIFFEID support
- [ ] Bundle rotation procedures are documented and tested
