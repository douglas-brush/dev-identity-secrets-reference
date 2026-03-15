# SPIFFE/SPIRE Integration

## What is SPIFFE?

SPIFFE (Secure Production Identity Framework for Everyone) provides cryptographic workload identity. Instead of static credentials, workloads receive short-lived X.509 certificates (SVIDs) that prove their identity. SPIRE is the reference implementation.

## When to Use SPIFFE/SPIRE

Use SPIFFE/SPIRE when you need:

- **Zero-trust service-to-service authentication** — mTLS between workloads without managing certificates manually
- **Cross-cluster or cross-cloud identity** — workloads in different clusters or clouds need to authenticate to each other via federation
- **Identity-based authorization** — access control decisions based on verified workload identity rather than network position
- **Replacement for static service credentials** — eliminate shared secrets, API keys, or static certificates for inter-service communication

Do NOT use SPIFFE/SPIRE when:

- **cert-manager is sufficient** — if you only need TLS certificates for ingress or simple mTLS within a single cluster, cert-manager is simpler
- **Cloud-native identity covers your case** — if all workloads are in a single cloud and can use IRSA/Workload Identity natively
- **You lack operational capacity** — SPIRE requires operational investment (server HA, trust bundle distribution, registration management)

## Architecture

```
┌─────────────────────────────────────────────┐
│                SPIRE Server                  │
│  - Issues SVIDs to attested agents           │
│  - Manages registration entries              │
│  - Maintains trust bundle                    │
│  - Supports federation with other domains    │
└──────────────┬──────────────────────────────┘
               │ Node Attestation (k8s PSAT)
               │
┌──────────────▼──────────────────────────────┐
│          SPIRE Agent (DaemonSet)             │
│  - Runs on every node                        │
│  - Attests workloads via k8s API             │
│  - Issues SVIDs to matched workloads         │
│  - Exposes Workload API (Unix socket)        │
└──────────────┬──────────────────────────────┘
               │ Workload API (Unix socket)
               │
    ┌──────────▼──────────┐
    │  SPIFFE CSI Driver   │ ← Recommended: exposes socket as CSI volume
    │  (or hostPath mount) │
    └──────────┬──────────┘
               │
    ┌──────────▼──────────┐
    │  Workload Pod        │
    │  - Gets X.509 SVID   │
    │  - Auto-rotated       │
    │  - No static creds    │
    └─────────────────────┘
```

## Files in This Directory

| File | Purpose |
|------|---------|
| `spire-server.yaml` | SPIRE Server StatefulSet, ConfigMap, RBAC, and Service |
| `spire-agent.yaml` | SPIRE Agent DaemonSet, ConfigMap, and RBAC |
| `spiffe-csi-driver.yaml` | CSI driver for exposing Workload API to pods |
| `clusterspiffeid-example.yaml` | ClusterSPIFFEID for automatic workload registration |

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

Use a SPIFFE-aware SDK (go-spiffe, java-spiffe, etc.) to fetch SVIDs from the Workload API socket.

## Trust Bundle Distribution

The SPIRE Server automatically populates the `spire-bundle` ConfigMap with the current trust bundle. Workloads that need to validate peer SVIDs should mount this ConfigMap or use the Workload API to fetch the bundle.

## Federation

To federate with another SPIFFE trust domain:

1. Exchange trust bundles between SPIRE Servers
2. Configure `ClusterFederatedTrustDomain` resources
3. Add `federatesWith` to relevant `ClusterSPIFFEID` entries

This enables workloads in different trust domains to authenticate each other without shared secrets.
