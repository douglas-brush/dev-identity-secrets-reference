# SIEM Integration — Vault Audit Log Forwarding

Patterns for forwarding HashiCorp Vault audit logs to Security Information and Event Management (SIEM) platforms.

## Architecture

Vault generates structured JSON audit logs for every authenticated API request. These logs contain:

- Authenticated identity (entity, accessor, policies)
- Request path, operation, and parameters
- Response status and wrap info
- Timestamps and client metadata (IP, user agent)

Sensitive values (tokens, secrets) are HMAC'd in audit logs by default — they are **not** plaintext.

## Forwarding Patterns

| Pattern | File | Use Case |
|---------|------|----------|
| Vault audit device to Splunk | `vault-audit-to-splunk.hcl` | Direct syslog or file-based forwarding to Splunk |
| Vault audit device to ELK | `vault-audit-to-elk.hcl` | File audit device with Logstash/Filebeat pipeline |
| FluentBit sidecar (Kubernetes) | `fluentbit-vault-audit.yaml` | Kubernetes-native log tailing with FluentBit DaemonSet |
| Prometheus/Alertmanager rules | `alert-rules.yaml` | Alerting on secrets-related anomalies |

## Deployment Models

### Model 1: Syslog Audit Device (push)

Vault pushes audit events directly via syslog to a remote collector (Splunk HEC, rsyslog, syslog-ng).

```
Vault → syslog audit device → Splunk HEC / rsyslog → SIEM
```

Best for: Non-Kubernetes deployments, low-latency alerting, direct integration.

### Model 2: File Audit Device + Log Shipper (pull)

Vault writes audit logs to a file. A log shipper (FluentBit, Filebeat, Fluentd) tails the file and forwards.

```
Vault → file audit device → FluentBit/Filebeat → Elasticsearch/Splunk/S3
```

Best for: Kubernetes deployments, buffered delivery, multiple destinations.

### Model 3: Socket Audit Device (push)

Vault pushes audit events to a TCP/UDP socket. A log aggregator listens on the socket.

```
Vault → socket audit device → Logstash/Vector → Elasticsearch/Splunk
```

Best for: High-throughput environments, custom parsing pipelines.

## Key Considerations

1. **Audit device blocking**: Vault will block client requests if all audit devices fail to write. Always configure at least two audit devices for resilience.
2. **HMAC verification**: Use `vault audit list -detailed` to confirm HMAC keys. Rotate HMAC keys periodically.
3. **Log volume**: A busy Vault cluster generates significant log volume. Plan storage and retention accordingly.
4. **Sensitive fields**: Vault HMAC's sensitive fields by default. Set `hmac_accessor=false` only if your SIEM needs raw accessor values for correlation.
5. **mTLS**: When using syslog or socket devices over the network, enforce TLS to protect audit data in transit.

## Alert Rules

The `alert-rules.yaml` file provides Prometheus/Alertmanager rules for:

- Failed authentication attempts (brute force detection)
- Secret access anomalies (unusual read patterns)
- Certificate expiry warnings (cert-manager and Vault PKI)
- Audit device failures (loss of audit trail)
- Token creation spikes (potential credential stuffing)

These rules assume Vault telemetry is scraped by Prometheus (configured in `platform/vault/config/vault-server.hcl`).

## Prerequisites

- Vault audit logging enabled (see `platform/vault/examples/setup-complete.sh`)
- Vault telemetry exposed to Prometheus (configured in `platform/vault/config/vault-server.hcl`)
- Network connectivity from Vault to SIEM ingest endpoints
- TLS certificates for secure log transport
