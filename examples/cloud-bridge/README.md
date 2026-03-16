# Multi-Cloud Secrets Bridge

Reference implementations for synchronizing secrets between HashiCorp Vault and cloud-native secret managers. These scripts demonstrate bidirectional sync patterns with conflict resolution, dry-run support, and webhook notifications.

## When to Use a Secrets Bridge

A secrets bridge makes sense when your organization:

- **Runs workloads across multiple clouds** and each cloud's services need secrets in the native secret manager (e.g., AWS Lambda reading from ASM, Azure Functions reading from AKV).
- **Is migrating between secret managers** and needs a transition period where secrets exist in both systems.
- **Uses Vault as the central authority** but cloud-native services require secrets in provider-native stores for IAM integration, rotation, or compliance.
- **Needs disaster recovery** with secrets replicated to a secondary cloud provider.

A secrets bridge is **not** appropriate when a Vault agent sidecar or CSI provider can inject secrets directly into the workload. Prefer direct Vault integration when possible.

## Architecture

```
                         ┌───────────────┐
                         │  HashiCorp    │
                         │    Vault      │
                         │  (KV v2)      │
                         └──────┬────────┘
                                │
               ┌────────────────┼────────────────┐
               │                │                │
               ▼                ▼                ▼
    ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
    │  AWS Secrets      │ │ Azure Key    │ │ GCP Secret       │
    │  Manager          │ │ Vault        │ │ Manager          │
    │                   │ │              │ │                  │
    │ • Rotation via    │ │ • Immutable  │ │ • Version-based  │
    │   Lambda          │ │   versions   │ │ • IAM conditions │
    │ • Resource policy │ │ • RBAC +     │ │ • Replication    │
    │ • Cross-account   │ │   network    │ │   policies       │
    │   sharing         │ │   ACLs       │ │ • Pub/Sub notify │
    └──────────────────┘ └──────────────┘ └──────────────────┘
```

## Scripts

| Script | Cloud Provider | Key Features |
|--------|---------------|--------------|
| `aws-secrets-manager-bridge.sh` | AWS Secrets Manager | Rotation schedule sync, cross-account support |
| `azure-keyvault-bridge.sh` | Azure Key Vault | Version tracking, content types, tags |
| `gcp-secret-manager-bridge.sh` | GCP Secret Manager | IAM condition bindings, labels, replication |

All scripts share the same interface:

```bash
./<bridge>.sh \
    --direction vault-to-<provider>|<provider>-to-vault|bidirectional \
    --mapping-file bridge-config.yaml \
    --conflict-policy vault-wins|<provider>-wins|newest-wins \
    --dry-run \
    --notify-webhook https://hooks.slack.com/...
```

## Conflict Resolution Policies

| Policy | Behavior | Use When |
|--------|----------|----------|
| `vault-wins` | Vault value always overwrites cloud | Vault is the single source of truth |
| `<provider>-wins` | Cloud value always overwrites Vault | Cloud-native rotation is authoritative |
| `newest-wins` | Most recently modified value wins | Both sides may update independently |

The `newest-wins` policy compares timestamps from Vault metadata (`updated_time`) and the cloud provider's last-modified field. In the event of a tie (identical timestamps), the sync is skipped.

## Cloud Secret Manager Comparison

| Feature | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager |
|---------|--------------------|-----------------|--------------------|
| **Versioning** | Single current + staging | Immutable versions, all retained | Immutable versions, enabled/disabled/destroyed |
| **Rotation** | Lambda-based, built-in for RDS/Aurora | Near-expiry event via Event Grid | Pub/Sub topic on rotation |
| **Access Control** | Resource policy + IAM | RBAC + network ACLs + firewall | IAM with CEL conditions |
| **Cross-account** | Resource policy sharing | N/A (use Managed HSM for multi-tenant) | Cross-project IAM bindings |
| **Pricing Model** | Per-secret + per-API-call | Per-operation + per-secret | Per-version + per-access |
| **Max Secret Size** | 64 KB | 25 KB (secrets), 200 KB (keys) | 64 KB |
| **Replication** | Multi-region built-in | Geo-redundant by default | Automatic or user-managed replicas |
| **Audit** | CloudTrail | Azure Monitor + Diagnostic Logs | Cloud Audit Logs |

## Migration Strategies

### Vault-First (Recommended)

Keep Vault as the authoritative source. Use bridges to push secrets to cloud providers as needed.

1. All secrets originate in Vault via standard workflows.
2. Run bridges with `--direction vault-to-<provider>` on a schedule (cron or CI/CD).
3. Cloud workloads read from their native secret manager.
4. Rotation happens in Vault; bridges propagate the new values.

### Cloud-First (Transitional)

Use when migrating from a cloud-native secret manager to Vault.

1. Run bridges with `--direction <provider>-to-vault` to seed Vault.
2. Gradually update workloads to read from Vault directly.
3. Once migration is complete, switch to Vault-First mode.
4. Decommission cloud-side secrets after verifying all consumers use Vault.

### Bidirectional (Advanced)

Use when some secrets are authoritative in Vault and others in the cloud provider.

1. Define clear ownership per secret in the mapping file.
2. Use `newest-wins` conflict policy or split mappings into separate files per direction.
3. Monitor sync logs closely for conflict resolution decisions.
4. Avoid bidirectional sync for secrets that rotate in both systems simultaneously.

## Configuration

See `bridge-config.yaml` for a complete example with annotations. Key sections:

- **mappings**: Array of Vault path to cloud secret name pairs
- **conflict_policy**: Default conflict resolution strategy
- **vault_mount**: Vault KV v2 mount point
- **notify_webhook**: Slack-compatible webhook for sync status notifications

Provider-specific mapping fields:

| Field | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Cloud name key | `asm_name` | `akv_name` | `gcp_name` |
| Rotation | `rotation_days` | N/A | N/A |
| Content type | N/A | `content_type` | N/A |
| Metadata | N/A | `tags` | `labels` |
| Access control | N/A | N/A | `iam_conditions` |

## Prerequisites

All scripts require:

- `vault` CLI with `VAULT_ADDR` and `VAULT_TOKEN` configured
- `jq` for JSON processing
- `yq` or `python3` with PyYAML for YAML mapping file parsing

Provider-specific:

| Provider | CLI | Auth |
|----------|-----|------|
| AWS | `aws` v2 | `AWS_PROFILE` or env credentials |
| Azure | `az` | `az login` |
| GCP | `gcloud` | `gcloud auth application-default login` |

## Security Considerations

- **Never store bridge mapping files with secret values.** Mappings contain only paths and names, not secret content.
- **Use dry-run first.** Always validate with `--dry-run` before executing a sync against production.
- **Audit logging.** Each script logs all operations with timestamps to `/tmp/<provider>-bridge-*.log`. Forward these to your SIEM.
- **Least privilege.** Grant bridge credentials only the permissions needed for read/write on the specific secrets being synced.
- **Network security.** Run bridges from a trusted network with access to both Vault and the cloud provider API.
- **Webhook security.** If using notification webhooks, ensure the webhook URL uses HTTPS and is not logged in plaintext.
