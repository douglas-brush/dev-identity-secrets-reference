# Vault Migration Toolkit

Tools for exporting, importing, comparing, and health-checking HashiCorp Vault instances during migrations.

## Tools

| Script | Purpose |
|--------|---------|
| `vault-export.sh` | Export KV secrets (v1/v2) to SOPS-encrypted JSON or YAML |
| `vault-import.sh` | Import SOPS-encrypted exports into a target Vault |
| `vault-diff.sh` | Compare secret metadata between two Vault instances |
| `vault-health-check.sh` | Comprehensive Vault health assessment report |

## Prerequisites

- `vault` CLI (1.12+)
- `jq` (1.6+)
- `sops` (3.7+) with `age` keys configured
- `yq` (optional, for YAML format exports)

## Common Scenarios

### 1. Full Mount Migration

Export everything from the `secret/` mount, then import to a new Vault:

```bash
# Export from source
export VAULT_ADDR=https://vault-old.example.com:8200
export VAULT_TOKEN=hvs.source-token
export SOPS_AGE_RECIPIENTS=age1...

./vault-export.sh --mount secret --output migration-backup.json

# Health check the target
export VAULT_ADDR=https://vault-new.example.com:8200
export VAULT_TOKEN=hvs.dest-token
./vault-health-check.sh

# Dry-run import first
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
./vault-import.sh --input migration-backup.json --dry-run

# Execute import
./vault-import.sh --input migration-backup.json
```

### 2. Selective Path Migration with Remapping

Migrate specific paths and remap them to a new structure:

```bash
# Export only the apps path
./vault-export.sh --mount secret --path apps/ --output apps-export.json

# Create remap file
cat > remap.json <<'EOF'
{
  "remaps": [
    {"from": "apps/legacy-api", "to": "apps/api-v2"},
    {"from": "apps/old-worker", "to": "services/worker"}
  ]
}
EOF

# Import with remapping
./vault-import.sh --input apps-export.json --remap-file remap.json --dry-run
./vault-import.sh --input apps-export.json --remap-file remap.json
```

### 3. KV v1 to v2 Migration

Export from a v1 mount and import into a v2 mount:

```bash
# Export from v1 source
./vault-export.sh --mount legacy-kv --kv-version 1 --output v1-export.json

# Create v2 mount on target
vault secrets enable -path=modern-kv -version=2 kv

# Import to v2 mount
./vault-import.sh --input v1-export.json --mount modern-kv
```

### 4. Version-Preserving Migration

Preserve all KV v2 version history during migration:

```bash
./vault-export.sh --mount secret --output full-backup.json
./vault-import.sh --input full-backup.json --preserve-versions
```

### 5. Pre-Migration Diff Check

Compare source and destination after migration to verify completeness:

```bash
export VAULT_SOURCE_TOKEN=hvs.source-token
export VAULT_DEST_TOKEN=hvs.dest-token

# Table output
./vault-diff.sh \
  --source-addr https://vault-old:8200 \
  --dest-addr https://vault-new:8200 \
  --path secret/

# JSON output for automation
./vault-diff.sh \
  --source-addr https://vault-old:8200 \
  --dest-addr https://vault-new:8200 \
  --path secret/ --json | jq '.diff_metadata.summary'
```

### 6. Health Check Before/After Migration

```bash
# Check source health
export VAULT_ADDR=https://vault-old:8200
./vault-health-check.sh --verbose

# Check target health (JSON for CI)
export VAULT_ADDR=https://vault-new:8200
./vault-health-check.sh --json > health-report.json
```

## Security Notes

- **Encryption at rest**: Export files are always SOPS-encrypted. Plaintext secrets never touch disk.
- **No value comparison**: `vault-diff.sh` compares metadata only (versions, timestamps, key names). Secret values are never read during diff.
- **Token scoping**: Use the minimum required Vault policy. Export needs `read` + `list`; import needs `create` + `update`; diff needs `read` + `list` on both; health-check benefits from broad read access.
- **Temp file cleanup**: Export uses a trap to remove the plaintext temp file on exit or error.
- **Audit trail**: All operations go through the Vault API and will appear in Vault audit logs.

## Environment Variables

| Variable | Required By | Description |
|----------|-------------|-------------|
| `VAULT_ADDR` | all | Vault server address |
| `VAULT_TOKEN` | all | Vault authentication token |
| `SOPS_AGE_RECIPIENTS` | export | age public key for encryption |
| `SOPS_AGE_KEY_FILE` | import | Path to age private key for decryption |
| `VAULT_SOURCE_TOKEN` | diff | Source Vault token (falls back to `VAULT_TOKEN`) |
| `VAULT_DEST_TOKEN` | diff | Destination Vault token (falls back to `VAULT_TOKEN`) |

## Exit Codes

All scripts follow consistent exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (or no differences for diff) |
| 1 | Failure or differences found |
| 2 | Usage / argument error |
