# Application Onboarding Guide

How to onboard a new application to the Dev Identity & Secrets platform.

## Prerequisites

- Vault access with `developer-read` policy (or higher)
- `kubectl` access to the target namespace
- SOPS + age configured for encrypted config files

## Step 1: Run the Onboarding Script

```bash
# ExternalSecrets Operator delivery (recommended for most apps)
./bootstrap/scripts/onboard_app.sh my-api dev --delivery eso --cert --db-role

# CSI driver delivery (for volume-mounted secrets)
./bootstrap/scripts/onboard_app.sh my-api dev --delivery csi

# Preview what would be created
./bootstrap/scripts/onboard_app.sh my-api dev --delivery eso --dry-run
```

This creates:
- Vault policy scoped to `kv/data/dev/apps/my-api/*`
- Kubernetes ServiceAccount with `automountServiceAccountToken: false`
- Secret delivery resource (ExternalSecret, SecretProviderClass, or Agent annotations)
- Optional: cert-manager Certificate for mTLS

## Step 2: Choose a Deployment Pattern

### ExternalSecrets Operator (ESO)

Secrets are synced from Vault to native Kubernetes Secrets, then consumed via `envFrom`:

```yaml
envFrom:
  - secretRef:
      name: my-api-config
```

See `deployment-with-externalsecrets.yaml` for the full example.

### CSI Secrets Store

Secrets are mounted as files directly into pods:

```yaml
volumeMounts:
  - name: secrets-store
    mountPath: /vault/secrets
    readOnly: true
```

See `deployment-with-csi.yaml` for the full example.

### Vault Agent Sidecar

Add annotations to your Deployment for automatic Vault Agent injection:

```yaml
annotations:
  vault.hashicorp.com/agent-inject: "true"
  vault.hashicorp.com/role: "my-api"
  vault.hashicorp.com/agent-inject-secret-config: "kv/data/dev/apps/my-api/config"
```

## Step 3: Encrypted Config Files

For values that need to be committed to the repository:

```bash
# Create your config file
cat > values.yaml <<EOF
database:
  password: "my-secret-password"
EOF

# Encrypt with SOPS
sops -e values.yaml > values.enc.yaml
rm values.yaml

# Deploy with helm-secrets
helm secrets upgrade my-api ./chart -f values.enc.yaml
```

See `values.enc.yaml.example` for the encrypted file structure.

## Step 4: Dynamic Database Credentials

If `--db-role` was used during onboarding, your app receives short-lived database credentials automatically. Credentials rotate every hour (configurable).

Your application should handle credential rotation gracefully by re-reading the mounted secret files or environment variables on connection failure.

## Security Checklist

- [ ] ServiceAccount has `automountServiceAccountToken: false`
- [ ] Pod runs as non-root (`runAsNonRoot: true`)
- [ ] Root filesystem is read-only (`readOnlyRootFilesystem: true`)
- [ ] All capabilities dropped (`drop: [ALL]`)
- [ ] Resource limits are set
- [ ] No secrets in container image or environment variable defaults
- [ ] Health checks configured (liveness + readiness)
- [ ] Prometheus metrics exposed for monitoring
