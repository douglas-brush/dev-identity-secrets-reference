# Application Onboarding Guide

How to onboard a new application to the Dev Identity & Secrets platform.

## Prerequisites

- Vault access with `developer-read` policy (or higher)
- CLI access to the target platform namespace
- SOPS + age configured for encrypted config files

## Step 1: Run the Onboarding Script

```bash
# External secrets sync delivery (recommended for most apps)
./bootstrap/scripts/onboard_app.sh my-api dev --delivery eso --cert --db-role

# Volume-mount delivery (for file-based secrets)
./bootstrap/scripts/onboard_app.sh my-api dev --delivery csi

# Preview what would be created
./bootstrap/scripts/onboard_app.sh my-api dev --delivery eso --dry-run
```

This creates:
- Vault policy scoped to `kv/data/dev/apps/my-api/*`
- Platform service account
- Secret delivery resource (sync rule, mount class, or agent annotations)
- Optional: workload certificate for mTLS

## Step 2: Choose a Delivery Pattern

### External secrets sync

Secrets are synced from the central broker to platform-native secrets, then consumed via environment variables or secret references. Configure the sync rule to target the correct secret path and refresh interval.

### Volume-mount driver

Secrets are mounted as files directly into workloads. Configure the mount class to target the correct secret path and provider.

### Secrets agent sidecar

Use agent annotations or configuration to inject a sidecar that retrieves and templates secrets from the central broker at runtime.

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
```

Use the encrypted file with your deployment tooling (e.g., `sops -d values.enc.yaml | your-deploy-tool`).

## Step 4: Dynamic Database Credentials

If `--db-role` was used during onboarding, your app receives short-lived database credentials automatically. Credentials rotate every hour (configurable).

Your application should handle credential rotation gracefully by re-reading the mounted secret files or environment variables on connection failure.

## Security Checklist

- [ ] Service account follows least-privilege principles
- [ ] Workload runs as non-root where possible
- [ ] Filesystem is read-only where possible
- [ ] Resource limits are set
- [ ] No secrets in container image or environment variable defaults
- [ ] Health checks configured
- [ ] Monitoring and observability enabled
