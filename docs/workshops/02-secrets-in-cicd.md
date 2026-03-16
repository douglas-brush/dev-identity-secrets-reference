# Workshop 02: Secrets in CI/CD

**Duration:** 2 hours
**Level:** Intermediate
**Audience:** DevOps engineers, platform engineers, security engineers

---

## Objectives

By the end of this workshop, participants will be able to:

1. Configure OIDC authentication between GitHub Actions and Vault (zero static secrets)
2. Use dynamic credentials in CI pipelines instead of stored secrets
3. Encrypt configuration files with SOPS and `age` keys
4. Set up secret scanning and pre-commit hooks to prevent leaks
5. Sign build artifacts using Vault Transit keys

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Completed Workshop 01 or equivalent Vault familiarity | -- |
| Docker 24.0+ and Docker Compose 2.20+ | `docker --version` |
| GitHub account | -- |
| `gh` CLI | `gh --version` |
| `sops` 3.8+ | `sops --version` |
| `age` 1.1+ | `age --version` |
| `cosign` 2.0+ (Lab 5 only) | `cosign version` |
| `pre-commit` 3.0+ | `pre-commit --version` |
| `gitleaks` 8.18+ | `gitleaks version` |
| Vault CLI | `vault version` |

### Install missing tools (macOS)

```bash
brew install sops age sigstore/tap/cosign pre-commit gitleaks gh
```

### Environment Setup

```bash
cd dev-identity-secrets-reference

# Start the dev environment
make dev-up && make dev-setup

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
vault status
```

---

## Lab 1: OIDC Authentication from GitHub Actions (25 minutes)

### Concept

OIDC (OpenID Connect) federation eliminates stored secrets in CI. Instead of a static `VAULT_TOKEN` in GitHub Secrets, the runner requests a short-lived JWT from GitHub's OIDC provider and exchanges it for a scoped Vault token.

The flow:
1. GitHub Actions runner requests a JWT from GitHub's OIDC provider
2. The JWT contains claims: repository, branch, actor, workflow, etc.
3. Vault validates the JWT against GitHub's OIDC discovery endpoint
4. Vault issues a short-lived token with policies mapped to the role
5. The pipeline uses the Vault token, which auto-expires after the TTL

### 1.1 Configure JWT Auth Backend in Vault

```bash
# Enable the JWT auth method at the github-actions path
vault auth enable -path=jwt/github jwt

# Configure it to trust GitHub's OIDC provider
vault write auth/jwt/github/config \
  oidc_discovery_url="https://token.actions.githubusercontent.com" \
  bound_issuer="https://token.actions.githubusercontent.com"
```

### 1.2 Create a Vault Policy for CI

```bash
vault policy write ci-readonly - <<'EOF'
# CI pipeline policy — read-only access to application secrets
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

# Allow reading dynamic database credentials
path "database/creds/demo-readonly" {
  capabilities = ["read"]
}

# Allow Transit encrypt/decrypt for artifact signing
path "transit/sign/ci-signing-key/*" {
  capabilities = ["update"]
}

path "transit/verify/ci-signing-key/*" {
  capabilities = ["update"]
}
EOF
```

### 1.3 Create a Vault Role Bound to Your Repository

```bash
# Replace YOUR_ORG/YOUR_REPO with your actual repository
vault write auth/jwt/github/role/ci-readonly \
  role_type="jwt" \
  user_claim="repository_owner" \
  bound_claims_type="glob" \
  bound_claims='{"repository": "YOUR_ORG/YOUR_REPO", "ref": "refs/heads/main"}' \
  policies="ci-readonly" \
  token_ttl="600" \
  token_max_ttl="1200"
```

**What the bound claims enforce:**
- `repository`: Only this specific repo can authenticate
- `ref`: Only the `main` branch (prevents feature branches from getting secrets)

### 1.4 Examine the Reusable Workflow

The repository includes a reusable OIDC auth workflow at `platform/github-actions/reusable/oidc-vault-auth.yml`.

```bash
cat platform/github-actions/reusable/oidc-vault-auth.yml
```

Key elements:
- `permissions: id-token: write` -- required to request the GitHub OIDC JWT
- Uses `hashicorp/vault-action@v3` to exchange the JWT for a Vault token
- Validates the token after acquisition
- Exports the token as a workflow output

### 1.5 Simulate the OIDC Flow Locally

Since we cannot run actual GitHub Actions locally, simulate the token exchange:

```bash
# Create a JWT auth role for local testing
vault write auth/jwt/github/role/local-test \
  role_type="jwt" \
  user_claim="sub" \
  bound_audiences="vault" \
  policies="ci-readonly" \
  token_ttl="300"

# In a real pipeline, the JWT comes from:
# curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
#   "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=vault"
# For local testing, we use AppRole as a stand-in:

ROLE_ID=$(vault read -field=role_id auth/approle/role/demo-app/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/demo-app/secret-id)
CI_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="$ROLE_ID" secret_id="$SECRET_ID")

echo "Simulated CI token: $CI_TOKEN"

# Use the CI token to read a secret
VAULT_TOKEN=$CI_TOKEN vault kv get secret/demo/app-config 2>/dev/null \
  && echo "SUCCESS: CI token can read secrets" \
  || echo "Expected: token may not have access to this exact path"
```

### 1.6 Write a Workflow That Uses OIDC

Create a workflow file (do not push -- just review the structure):

```yaml
# .github/workflows/deploy-example.yml
name: Deploy with Vault OIDC

on:
  push:
    branches: [main]

permissions:
  id-token: write    # Required for OIDC
  contents: read

jobs:
  auth:
    uses: ./.github/workflows/oidc-vault-auth.yml
    with:
      vault_addr: https://vault.example.com
      vault_role: ci-readonly

  deploy:
    needs: auth
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Read secrets from Vault
        env:
          VAULT_ADDR: https://vault.example.com
          VAULT_TOKEN: ${{ needs.auth.outputs.vault_token }}
        run: |
          DB_CREDS=$(vault read -format=json database/creds/demo-readonly)
          export DB_USER=$(echo $DB_CREDS | jq -r '.data.username')
          export DB_PASS=$(echo $DB_CREDS | jq -r '.data.password')
          # Deploy using short-lived credentials
          echo "Deploying with dynamic DB user: $DB_USER"
```

**Verification:**
- [ ] JWT auth backend is enabled and configured for GitHub OIDC
- [ ] A Vault role exists with repository and branch binding
- [ ] Participant can explain why `id-token: write` permission is required
- [ ] Participant understands the claim-to-policy binding model

---

## Lab 2: Dynamic Credentials in CI Pipelines (20 minutes)

### Concept

Every CI run should get unique, short-lived credentials. When the pipeline finishes (or the TTL expires), the credentials are automatically revoked. No credential reuse across builds. No lingering access.

### 2.1 Create a CI-Specific Database Role

```bash
vault write database/roles/ci-migrations \
  db_name=demo-postgres \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ALL ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
  default_ttl="15m" \
  max_ttl="30m"
```

Note the short TTLs: 15 minutes default, 30 minutes max. A CI pipeline should complete within this window.

### 2.2 Simulate a CI Pipeline

```bash
echo "=== CI Pipeline Start ==="

# Step 1: Authenticate (simulated — in real CI, this is OIDC)
export VAULT_TOKEN=dev-root-token

# Step 2: Get dynamic database credentials
echo "--- Requesting database credentials ---"
DB_CREDS=$(vault read -format=json database/creds/ci-migrations)
DB_USER=$(echo $DB_CREDS | jq -r '.data.username')
DB_PASS=$(echo $DB_CREDS | jq -r '.data.password')
LEASE_ID=$(echo $DB_CREDS | jq -r '.lease_id')

echo "DB User: $DB_USER (TTL: 15m)"

# Step 3: Run migrations (simulated)
echo "--- Running database migrations ---"
docker exec dev-postgres psql -U "$DB_USER" -d demo \
  -c "SELECT current_user, now();"

# Step 4: Read application config from Vault
echo "--- Reading application config ---"
vault kv get -format=json secret/demo/app-config 2>/dev/null || \
  echo "(No demo config found — this is expected on a fresh setup)"

# Step 5: Revoke credentials after pipeline completes
echo "--- Revoking credentials ---"
vault lease revoke "$LEASE_ID"
echo "Credentials revoked."

echo "=== CI Pipeline Complete ==="
```

### 2.3 Verify Credential Revocation

```bash
# The dynamic user should no longer exist
docker exec dev-postgres psql -U "$DB_USER" -d demo \
  -c "SELECT 1;" 2>&1 | head -1
```

Expected: Authentication failure.

### 2.4 Automated Lease Revocation Pattern

In production CI, use a cleanup step that always runs:

```yaml
# In a GitHub Actions workflow:
- name: Revoke Vault lease
  if: always()  # Runs even if previous steps fail
  env:
    VAULT_ADDR: ${{ env.VAULT_ADDR }}
    VAULT_TOKEN: ${{ env.VAULT_TOKEN }}
  run: |
    if [ -n "$LEASE_ID" ]; then
      vault lease revoke "$LEASE_ID" || true
    fi
```

**Verification:**
- [ ] Generated credentials with a 15-minute TTL for CI use
- [ ] Used the credentials in a simulated pipeline
- [ ] Revoked credentials after pipeline completion
- [ ] Confirmed the revoked credentials no longer work

---

## Lab 3: SOPS Encryption for Config Files (25 minutes)

### Concept

SOPS (Secrets OPerationS) encrypts specific fields within YAML/JSON files while leaving keys and structure visible. This allows:
- Encrypted secrets in Git (reviewable diffs on non-secret fields)
- Multiple encryption backends (age, AWS KMS, Azure Key Vault, GCP Cloud KMS)
- Per-environment encryption rules via `.sops.yaml`

### 3.1 Generate an `age` Key Pair

```bash
# Create a workshop-specific key
mkdir -p /tmp/workshop-sops
age-keygen -o /tmp/workshop-sops/key.txt

# Display the public key (recipient)
AGE_RECIPIENT=$(grep "^# public key:" /tmp/workshop-sops/key.txt | cut -d' ' -f4)
echo "Public key (recipient): $AGE_RECIPIENT"

# Set the SOPS age key file for decryption
export SOPS_AGE_KEY_FILE=/tmp/workshop-sops/key.txt
```

### 3.2 Examine the `.sops.yaml` Configuration

```bash
cat .sops.yaml
```

Key observations:
- `path_regex` determines which files get which encryption keys
- `encrypted_regex` controls which YAML keys get encrypted (not the entire file)
- Separate rules per environment (dev, staging, prod)
- Production requires cloud KMS (age-only is insufficient)

### 3.3 Create and Encrypt a Config File

```bash
# Create a plaintext config file
cat > /tmp/workshop-sops/app-config.yaml <<'EOF'
app:
  name: workshop-demo
  version: 1.0.0
  environment: development
secrets:
  api_key: "sk-live-workshop-secret-key"
  database_password: "super-secret-db-password"
  jwt_signing_key: "jwt-hmac-256-secret"
credentials:
  aws_access_key: "AKIA1234567890EXAMPLE"
  aws_secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EOF

echo "=== Before encryption ==="
cat /tmp/workshop-sops/app-config.yaml
```

**Encrypt the file:**

```bash
sops --encrypt \
  --age "$AGE_RECIPIENT" \
  --encrypted-regex '^(api_key|database_password|jwt_signing_key|aws_access_key|aws_secret_key)$' \
  /tmp/workshop-sops/app-config.yaml > /tmp/workshop-sops/app-config.enc.yaml

echo "=== After encryption ==="
cat /tmp/workshop-sops/app-config.enc.yaml
```

Expected: The `app.name`, `app.version`, and `app.environment` fields are plaintext. The secret fields are encrypted (prefixed with `ENC[AES256_GCM,data:...`). A `sops` metadata block is appended with the recipient, MAC, and version info.

### 3.4 Decrypt the File

```bash
sops --decrypt /tmp/workshop-sops/app-config.enc.yaml
```

Expected: Original plaintext is restored.

**Decrypt to a specific output:**

```bash
sops --decrypt --output /tmp/workshop-sops/app-config-decrypted.yaml \
  /tmp/workshop-sops/app-config.enc.yaml

diff /tmp/workshop-sops/app-config.yaml /tmp/workshop-sops/app-config-decrypted.yaml
echo "Exit code: $? (0 = files are identical)"
```

### 3.5 Edit an Encrypted File In-Place

```bash
# SOPS opens the file decrypted in your editor, re-encrypts on save
EDITOR="vim" sops /tmp/workshop-sops/app-config.enc.yaml
# (Or use EDITOR="nano" or EDITOR="code --wait")
```

### 3.6 Decrypt in a CI Pipeline

```bash
# Simulate CI decryption
echo "=== CI Pipeline: SOPS Decrypt ==="

# In real CI, SOPS_AGE_KEY_FILE is set from a Vault secret or GitHub Secret
export SOPS_AGE_KEY_FILE=/tmp/workshop-sops/key.txt

# Decrypt and extract a single value
API_KEY=$(sops --decrypt --extract '["secrets"]["api_key"]' \
  /tmp/workshop-sops/app-config.enc.yaml)
echo "Extracted API key: ${API_KEY:0:10}..."

# Decrypt to environment variables
eval "$(sops --decrypt /tmp/workshop-sops/app-config.enc.yaml \
  | python3 -c "
import sys, yaml
d = yaml.safe_load(sys.stdin)
for k, v in d.get('secrets', {}).items():
    print(f'export {k.upper()}=\"{v}\"')
")"
echo "DATABASE_PASSWORD is set: ${DATABASE_PASSWORD:+yes}"
```

### 3.7 SOPS with Vault Transit (Advanced)

SOPS can use Vault Transit as an encryption backend instead of age/KMS:

```bash
# Create a SOPS-specific Transit key
vault write -f transit/keys/sops-key

# Encrypt using Vault Transit
sops --encrypt \
  --hc-vault-transit "$VAULT_ADDR/v1/transit/keys/sops-key" \
  --encrypted-regex '^(api_key|database_password)$' \
  /tmp/workshop-sops/app-config.yaml > /tmp/workshop-sops/app-config-vault.enc.yaml

# Decrypt
sops --decrypt /tmp/workshop-sops/app-config-vault.enc.yaml
```

**Verification:**
- [ ] Generated an age key pair
- [ ] Encrypted a config file with selective field encryption
- [ ] Verified non-secret fields remain readable in the encrypted file
- [ ] Decrypted the file and confirmed it matches the original
- [ ] Extracted a single secret value from an encrypted file

---

## Lab 4: Secret Scanning and Pre-Commit Hooks (20 minutes)

### Concept

Defense in depth: even with SOPS and Vault, developers may accidentally commit secrets. Pre-commit hooks provide a last line of defense before secrets enter Git history.

### 4.1 Install Pre-Commit Hooks

```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install the hooks defined in .pre-commit-config.yaml
pre-commit install
```

### 4.2 Examine the Hook Configuration

```bash
cat .pre-commit-config.yaml
```

Key hooks relevant to secret protection:
- `gitleaks` -- pattern-based secret detection using custom rules
- `detect-private-key` -- catches PEM/PKCS key files
- `sops-encrypted-check` -- verifies files in `secrets/` are SOPS-encrypted
- `entropy-check` -- detects high-entropy strings that may be secrets
- `no-plaintext-secrets` -- custom scanner for 15+ secret patterns
- `no-private-keys` -- blocks `.pem`, `.key`, `.p12`, `.pfx` files

### 4.3 Test Secret Detection

Create a test file with a fake secret:

```bash
mkdir -p /tmp/workshop-scanning
cat > /tmp/workshop-scanning/test-leak.py <<'EOF'
# This file contains intentional secrets for testing
import os

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.example.com:5432/prod"
EOF
```

**Run gitleaks against the test file:**

```bash
gitleaks detect \
  --source /tmp/workshop-scanning/ \
  --config tools/scanning/custom-gitleaks.toml \
  --verbose 2>&1 || true
```

Expected: Gitleaks reports findings for AWS keys, GitHub token, and database URL.

### 4.4 Run the Repository Scanner

```bash
# Run the built-in enhanced scanner
./tools/scanning/scan_repo.sh 2>/dev/null || echo "(Scanner found issues or is not configured)"

# Run the entropy checker
./tools/scanning/entropy_check.sh --threshold 4.5 /tmp/workshop-scanning/test-leak.py 2>/dev/null || true
```

### 4.5 Run Pre-Commit Hooks Manually

```bash
# Run all hooks against all files
pre-commit run --all-files 2>&1 | tail -20
```

Expected: Several hooks pass, gitleaks and secret scanners may report findings on any test/example files.

### 4.6 Test the Pre-Commit Block

```bash
# Create a branch for testing
git checkout -b workshop-test-secrets 2>/dev/null || true

# Create a file with a secret
echo 'API_KEY="ghp_fake1234567890abcdef"' > /tmp/test-secret-file.txt
cp /tmp/test-secret-file.txt .

# Try to commit it
git add test-secret-file.txt 2>/dev/null
git commit -m "test: add file with secret" 2>&1 | tail -10 || true

# Clean up
git checkout -- . 2>/dev/null || true
rm -f test-secret-file.txt
git checkout main 2>/dev/null || true
git branch -D workshop-test-secrets 2>/dev/null || true
```

Expected: The pre-commit hook blocks the commit with a gitleaks or secret detection warning.

**Verification:**
- [ ] Pre-commit hooks are installed
- [ ] Gitleaks detects AWS keys and GitHub tokens in test files
- [ ] A commit containing a secret is blocked by pre-commit hooks
- [ ] Participant can explain the defense-in-depth layers (SOPS + scanning + hooks)

---

## Lab 5: Artifact Signing with Vault Transit (20 minutes)

### Concept

Artifact signing provides supply chain integrity. Every build artifact (container image, binary, config bundle) is signed. Deployment environments verify the signature before accepting the artifact. Vault Transit provides the signing key without exposing it.

### 5.1 Create a Signing Key in Vault Transit

```bash
# Create an ECDSA-P256 key for signing
vault write transit/keys/ci-signing-key \
  type=ecdsa-p256

# Verify the key
vault read transit/keys/ci-signing-key
```

### 5.2 Sign Data with Vault Transit

```bash
# Create a test artifact
echo "workshop-artifact-v1.0.0" > /tmp/workshop-artifact.txt

# Compute the SHA-256 hash
ARTIFACT_HASH=$(sha256sum /tmp/workshop-artifact.txt | awk '{print $1}')
echo "Artifact hash: $ARTIFACT_HASH"

# Sign the hash using Vault Transit
SIGNATURE=$(vault write -field=signature transit/sign/ci-signing-key \
  input=$(echo -n "$ARTIFACT_HASH" | base64))
echo "Signature: $SIGNATURE"
```

### 5.3 Verify the Signature

```bash
vault write transit/verify/ci-signing-key \
  input=$(echo -n "$ARTIFACT_HASH" | base64) \
  signature="$SIGNATURE"
```

Expected output:
```
Key      Value
---      -----
valid    true
```

**Tamper with the artifact and verify again:**

```bash
# Modify the artifact
echo "tampered-content" > /tmp/workshop-artifact-tampered.txt
TAMPERED_HASH=$(sha256sum /tmp/workshop-artifact-tampered.txt | awk '{print $1}')

# Verify with the original signature
vault write transit/verify/ci-signing-key \
  input=$(echo -n "$TAMPERED_HASH" | base64) \
  signature="$SIGNATURE"
```

Expected: `valid: false` -- the signature does not match the tampered artifact.

### 5.4 Sign a Container Image with cosign + Vault KMS

```bash
# This requires cosign and a real container image
# For the workshop, we demonstrate the command structure

# Build a test image (if Docker is available)
echo "FROM alpine:3.19" > /tmp/Dockerfile.workshop
docker build -t workshop-test:v1 -f /tmp/Dockerfile.workshop /tmp/ 2>/dev/null

# In production, sign with Vault KMS:
# cosign sign --key hashivault://ci-signing-key \
#   --vault-addr=$VAULT_ADDR \
#   --vault-token=$VAULT_TOKEN \
#   ghcr.io/org/app@sha256:...

# Verify:
# cosign verify --key hashivault://ci-signing-key \
#   --vault-addr=$VAULT_ADDR \
#   --vault-token=$VAULT_TOKEN \
#   ghcr.io/org/app@sha256:...

echo "cosign + Vault KMS signing demonstrated (see platform/github-actions/reusable/sign-and-verify.yml for CI workflow)"
```

### 5.5 Examine the Signing Workflow

```bash
cat platform/github-actions/reusable/sign-and-verify.yml
```

Key elements:
- Supports three signing methods: keyless (Fulcio), vault-kms (cosign), vault-transit
- Signs after build, verifies before deploy
- Requires `id-token: write` and `packages: write` permissions

### 5.6 CI Signing Pipeline Pattern

```bash
echo "=== CI Signing Pipeline ==="

# Step 1: Build artifact
echo "building artifact..." > /tmp/workshop-build-output.tar.gz

# Step 2: Hash the artifact
BUILD_HASH=$(sha256sum /tmp/workshop-build-output.tar.gz | awk '{print $1}')

# Step 3: Sign with Vault Transit
BUILD_SIG=$(vault write -field=signature transit/sign/ci-signing-key \
  input=$(echo -n "$BUILD_HASH" | base64))

# Step 4: Store signature alongside artifact
echo "$BUILD_SIG" > /tmp/workshop-build-output.tar.gz.sig
echo "$BUILD_HASH" > /tmp/workshop-build-output.tar.gz.sha256

# Step 5: Verify before deploy
VERIFY=$(vault write -field=valid transit/verify/ci-signing-key \
  input=$(echo -n "$BUILD_HASH" | base64) \
  signature="$BUILD_SIG")

if [ "$VERIFY" = "true" ]; then
  echo "Signature valid -- deploying"
else
  echo "Signature INVALID -- aborting deployment"
  exit 1
fi

echo "=== Pipeline Complete ==="
```

**Verification:**
- [ ] Created an ECDSA signing key in Vault Transit
- [ ] Signed an artifact hash and received a signature
- [ ] Verified the signature against the original artifact
- [ ] Confirmed a tampered artifact fails verification
- [ ] Understands the cosign + Vault KMS integration pattern

---

## Cleanup

```bash
# Remove workshop resources from Vault
vault delete transit/keys/ci-signing-key 2>/dev/null || true
vault delete auth/jwt/github/role/ci-readonly 2>/dev/null || true
vault delete auth/jwt/github/role/local-test 2>/dev/null || true
vault auth disable jwt/github 2>/dev/null || true
vault policy delete ci-readonly 2>/dev/null || true
vault delete database/roles/ci-migrations 2>/dev/null || true

# Remove local temp files
rm -rf /tmp/workshop-sops /tmp/workshop-scanning /tmp/workshop-artifact* /tmp/workshop-build-* /tmp/Dockerfile.workshop

# Or reset everything
make dev-reset
```

---

## Review Questions

1. **Why is OIDC preferred over stored secrets for CI/CD authentication?**
   OIDC eliminates static credentials entirely. The JWT is short-lived, scoped to a specific repository and branch, and cannot be reused. Stored secrets (like `VAULT_TOKEN` in GitHub Secrets) are long-lived, can be exfiltrated, and require manual rotation.

2. **What happens if a CI pipeline fails mid-run with dynamic credentials?**
   The credentials expire when their TTL runs out. Best practice: use an `if: always()` cleanup step to revoke the lease immediately. Even without cleanup, the short TTL (15m) limits the exposure window.

3. **Why does SOPS encrypt only specific fields rather than the entire file?**
   Selective encryption preserves diff-ability in Git. Reviewers can see what configuration keys changed without accessing the secret values. It also makes it obvious which fields are sensitive.

4. **What is the defense-in-depth model for secret protection?**
   Layer 1: Vault (centralized secret storage, dynamic credentials). Layer 2: SOPS (encryption at rest in Git). Layer 3: Pre-commit hooks (block secrets before they enter history). Layer 4: CI scanning (catch anything that slipped through). Layer 5: Audit logging (detect unauthorized access after the fact).

5. **Why sign artifacts with Vault Transit instead of storing a signing key in CI?**
   The signing key never leaves Vault. If the CI system is compromised, the attacker cannot extract the key to sign malicious artifacts. Access to signing is controlled by Vault policies and logged in the audit trail.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `sops: command not found` | `brew install sops` or download from github.com/getsops/sops |
| `age: command not found` | `brew install age` or download from github.com/FiloSottile/age |
| SOPS decrypt fails: `no matching keys found` | Ensure `SOPS_AGE_KEY_FILE` points to the correct key file |
| `pre-commit: command not found` | `pip install pre-commit` |
| gitleaks not finding secrets | Check config path: `--config tools/scanning/custom-gitleaks.toml` |
| JWT auth mount fails | Check if already enabled: `vault auth list` |
| Transit sign returns permission denied | Verify VAULT_TOKEN is set to root token for the workshop |

---

## Next Steps

- **Workshop 03:** [Incident Response with SIRM](03-incident-response-with-sirm.md) -- What happens when secrets are exposed
- **Reference:** [CI Integration Guide](../../platform/ci-integration-guide.md) for production pipeline templates
- **Reference:** [SOPS Bootstrap Guide](../15-sops-bootstrap-guide.md) for production SOPS setup
