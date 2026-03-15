# Artifact Signing Examples

Practical examples for signing container images, binaries, and SBOMs across CI and local development workflows.

## Container Image Signing with cosign + Vault KMS

Sign images using a Vault-managed transit key via cosign's KMS provider.

### Prerequisites

```bash
# Install cosign
brew install cosign    # macOS
# or: go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Configure Vault
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=s.xxxxxxxx

# Create a transit signing key (one-time setup)
vault secrets enable transit
vault write transit/keys/image-signing type=ecdsa-p256
```

### Sign after build

```bash
# Build and push the image
docker build -t ghcr.io/org/app:v1.2.3 .
docker push ghcr.io/org/app:v1.2.3

# Sign with the toolkit
./tools/signing/sign_artifact.sh \
  --artifact ghcr.io/org/app:v1.2.3 \
  --type image \
  --key image-signing \
  --verbose

# Or sign directly with cosign
cosign sign --key hashivault://image-signing \
  --annotation "version=v1.2.3" \
  --yes \
  ghcr.io/org/app:v1.2.3
```

### Verify before deploy

```bash
# Verify with the toolkit
./tools/signing/verify_artifact.sh \
  --artifact ghcr.io/org/app:v1.2.3 \
  --type image \
  --key image-signing

# Or verify directly with cosign
cosign verify --key hashivault://image-signing \
  ghcr.io/org/app:v1.2.3
```

---

## Binary Signing with Vault Transit

Sign compiled binaries using Vault transit's signing API directly.

### Sign a release binary

```bash
# Build the binary
go build -o dist/myapp-linux-amd64 ./cmd/myapp

# Sign with the toolkit
./tools/signing/sign_artifact.sh \
  --artifact ./dist/myapp-linux-amd64 \
  --type binary \
  --key code-signing

# This produces:
#   dist/myapp-linux-amd64.vault-sig   (detached Vault transit signature)
#   .signatures/dist_myapp-linux-amd64.json  (metadata)
```

### Sign with GPG + Vault transit (hybrid approach)

For environments that require GPG-compatible signatures with Vault-backed key management:

```bash
# 1. Hash the binary
HASH=$(sha256sum dist/myapp-linux-amd64 | awk '{print $1}')

# 2. Sign the hash with Vault transit
SIGNATURE=$(vault write -format=json transit/sign/code-signing \
  input="$(printf '%s' "$HASH" | base64)" \
  hash_algorithm=sha2-256 | jq -r '.data.signature')

# 3. Store the signature bundle
cat > dist/myapp-linux-amd64.sigbundle.json <<EOF
{
  "artifact": "myapp-linux-amd64",
  "hash_algorithm": "sha256",
  "hash": "${HASH}",
  "signature": "${SIGNATURE}",
  "vault_key": "code-signing",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# 4. Verify
VALID=$(vault write -format=json transit/verify/code-signing \
  input="$(printf '%s' "$HASH" | base64)" \
  signature="$SIGNATURE" \
  hash_algorithm=sha2-256 | jq -r '.data.valid')

echo "Signature valid: ${VALID}"
```

---

## SBOM Generation and Signing

Generate a Software Bill of Materials and sign it for supply chain integrity.

### Generate SBOM with syft

```bash
# Install syft
brew install syft    # macOS

# Generate SBOM for a container image
syft ghcr.io/org/app:v1.2.3 -o spdx-json > sbom.spdx.json

# Or for a local project directory
syft dir:. -o cyclonedx-json > sbom.cdx.json
```

### Sign the SBOM

```bash
# Sign with the toolkit (Vault transit)
./tools/signing/sign_artifact.sh \
  --artifact ./sbom.spdx.json \
  --type sbom \
  --key sbom-signing

# Sign with cosign keyless (CI)
cosign sign-blob \
  --output-signature sbom.spdx.json.sig \
  --output-certificate sbom.spdx.json.cert \
  --yes \
  sbom.spdx.json
```

### Verify signed SBOM

```bash
# Verify with the toolkit
./tools/signing/verify_artifact.sh \
  --artifact ./sbom.spdx.json \
  --type sbom \
  --key sbom-signing \
  --verbose

# Verify cosign-signed SBOM
cosign verify-blob \
  --signature sbom.spdx.json.sig \
  --certificate sbom.spdx.json.cert \
  --certificate-identity "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.2.3" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sbom.spdx.json
```

### Attach SBOM as OCI artifact (cosign)

```bash
# Attach SBOM to the container image
cosign attach sbom --sbom sbom.spdx.json ghcr.io/org/app:v1.2.3

# Sign the attached SBOM
cosign sign --key hashivault://sbom-signing \
  --yes \
  --attachment sbom \
  ghcr.io/org/app:v1.2.3

# Verify
cosign verify --key hashivault://sbom-signing \
  --attachment sbom \
  ghcr.io/org/app:v1.2.3
```

---

## CI Integration: GitHub Actions

### Keyless signing in CI (recommended for GitHub Actions)

```yaml
# .github/workflows/build-sign.yml
name: Build and Sign
on:
  push:
    tags: ['v*']

permissions:
  id-token: write
  packages: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image_ref: ${{ steps.build.outputs.image_ref }}
    steps:
      - uses: actions/checkout@v4

      - name: Build and push
        id: build
        run: |
          IMAGE="ghcr.io/${{ github.repository }}:${{ github.ref_name }}"
          docker build -t "$IMAGE" .
          docker push "$IMAGE"
          echo "image_ref=${IMAGE}" >> "$GITHUB_OUTPUT"

  sign:
    needs: build
    uses: ./.github/workflows/sign-and-verify.yml
    with:
      image_ref: ${{ needs.build.outputs.image_ref }}
      signing_method: keyless
      generate_provenance: true
```

### Vault KMS signing in CI

```yaml
# .github/workflows/build-sign-vault.yml
name: Build and Sign (Vault)
on:
  push:
    tags: ['v*']

permissions:
  id-token: write
  packages: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image_ref: ${{ steps.build.outputs.image_ref }}
    steps:
      - uses: actions/checkout@v4

      - name: Build and push
        id: build
        run: |
          IMAGE="ghcr.io/${{ github.repository }}:${{ github.ref_name }}"
          docker build -t "$IMAGE" .
          docker push "$IMAGE"
          echo "image_ref=${IMAGE}" >> "$GITHUB_OUTPUT"

  sign:
    needs: build
    uses: ./.github/workflows/sign-and-verify.yml
    with:
      image_ref: ${{ needs.build.outputs.image_ref }}
      signing_method: vault-kms
      vault_addr: https://vault.example.com
      vault_role: github-ci
      vault_transit_key: image-signing
```

---

## Verification at Deploy Time

### Kubernetes admission control with Kyverno

```yaml
# policy/require-signed-images.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/org/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/org/repo/.github/workflows/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
```

### Pre-deploy verification script

```bash
#!/usr/bin/env bash
# verify-before-deploy.sh — Gate deployment on signature verification
set -euo pipefail

IMAGE="$1"
EXPECTED_IDENTITY="${2:-}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

echo "Verifying signature on: ${IMAGE}"

# Verify the image signature
if [[ -n "$EXPECTED_IDENTITY" ]]; then
  cosign verify \
    --certificate-identity "$EXPECTED_IDENTITY" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE"
else
  cosign verify \
    --certificate-identity-regexp "https://github.com/org/.*" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE"
fi

# Verify SLSA provenance
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "https://github.com/org/.*" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$IMAGE"

# Verify SBOM exists
cosign verify \
  --certificate-identity-regexp "https://github.com/org/.*" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  --attachment sbom \
  "$IMAGE"

echo "All verification checks passed. Safe to deploy."
```

---

## Vault Transit Key Setup

One-time setup for creating signing keys in Vault:

```bash
# Enable transit engine (if not already enabled)
vault secrets enable transit

# Create keys for different artifact types
vault write transit/keys/image-signing \
  type=ecdsa-p256 \
  deletion_allowed=false

vault write transit/keys/code-signing \
  type=rsa-4096 \
  deletion_allowed=false

vault write transit/keys/sbom-signing \
  type=ecdsa-p256 \
  deletion_allowed=false

# Create a policy for CI signing
vault policy write ci-signing - <<EOF
path "transit/sign/image-signing" {
  capabilities = ["update"]
}
path "transit/verify/image-signing" {
  capabilities = ["update"]
}
path "transit/sign/sbom-signing" {
  capabilities = ["update"]
}
path "transit/verify/*" {
  capabilities = ["update"]
}
EOF

# Bind the policy to GitHub Actions OIDC
vault write auth/jwt/role/github-ci \
  role_type=jwt \
  bound_audiences="https://github.com/org" \
  bound_claims_type=glob \
  bound_claims='{"repository":"org/*"}' \
  user_claim=repository \
  policies=ci-signing \
  ttl=600
```
