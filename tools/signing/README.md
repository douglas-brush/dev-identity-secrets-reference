# Artifact Signing Toolkit

Sign and verify container images, binaries, and SBOMs using cosign, notation, or HashiCorp Vault transit.

## Tools

| Script | Purpose |
|--------|---------|
| `sign_artifact.sh` | Sign artifacts with auto-detected signing method |
| `verify_artifact.sh` | Verify signatures with structured pass/fail output |

## Signing Methods

The toolkit auto-detects the best available signing method:

| Priority | Method | Requirements | Use Case |
|----------|--------|-------------|----------|
| 1 | cosign + Vault KMS | `cosign`, `VAULT_ADDR`, `--key` | Production image signing with Vault-managed keys |
| 2 | cosign keyless (Fulcio) | `cosign`, OIDC token | CI/CD ephemeral signing via GitHub Actions OIDC |
| 3 | notation | `notation` | OCI-native signing with trust policies |
| 4 | Vault transit direct | `vault`, `--key` | Binary/SBOM signing without cosign |

## Quick Start

### Sign a container image with Vault KMS

```bash
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=s.xxxxxxxx

./sign_artifact.sh \
  --artifact ghcr.io/org/app:v1.2.3 \
  --type image \
  --key transit-sign-key
```

### Sign a binary with Vault transit

```bash
./sign_artifact.sh \
  --artifact ./dist/myapp-linux-amd64 \
  --type binary \
  --key code-signing
```

### Sign an SBOM

```bash
./sign_artifact.sh \
  --artifact ./sbom.spdx.json \
  --type sbom \
  --key sbom-key
```

### Keyless signing (CI/CD with OIDC)

```bash
# In GitHub Actions with id-token: write permission
./sign_artifact.sh \
  --artifact ghcr.io/org/app:sha-abc1234 \
  --type image
```

### Verify a signed artifact

```bash
./verify_artifact.sh \
  --artifact ghcr.io/org/app:v1.2.3 \
  --type image \
  --key transit-sign-key
```

### Verify with identity constraints (keyless)

```bash
./verify_artifact.sh \
  --artifact ghcr.io/org/app:v1.2.3 \
  --type image \
  --certificate-identity "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## Verification Checks

`verify_artifact.sh` runs five checks and outputs structured results:

| Check | What It Validates |
|-------|-------------------|
| Signature exists | A signature file or OCI annotation is present |
| Cryptographic verification | The signature is mathematically valid against the key |
| Key trust chain | The signing key is active, correct type, and not scheduled for deletion |
| Metadata consistency | Stored signing metadata matches the current artifact hash |
| Timestamp validation | Signature is not from the future and not expired |

## Output Formats

Both scripts support `--output-format json` for CI integration:

```bash
./verify_artifact.sh \
  --artifact ghcr.io/org/app:v1.2.3 \
  --type image \
  --key mykey \
  --output-format json
```

## Signature Metadata

When signing, metadata is stored in `.signatures/` as JSON:

```json
{
  "artifact": "ghcr.io/org/app:v1.2.3",
  "artifact_type": "image",
  "artifact_hash": "sha256:abc123...",
  "signing_method": "cosign-vault",
  "signing_identity": "ci@github-actions",
  "vault_key": "transit-sign-key",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `VAULT_ADDR` | Vault server address |
| `VAULT_TOKEN` | Vault authentication token |
| `COSIGN_KEY` | Override cosign key reference (e.g. `hashivault://mykey`) |
| `SIGNING_IDENTITY` | Override signer identity string |
| `NO_COLOR` | Disable colored output |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (signing completed or all verification checks passed) |
| 1 | Failure (signing failed or one or more verification checks failed) |
| 2 | Usage error or missing dependencies |

## Integration with CI

See [`platform/github-actions/reusable/sign-and-verify.yml`](../../platform/github-actions/reusable/sign-and-verify.yml) for a reusable GitHub Actions workflow that integrates these tools.

See [`examples/signing/`](../../examples/signing/) for complete examples of signing workflows.
