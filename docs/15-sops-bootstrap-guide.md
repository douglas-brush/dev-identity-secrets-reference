# SOPS Bootstrap Guide

## 1. Overview

SOPS (Secrets OPerationS) encrypts structured data files — YAML, JSON, ENV, INI — while leaving keys in cleartext so diffs remain readable. In this architecture SOPS is the mechanism that allows secrets to live in Git without exposing plaintext values.

The `.sops.yaml` at the repository root defines creation rules that match file paths to encryption recipients. Each environment (`dev`, `staging`, `prod`) has its own rule. Only fields matching `encrypted_regex` are encrypted, so non-secret config keys stay visible for review.

SOPS supports multiple key backends simultaneously:
- **age** — lightweight, file-based asymmetric encryption used for the break-glass recipient and individual developer keys
- **AWS KMS** — envelope encryption using IAM-controlled customer-managed keys
- **Azure Key Vault** — RSA or EC key operations through Azure RBAC
- **GCP Cloud KMS** — symmetric or asymmetric keys through GCP IAM

In production, cloud KMS is mandatory. age alone is acceptable for dev and local environments.

---

## 2. Prerequisites

### CLI tools

Install `sops` and `age` before proceeding.

```bash
# macOS
brew install sops age

# Linux (Debian/Ubuntu)
sudo apt-get install -y age
# sops — download the latest release binary
SOPS_VERSION=$(curl -s https://api.github.com/repos/getsops/sops/releases/latest | grep tag_name | cut -d '"' -f 4)
curl -Lo /usr/local/bin/sops "https://github.com/getsops/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.amd64"
chmod +x /usr/local/bin/sops
```

Verify:

```bash
sops --version
age --version
```

### Cloud KMS access (when applicable)

| Provider | Requirement |
|----------|-------------|
| AWS | IAM principal with `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey` on the target CMK |
| Azure | RBAC role `Key Vault Crypto User` on the Key Vault key |
| GCP | IAM role `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the target key resource |

Cloud credentials must be configured in the local environment before SOPS can use the KMS backend (`aws configure`, `az login`, or `gcloud auth application-default login`).

---

## 3. Break-glass age key generation ceremony

The break-glass key is the key of last resort. It is listed as a recipient on every SOPS rule so that if cloud KMS access is lost, encrypted files can still be recovered. This key must be generated with deliberate ceremony, not casually.

### Step 1 — Generate the key pair on an air-gapped or isolated machine

```bash
age-keygen -o break-glass.key 2>break-glass.pub
```

This produces:
- `break-glass.key` — the private key file (contains `AGE-SECRET-KEY-...`)
- `break-glass.pub` — stderr output containing the public key (`age1...`)

Extract and record the public key:

```bash
cat break-glass.pub
# Output: Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### Step 2 — Record the public key in `.sops.yaml`

Replace every `age1replacewithbreakglassrecipientonly` placeholder in `.sops.yaml` with the actual public key from step 1.

### Step 3 — Secure the private key

The private key must be stored offline in at least two physically separate locations. Options ranked by preference:

1. **Hardware security module** — import the raw key material into an HSM if your organization has one
2. **Split custody with Shamir sharing** — split the key into N shares with a K-of-N threshold using `ssss-split`:
   ```bash
   # 3-of-5 split
   cat break-glass.key | grep 'AGE-SECRET-KEY-' | ssss-split -t 3 -n 5 -w break-glass
   ```
   Distribute shares to separate custodians. Store each share in a tamper-evident envelope in a separate safe or vault.
3. **Sealed envelopes in two safes** — print the full private key, place copies in tamper-evident envelopes, store in two separate physical safes with logged access

### Step 4 — Destroy the working copy

After securing the private key in escrow:

```bash
shred -u break-glass.key break-glass.pub
# or on macOS (no shred by default):
rm -P break-glass.key break-glass.pub
```

### Step 5 — Document the ceremony

Record in your organization's key management log:
- Date and time (UTC)
- Participants and their roles
- Public key fingerprint
- Storage locations of private key material
- Access procedure for retrieval

---

## 4. Wiring cloud KMS

The `.sops.yaml` file ships with cloud KMS lines commented out. To enable a cloud KMS backend for an environment, uncomment the relevant line and replace the placeholder with your actual resource identifier.

### AWS KMS

```yaml
creation_rules:
  - path_regex: secrets/prod/.*\.enc\.(ya?ml|json)$
    kms: 'arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    age: 'age1youractualbreakglasspublickey'
    encrypted_regex: '^(data|stringData|secrets|env|password|token|client_secret|private_key|api_key|connection_string|credentials)$'
```

Multiple KMS keys (cross-region or cross-account) are comma-separated:

```yaml
    kms: 'arn:aws:kms:us-east-1:111122223333:key/key-id-1,arn:aws:kms:us-west-2:111122223333:key/key-id-2'
```

### Azure Key Vault

```yaml
    azure_keyvault: 'https://your-prod-kv.vault.azure.net/keys/sops-prod/aabbccddeeff00112233'
```

The version suffix is optional. Without it, SOPS uses the latest key version.

### GCP Cloud KMS

```yaml
    gcp_kms: 'projects/your-project-prod/locations/global/keyRings/sops/cryptoKeys/prod'
```

### Combining cloud KMS with age

Every rule should include both a cloud KMS key and the break-glass age key. SOPS encrypts the data key to all listed recipients, so any single recipient can decrypt. This provides redundancy — cloud KMS for normal operations, age for break-glass recovery.

After editing `.sops.yaml`, re-encrypt all existing files to add the new recipient. See section 7 for the rotation procedure.

---

## 5. Testing encryption

### Create a sample secrets file

```bash
mkdir -p secrets/dev
cat > /tmp/test-secret.yaml <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: dev
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=
  api_key: dGVzdC1hcGkta2V5LTEyMzQ=
stringData:
  connection_string: "postgresql://user:pass@db:5432/mydb"
EOF
```

### Encrypt

```bash
sops --encrypt /tmp/test-secret.yaml > secrets/dev/test-secret.enc.yaml
```

SOPS matches the output path against `.sops.yaml` rules. Because the file lands in `secrets/dev/`, the dev creation rule applies and only fields matching `encrypted_regex` are encrypted.

### Verify encryption

```bash
cat secrets/dev/test-secret.enc.yaml
```

You should see:
- `metadata.name`, `metadata.namespace`, `apiVersion`, `kind`, `type` — in cleartext
- `data.password`, `data.api_key`, `stringData.connection_string` — encrypted (ENC[AES256_GCM,...])
- A `sops:` metadata block at the bottom listing recipients and the MAC

### Decrypt and verify round-trip

```bash
sops --decrypt secrets/dev/test-secret.enc.yaml > /tmp/test-secret-decrypted.yaml
diff /tmp/test-secret.yaml /tmp/test-secret-decrypted.yaml
```

If `diff` produces no output, the round-trip is clean.

### In-place editing

SOPS can open an encrypted file in your `$EDITOR`, decrypt in memory, let you edit, and re-encrypt on save:

```bash
sops secrets/dev/test-secret.enc.yaml
```

### Clean up the test file

```bash
rm /tmp/test-secret.yaml /tmp/test-secret-decrypted.yaml
rm secrets/dev/test-secret.enc.yaml  # unless you want to keep it
```

---

## 6. Adding recipients

When a new developer needs to decrypt SOPS-encrypted files, add their age public key to the relevant `.sops.yaml` rules.

### Step 1 — Developer generates a personal age key pair

```bash
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
```

The developer shares only the public key (the `age1...` line printed to stderr). The private key stays on the developer's machine at `~/.config/sops/age/keys.txt`. SOPS reads this path by default, or the developer can set `SOPS_AGE_KEY_FILE`.

### Step 2 — Add the public key to `.sops.yaml`

Multiple age recipients are comma-separated:

```yaml
creation_rules:
  - path_regex: secrets/dev/.*\.enc\.(ya?ml|json)$
    age: 'age1breakglasskey,age1developerAkey,age1developerBkey'
    encrypted_regex: '^(data|stringData|secrets|env|password|token|client_secret|private_key|api_key|connection_string|credentials)$'
```

### Step 3 — Re-encrypt all files to include the new recipient

Adding a key to `.sops.yaml` only affects newly encrypted files. Existing files must be re-encrypted so the new recipient can decrypt them.

```bash
# Preview what will change
tools/rotate/rotate_sops_keys.sh --dry-run --env dev

# Apply
tools/rotate/rotate_sops_keys.sh --env dev

# Commit
git add .sops.yaml secrets/dev/
git commit -m "chore: add developer age key and re-encrypt dev secrets"
```

### Removing a recipient

To revoke access, remove the public key from `.sops.yaml` and re-encrypt. The removed recipient will no longer be able to decrypt newly encrypted files. Previously decrypted material should be considered exposed — rotate the underlying secrets, not just the SOPS keys.

---

## 7. Key rotation

Key rotation re-encrypts all SOPS-managed files with the current recipient list from `.sops.yaml`. Use the included `tools/rotate/rotate_sops_keys.sh` script.

### When to rotate

- A developer leaves the team (remove their key, then rotate)
- A new cloud KMS key is provisioned
- The break-glass key is suspected compromised
- Periodic rotation per organizational policy

### Usage

```bash
# Preview changes without modifying files
tools/rotate/rotate_sops_keys.sh --dry-run

# Rotate all environments
tools/rotate/rotate_sops_keys.sh

# Rotate only production
tools/rotate/rotate_sops_keys.sh --env prod

# Verbose output with custom log location
tools/rotate/rotate_sops_keys.sh --verbose --log-file /tmp/rotation.log
```

### What the script does

1. Validates that `sops` is installed and `.sops.yaml` exists
2. Checks for an available age key file
3. Finds all `*.enc.yaml`, `*.enc.yml`, and `*.enc.json` files in the repository
4. For each file: decrypts to a temp file, re-encrypts with the current `.sops.yaml` recipients, verifies the result decrypts cleanly, replaces the original
5. Logs every operation to `logs/sops-rotation-<timestamp>.log`

### After rotation

```bash
git diff --stat
git add -A
git commit -m "chore: rotate SOPS encryption keys"
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `could not decrypt data key` | Your age private key is not in the recipient list, or the key file is missing | Verify `~/.config/sops/age/keys.txt` exists and its public key appears in `.sops.yaml` |
| `no matching creation rule` | The file path does not match any `path_regex` in `.sops.yaml` | Check the file path against the regex patterns. SOPS uses first-match. |
| `error getting data key` with AWS KMS | Missing IAM permissions or expired credentials | Run `aws sts get-caller-identity` to confirm identity, then verify KMS key policy |
| `azure.BearerAuthorizer` errors | Expired or missing Azure login | Run `az login` and `az account set --subscription <sub-id>` |
| `googleapi: Error 403: Permission denied` | Missing GCP IAM binding | Run `gcloud auth application-default login` and verify the IAM role on the key resource |
| Encrypted file has no `sops:` block | File was never encrypted by SOPS, or was overwritten with plaintext | Re-encrypt from the plaintext source |
| `MAC mismatch` | The encrypted file was manually edited after encryption | Re-encrypt from the last known-good plaintext, or decrypt using `--ignore-mac` (use with caution — verify integrity separately) |
| `SOPS_AGE_KEY_FILE` set but key not found | Environment variable points to a non-existent path | Verify: `ls -la "$SOPS_AGE_KEY_FILE"` |
| Rotation script says "No encrypted files found" | No files match the expected naming pattern or environment filter | Check that files use `.enc.yaml` / `.enc.json` naming and are inside `secrets/` |

### Diagnostic commands

```bash
# Show which creation rule SOPS would apply to a file
sops --verbose --encrypt --in-place /dev/null 2>&1 | grep -i rule  # (use a test path)

# List age recipients an encrypted file was encrypted for
grep -A 20 '^sops:' secrets/dev/example.enc.yaml | grep 'recipient:'

# Verify your local age key fingerprint
grep 'public key' ~/.config/sops/age/keys.txt

# Test decryption without writing output
sops --decrypt secrets/dev/example.enc.yaml > /dev/null
```

---

## 9. Security considerations

### Break-glass key storage

The break-glass age private key is the single most sensitive artifact in this system. If compromised, an attacker with access to the Git repository can decrypt every SOPS-encrypted file.

Controls:
- Never store the break-glass private key on any networked machine after the generation ceremony
- Never store it in a password manager accessible to individual accounts
- Use split custody (Shamir secret sharing or equivalent) so no single person can reconstitute the key
- Log every retrieval from physical storage with date, time, person, and reason
- After a break-glass event, generate a new key pair and re-encrypt all files

### Split custody model

For organizations using Shamir splitting:

| Parameter | Recommended value |
|-----------|-------------------|
| Total shares (N) | 5 |
| Threshold (K) | 3 |
| Custodian overlap with cloud KMS admins | 0 — different people |
| Share storage | Tamper-evident envelopes in separate physical safes |
| Reconstitution procedure | Documented, tested annually |

### Cloud KMS vs. age

| Property | Cloud KMS | age |
|----------|-----------|-----|
| Key material location | HSM-backed, never exported | Local file |
| Access control | IAM policy with audit trail | File system permissions |
| Rotation | Managed, automatic version rotation available | Manual re-keying |
| Availability | Tied to cloud provider uptime | Offline-capable |
| Break-glass suitability | Poor — if IAM is locked out, KMS is unreachable | Good — independent of any service |

Use cloud KMS as the primary encryption backend. Use age as the break-glass fallback. Do not rely on age alone for production.

### Operational rules

- Every `.sops.yaml` change must be reviewed in a pull request
- Rotation after access revocation is mandatory, not optional
- Plaintext secrets must never be committed — use pre-commit hooks to block `secrets/` paths without `.enc.` in the filename
- The `encrypted_regex` pattern must cover all sensitive field names used in your configuration format. Audit this when adding new secret types.
- Test decryption in CI after every `.sops.yaml` change to catch misconfigurations before they block the team
