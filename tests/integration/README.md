# Integration Tests

End-to-end tests that validate the reference architecture's core secret management workflows against real infrastructure.

## Prerequisites

| Test | Requirements |
|------|-------------|
| `test_sops_roundtrip.sh` | `sops`, `age-keygen`, `jq` (no server needed) |
| `test_vault_dynamic_creds.sh` | Running Vault with database engine configured |
| `test_vault_pki.sh` | Running Vault, `openssl` |
| `test_vault_ssh_ca.sh` | Running Vault, `ssh-keygen` |
| `test_vault_transit.sh` | Running Vault, `base64` |

All Vault tests require:
- `vault` CLI installed and in `PATH`
- `VAULT_ADDR` set to a reachable Vault instance
- A valid Vault token (run `vault login` first)
- `jq` installed

## Running Against Local Dev Environment

Start the local dev Vault first:

```bash
# Option 1: Use the dev environment (docker-compose)
make dev-up

# Option 2: Use Vault dev mode directly
vault server -dev -dev-root-token-id=root &
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
```

Run individual tests:

```bash
# SOPS roundtrip (no Vault needed)
./tests/integration/test_sops_roundtrip.sh

# Vault PKI lifecycle
./tests/integration/test_vault_pki.sh

# Vault SSH certificate authority
./tests/integration/test_vault_ssh_ca.sh

# Vault transit encryption
./tests/integration/test_vault_transit.sh

# Vault dynamic database credentials
./tests/integration/test_vault_dynamic_creds.sh
```

Run all integration tests:

```bash
for t in tests/integration/test_*.sh; do
  echo "=== Running $t ==="
  bash "$t" || echo "FAILED: $t"
  echo ""
done
```

## Running Against a Real Vault Instance

```bash
export VAULT_ADDR=https://vault.example.com:8200
vault login -method=oidc

# Tests create isolated mounts with unique names (pid-suffixed) and clean
# up after themselves, so they are safe to run against shared instances.
./tests/integration/test_vault_pki.sh
```

## What Each Test Covers

### `test_sops_roundtrip.sh`

| Area | What's tested |
|------|--------------|
| Basic roundtrip | YAML and JSON encrypt/decrypt with age keys |
| Value preservation | Strings, integers, booleans survive roundtrip |
| Partial encryption | `encrypted_regex` leaves public keys in cleartext |
| Key rotation | Re-encrypt from key1 to key2, verify decryption |
| Multi-recipient | Encrypt for two age keys, both can decrypt |
| Output formats | Dotenv output for env-file workflows |

### `test_vault_pki.sh`

| Area | What's tested |
|------|--------------|
| Root CA | Generate internal root CA |
| Intermediate CA | CSR, sign with root, import chain |
| Leaf certificate | Issue via role, verify CN and chain |
| Chain validation | OpenSSL verify against CA bundle |
| CRL | CRL endpoint accessible |
| Revocation | Revoke leaf, verify revocation timestamp |

### `test_vault_ssh_ca.sh`

| Area | What's tested |
|------|--------------|
| CA setup | Generate SSH signing key |
| Role config | Allowed users, extensions, TTL |
| Key signing | Sign ed25519 user public key |
| Certificate fields | Type, principals, signing CA |
| TTL enforcement | Short-TTL certificate validity window |
| Principal control | Allowed and disallowed principals |

### `test_vault_transit.sh`

| Area | What's tested |
|------|--------------|
| Key creation | Default aes256-gcm96 key |
| Encrypt/decrypt | Roundtrip with base64 plaintext |
| Non-determinism | Same plaintext produces different ciphertext |
| Key rotation | Rotate to v2, old ciphertext still decrypts |
| Rewrap | Re-encrypt v1 ciphertext with v2 key |
| Version enforcement | min_decryption_version rejects old versions |

### `test_vault_dynamic_creds.sh`

| Area | What's tested |
|------|--------------|
| Engine check | Database engine mounted |
| Credential generation | Username, password, lease ID |
| Uniqueness | Each request gets unique credentials |
| Lease management | Lookup, renew, revoke |

## Cleanup

All tests clean up after themselves using `trap` handlers. If a test is interrupted, cleanup runs automatically. Test resources use PID-suffixed names to avoid collisions with concurrent runs.

If cleanup fails for any reason, remove leftover mounts manually:

```bash
vault secrets list | grep -E '(pki|ssh|transit)-.*-test-'
# vault secrets disable <mount-path>
```
