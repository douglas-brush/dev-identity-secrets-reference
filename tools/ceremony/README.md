# Key Ceremony Runbook

Formal procedures for Root CA and Intermediate CA key ceremonies with Shamir secret sharing and hardware-backed key protection.

---

## Pre-Ceremony Checklist

### Environment

- [ ] Air-gapped machine prepared (no network interfaces active)
- [ ] Verified boot media integrity (hash-checked live USB or hardened OS)
- [ ] Machine BIOS/UEFI secure boot enabled
- [ ] All external storage devices accounted for and labeled
- [ ] Room secured — no unauthorized personnel, no cameras/phones unless recording ceremony

### Software

- [ ] OpenSSL >= 1.1.1 installed and version verified
- [ ] `ssss-split` / `ssss-combine` installed (Shamir's Secret Sharing Scheme)
- [ ] Ceremony scripts copied to air-gapped machine and hash-verified
- [ ] Script hashes match repository:
  - `sha256sum root_ca_ceremony.sh`
  - `sha256sum intermediate_ca_ceremony.sh`
  - `sha256sum import_to_vault.sh`

### Personnel

- [ ] Ceremony lead identified (operator)
- [ ] Minimum 2 independent witnesses present
- [ ] All key custodians present (N custodians for N Shamir shares)
- [ ] Each custodian has tamper-evident envelope and secure storage plan
- [ ] Notary or compliance officer present (if required by policy)

### Materials

- [ ] Blank USB drives for share distribution (one per custodian, plus backups)
- [ ] Tamper-evident bags/envelopes (one per share)
- [ ] Ceremony log printout for wet signatures
- [ ] Safe deposit box or vault access confirmed for share storage
- [ ] Hardware Security Module ready (if using HSM — PKCS#11 configured)

---

## Root CA Ceremony Procedure

### Step 1 — Verify Environment

```bash
# Confirm air-gap: no network
ip link show        # All interfaces should be DOWN
nmcli device status # All disconnected

# Verify tools
openssl version
ssss-split --version 2>/dev/null || echo "ssss not available — fallback mode"
```

### Step 2 — Dry Run

```bash
./root_ca_ceremony.sh \
  --algorithm ecdsap384 \
  --shares 5 \
  --threshold 3 \
  --dry-run
```

Review the dry-run output with all witnesses. Confirm parameters are correct.

### Step 3 — Execute Root CA Ceremony

```bash
./root_ca_ceremony.sh \
  --algorithm ecdsap384 \
  --shares 5 \
  --threshold 3 \
  --validity-days 3650 \
  --subject "/C=US/O=YourOrg/OU=Certificate Authority/CN=YourOrg Root CA"
```

The script will:
1. Generate the root CA private key (ECDSA P-384 or RSA 4096)
2. Create a self-signed root certificate with CA:TRUE, keyCertSign, cRLSign extensions
3. Split the private key into 5 Shamir shares (threshold: 3)
4. Securely delete the unsplit private key from disk
5. Write ceremony logs (text + JSON) with SHA-256 hashes of every artifact

### Step 4 — Distribute Shares

For each share:
1. Copy the share file to the custodian's USB drive
2. Verify the SHA-256 hash matches the ceremony log
3. Place the USB in a tamper-evident envelope
4. Custodian signs the ceremony log acknowledging receipt
5. Custodian stores the envelope in their designated secure location

### Step 5 — Sign Ceremony Log

All parties sign the text ceremony log:
- Ceremony operator
- Each witness
- Each key custodian (acknowledging their share)

### Step 6 — Secure the Root Certificate

```bash
# Copy root-ca.pem to distribution media
cp ceremony-output/*/certs/root-ca.pem /mnt/usb/

# Verify hash
sha256sum /mnt/usb/root-ca.pem
# Compare with ceremony log hash
```

The root CA certificate (public) is distributed to all systems that need to trust the hierarchy. The private key exists only as Shamir shares.

---

## Intermediate CA Ceremony Procedure

### Step 1 — Collect Shares

Gather the threshold number of key custodians (M of N). Each custodian:
1. Retrieves their tamper-evident envelope
2. Verifies the envelope seal is intact
3. Provides their share to the ceremony operator

### Step 2 — Prepare Share Directory

```bash
mkdir -p collected-shares/
# Copy each custodian's share into this directory
# Files must be named share-1.txt, share-2.txt, etc. (matching original naming)
```

### Step 3 — Dry Run

```bash
./intermediate_ca_ceremony.sh \
  --root-cert ./root-ca.pem \
  --shares-dir ./collected-shares/ \
  --threshold 3 \
  --dry-run
```

### Step 4 — Execute Intermediate CA Ceremony

```bash
./intermediate_ca_ceremony.sh \
  --algorithm ecdsap384 \
  --root-cert ./root-ca.pem \
  --shares-dir ./collected-shares/ \
  --threshold 3 \
  --validity-days 1825 \
  --path-length 0 \
  --subject "/C=US/O=YourOrg/OU=Certificate Authority/CN=YourOrg Intermediate CA"
```

The script will:
1. Validate collected Shamir shares
2. Reconstruct the root CA private key
3. Generate a new intermediate CA key pair
4. Create and sign the intermediate CA certificate (pathlen:0)
5. Build the certificate chain bundle
6. Securely delete the reconstructed root key
7. Write ceremony logs

### Step 5 — Verify Chain

```bash
openssl verify -CAfile root-ca.pem intermediate-ca.pem
# Expected: intermediate-ca.pem: OK
```

### Step 6 — Sign Ceremony Log

Same witness/custodian signing procedure as the root ceremony.

---

## Vault Import Procedure

This step is performed on a network-connected machine with Vault access. It is NOT performed on the air-gapped ceremony machine.

### Step 1 — Transfer Certificates

Transfer from the air-gapped machine to the Vault-connected machine:
- `root-ca.pem` (root CA certificate — public)
- `intermediate-ca.pem` (intermediate CA certificate — public)
- `intermediate-ca.key` (intermediate CA private key — **sensitive**)
- `ca-chain.pem` (chain bundle — public)

Verify hashes match the ceremony log after transfer.

### Step 2 — Import to Vault

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="<root-or-admin-token>"

./import_to_vault.sh \
  --cert-dir ./ceremony-certs/ \
  --vault-mount pki \
  --vault-int-mount pki_int \
  --crl-url "https://pki.example.com/v1/pki_int/crl" \
  --ocsp-url "https://pki.example.com/v1/pki_int/ocsp"
```

### Step 3 — Verify

```bash
# Read back root CA
vault read pki/cert/ca

# Read back intermediate CA
vault read pki_int/cert/ca

# Issue a test certificate
vault write pki_int/issue/test-role \
  common_name="test.example.com" \
  ttl="24h"
```

### Step 4 — Secure Cleanup

After successful Vault import, securely delete the intermediate CA private key from the transfer media:

```bash
# Overwrite and remove
dd if=/dev/urandom of=intermediate-ca.key bs=1 count=$(wc -c < intermediate-ca.key) conv=notrunc
rm -f intermediate-ca.key
```

---

## Key Custodian Responsibilities

Each custodian of a Shamir share agrees to:

1. **Secure storage** — Store the share in a physically secure location (safe deposit box, corporate vault, or equivalent)
2. **Tamper evidence** — Maintain the tamper-evident seal; report any breach immediately
3. **Availability** — Be reachable within the organization's defined SLA for ceremony participation (typically 24-48 hours for emergency, scheduled for planned ceremonies)
4. **No copying** — Do not duplicate the share or store it digitally outside the issued media
5. **No collusion** — Never provide your share to another custodian or combine shares outside a formal ceremony
6. **Succession** — If leaving the organization or role, participate in a share re-issuance ceremony before departure
7. **Annual verification** — Participate in annual share verification (confirm envelope seal intact, media readable)

---

## Annual Re-Signing / Rotation Procedure

### Intermediate CA Rotation (recommended: every 2-3 years)

1. Initiate a new intermediate CA ceremony (same root CA)
2. Issue the new intermediate CA certificate
3. Import into Vault alongside the existing intermediate
4. Transition workloads to certificates issued by the new intermediate
5. Allow the old intermediate to expire naturally (do not revoke unless compromised)

### Root CA Rotation (recommended: before expiry, typically 7-10 years)

1. Plan 12+ months before root CA expiry
2. Generate new root CA using the ceremony procedure
3. Cross-sign: have the old root CA sign the new root CA (requires Shamir reconstruction)
4. Distribute the new root CA to all trust stores
5. Issue new intermediate CAs under the new root
6. Maintain the old root in trust stores until all old intermediates expire

### Share Verification (annual)

1. Contact all custodians
2. Each custodian verifies their envelope seal is intact
3. Optionally verify share media is readable (on air-gapped machine)
4. Log verification results
5. Re-issue any shares where custodians have changed roles

---

## Disaster Recovery from Shamir Shares

### Scenario: Intermediate CA Key Lost

1. The intermediate CA key is stored in Vault; Vault's own backup/recovery handles this
2. If Vault is unrecoverable, re-run the intermediate CA ceremony to issue a new intermediate

### Scenario: Root CA Signing Needed (Emergency)

1. Invoke emergency ceremony procedure
2. Gather threshold (M) custodians — follow normal ceremony security procedures
3. Reconstruct root key from shares
4. Perform the required signing operation
5. Securely destroy the reconstructed key
6. Document everything in a new ceremony log

### Scenario: Custodian Share Lost or Compromised

1. Immediately initiate a re-sharing ceremony
2. Reconstruct the root key using remaining valid shares (must meet threshold)
3. Generate a new set of shares with new parameters if desired
4. Securely destroy all old shares
5. Distribute new shares to custodians
6. Update the share registry and ceremony log

### Scenario: Insufficient Shares Available

If fewer than the threshold number of shares can be recovered, the root CA private key is **permanently unrecoverable**. This is by design. The recovery path is:

1. Generate a new root CA (new ceremony)
2. Issue new intermediate CAs
3. Rotate all certificates in the hierarchy
4. Update all trust stores with the new root CA
5. Conduct a post-mortem on why shares were unavailable
