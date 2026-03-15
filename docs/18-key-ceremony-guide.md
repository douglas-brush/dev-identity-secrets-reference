# 18 — Key Ceremony Guide

## 1. Why Hardware-Backed Ceremonies Matter

A certificate authority private key is the single highest-value cryptographic asset in a PKI hierarchy. Compromise of a root CA key invalidates the entire chain of trust and requires full re-issuance of every certificate in the hierarchy — across every service, device, and identity that relies on it.

Hardware-backed key ceremonies address three problems that software-only key generation cannot:

| Problem | Ceremony Control |
|---------|-----------------|
| Key material exposure during generation | Air-gapped machine, no network exfiltration path |
| Single point of compromise | Shamir secret sharing distributes trust across M-of-N custodians |
| Auditability and non-repudiation | Witnessed, logged, hashed ceremony with wet signatures |
| Unauthorized key use | Key destroyed after ceremony; reconstruction requires quorum |

For compliance frameworks (SOC 2, PCI DSS, ISO 27001), a documented key ceremony is often the control that satisfies requirements around cryptographic key management, separation of duties, and dual control.

---

## 2. Root vs. Intermediate CA Hierarchy

This architecture uses a two-tier PKI hierarchy:

```
Root CA (offline, air-gapped)
  └── Intermediate CA (online, in Vault)
        ├── Server certificates
        ├── Client certificates
        ├── Code signing certificates
        └── mTLS identity certificates
```

### Root CA

- **Offline** — private key exists only as Shamir shares in physical custody
- **Long-lived** — typically 10-year validity
- **Rarely used** — only signs intermediate CA certificates
- **Trust anchor** — distributed to all trust stores

### Intermediate CA

- **Online** — private key stored in Vault PKI backend (or HSM)
- **Medium-lived** — typically 3-5 year validity
- **Frequently used** — issues end-entity certificates via Vault roles
- **Constrained** — pathLenConstraint:0 prevents further CA issuance
- **Revocable** — can be revoked by the root without rebuilding the entire hierarchy

The intermediate layer provides operational isolation: if the intermediate CA is compromised, revoke it and issue a new one from the root. The root never touches a network-connected machine.

---

## 3. Shamir Secret Sharing

Shamir's Secret Sharing Scheme (SSS) splits a secret into N shares such that any M shares (the threshold) can reconstruct the original, but M-1 shares reveal nothing about the secret. This is information-theoretically secure — it does not depend on computational hardness assumptions.

### Parameters

| Parameter | Typical Value | Rationale |
|-----------|--------------|-----------|
| N (total shares) | 5 | Covers key custodians with redundancy |
| M (threshold) | 3 | Tolerates loss of 2 shares while preventing 2-person collusion |

### Properties

- Any M shares reconstruct the secret exactly
- Any M-1 shares provide zero information about the secret
- Shares are mathematically independent — no share is "more important"
- The scheme works over a finite field (GF(p)) using polynomial interpolation

### Implementation

The ceremony scripts use `ssss-split` and `ssss-combine` from the `ssss` package (B. Poettering's implementation). When `ssss` is unavailable, the scripts fall back to an OpenSSL-based split that requires all shares — production ceremonies should always use proper SSS.

```bash
# Install ssss
apt-get install ssss    # Debian/Ubuntu
brew install ssss       # macOS
```

---

## 4. HSM Integration Options

For organizations requiring FIPS 140-2/3 validated key storage, the ceremony can be adapted to generate keys inside a Hardware Security Module rather than in software.

### PKCS#11 (On-Premises HSM)

Compatible with Thales Luna, Entrust nShield, Utimaco, and similar network HSMs.

```
Ceremony machine ── USB/Network ──> HSM
                                     │
                                     ├── Key generation inside HSM boundary
                                     ├── Signing operations via PKCS#11 API
                                     └── Key never leaves HSM in cleartext
```

Integration points:
- OpenSSL engine: `openssl ... -engine pkcs11`
- Vault: `seal` stanza with `pkcs11` provider, or Vault Enterprise HSM auto-unseal
- Key ceremony: generate key handle, export wrapped key for Shamir split (if policy allows)

### Cloud KMS

| Provider | Service | FIPS Level | Vault Integration |
|----------|---------|------------|-------------------|
| AWS | CloudHSM / KMS | 140-2 L3 / L2 | `awskms` seal, PKI with managed keys |
| Azure | Managed HSM / Key Vault | 140-2 L3 / L2 | `azurekeyvault` seal |
| GCP | Cloud HSM / KMS | 140-2 L3 / L1 | `gcpckms` seal |

Cloud KMS is appropriate for the intermediate CA key (online, in Vault). The root CA key should remain in physical custody via Shamir shares — cloud KMS introduces a dependency on the cloud provider for the trust anchor.

### YubiHSM 2

A cost-effective option for smaller organizations:
- FIPS 140-2 Level 3 validated
- USB form factor — suitable for air-gapped ceremony machines
- Supports RSA 2048/4096, ECDSA P-256/P-384
- `yubihsm-connector` + `yubihsm-shell` for ceremony operations
- Vault integration via PKCS#11 engine

Ceremony adaptation for YubiHSM:
1. Initialize YubiHSM with wrap key
2. Generate root CA key inside YubiHSM
3. Export wrapped key for Shamir split (under wrap key)
4. Store wrap key separately from Shamir shares
5. Sign root certificate using YubiHSM-resident key

---

## 5. Ceremony Cadence and Rotation Schedule

| Event | Frequency | Trigger |
|-------|-----------|---------|
| Root CA generation | Once (initial) | Infrastructure bootstrap |
| Intermediate CA generation | Every 2-3 years | Scheduled rotation |
| Intermediate CA emergency re-issue | As needed | Compromise, Vault loss |
| Share verification | Annual | Compliance, custodian changes |
| Share re-issuance | As needed | Custodian departure, share loss |
| Root CA rotation | 7-10 years | Before root expiry |
| CRL publication | Every 24-72 hours | Automated by Vault |

### Rotation Timeline

```
Year 0:  Root CA ceremony (10-year validity)
         Intermediate CA ceremony (5-year validity)
         Import to Vault

Year 1:  Annual share verification
         CRL rotation (automated)

Year 2:  Annual share verification

Year 3:  Intermediate CA rotation ceremony
         New intermediate signed by existing root
         Transition workloads to new intermediate

Year 5:  Second intermediate rotation

Year 7:  Begin planning root CA rotation
         Cross-signing strategy development

Year 8:  New root CA ceremony
         Cross-sign new root with old root
         Begin distributing new root to trust stores

Year 9:  Complete trust store migration
         Issue intermediates under new root

Year 10: Old root CA expires
         Old intermediates expire naturally
```

---

## 6. Evidence Collection for Compliance

### SOC 2 (Trust Services Criteria)

| SOC 2 Criteria | Ceremony Evidence |
|----------------|------------------|
| CC6.1 — Logical and physical access | Air-gapped machine, secured room, witness log |
| CC6.4 — Access restrictions to assets | Shamir shares in tamper-evident storage, custodian registry |
| CC6.6 — Measures against threats | Key destroyed after ceremony, M-of-N reconstruction |
| CC6.7 — Transmission integrity | SHA-256 hashes of all artifacts in ceremony log |
| CC7.1 — Detection and monitoring | Ceremony JSON log, Vault audit log |

### PCI DSS v4.0

| PCI DSS Requirement | Ceremony Evidence |
|---------------------|------------------|
| 3.6.1 — Strong cryptography | ECDSA P-384 or RSA 4096, SHA-384 signing |
| 3.6.2 — Secret key distribution | Shamir shares to named custodians, tamper-evident envelopes |
| 3.6.3 — Secret key storage | Air-gapped generation, physical share custody |
| 3.6.4 — Key changes/rotation | Documented rotation schedule, intermediate CA rotation |
| 3.6.5 — Key retirement | Secure deletion with overwrite, ceremony log documenting destruction |
| 3.6.6 — Split knowledge | M-of-N Shamir threshold, no single custodian has quorum |
| 3.6.7 — Key substitution prevention | SHA-256 hashes in witnessed ceremony log |
| 3.7 — Documented key management | This guide + ceremony logs + custodian registry |

### ISO 27001 (Annex A)

| Control | Ceremony Evidence |
|---------|------------------|
| A.10.1.1 — Cryptographic controls policy | This architecture document + ceremony runbook |
| A.10.1.2 — Key management | Ceremony procedures, Shamir scheme, rotation schedule |

### Artifact Retention

Retain the following for the lifetime of the CA hierarchy plus the organization's record retention period:

| Artifact | Retention | Storage |
|----------|-----------|---------|
| Ceremony log (text, signed) | Life of root CA + 7 years | Physical secure storage |
| Ceremony log (JSON) | Life of root CA + 7 years | Encrypted digital archive |
| Root CA certificate | Life of root CA | Trust stores, digital archive |
| Shamir shares | Life of root CA | Individual custodian custody |
| Custodian registry | Life of root CA + 7 years | HR/compliance system |
| Witness attestations | Life of root CA + 7 years | Physical secure storage |

---

## 7. Tooling Reference

### Ceremony Scripts

| Script | Purpose |
|--------|---------|
| `tools/ceremony/root_ca_ceremony.sh` | Root CA generation with Shamir split |
| `tools/ceremony/intermediate_ca_ceremony.sh` | Intermediate CA with share reconstruction |
| `tools/ceremony/import_to_vault.sh` | Import ceremony output into Vault PKI |

### Common Flags

All ceremony scripts support:

| Flag | Description |
|------|-------------|
| `--algorithm` | `rsa4096` or `ecdsap384` |
| `--dry-run` | Preview without execution |
| `--no-color` | Plain text output |
| `--help` | Usage information |

### Verification Commands

```bash
# Inspect root CA certificate
openssl x509 -in root-ca.pem -noout -text

# Verify intermediate signed by root
openssl verify -CAfile root-ca.pem intermediate-ca.pem

# Verify chain bundle
openssl verify -CAfile root-ca.pem -untrusted intermediate-ca.pem end-entity.pem

# Check certificate extensions
openssl x509 -in root-ca.pem -noout -text | grep -A2 "Basic Constraints"
openssl x509 -in root-ca.pem -noout -text | grep -A2 "Key Usage"

# Verify Vault PKI
vault read pki/cert/ca
vault read pki_int/cert/ca
```
