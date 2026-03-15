# Reference Architecture

## Executive summary

The recommended model for dev and platform security is a **brokered trust architecture**:

1. **Human identity** starts at the IdP.
2. **Device trust** is reinforced by MDM and posture.
3. **Central secret and credential brokerage** is handled by Vault and/or cloud secret services.
4. **Master cryptographic authority** is handled by cloud KMS / Key Vault / Cloud KMS and, where needed, HSM-backed services.
5. **Certificate issuance** is centralized through a private PKI workflow.
6. **Runtime delivery** uses purpose-specific patterns:
   - SOPS for Git-stored configuration secrets
   - OIDC federation for CI
   - External Secrets or CSI for Kubernetes
   - Vault Agent or cloud-native identity for VMs
   - short-lived SSH certificates or brokered admin access for human operations

## Architecture planes

### 1. Identity plane

The identity plane answers: **who is asking, from what device, with what posture, and with what role?**

Components:
- IdP (Entra ID / Okta / equivalent)
- MDM (Intune or equivalent)
- PIM/PAM or privileged role gating
- hardware-backed MFA / passkeys for high-value actions

### 2. Crypto and secrets plane

The crypto and secrets plane answers: **what secret, credential, key, or certificate exists, who may use it, and for how long?**

Components:
- Vault and/or cloud secret manager
- cloud KMS / Azure Key Vault / Google Cloud KMS
- SOPS for repository encryption
- PKI provider / certificate authority
- optional Transit / encryption-as-a-service

### 3. Runtime delivery plane

The runtime delivery plane answers: **how does a workload or tool receive what it needs at the time it needs it, without turning credentials into durable artifacts?**

Components:
- GitHub OIDC or equivalent
- External Secrets Operator
- Secrets Store CSI Driver
- cert-manager and cert-manager CSI driver
- Vault Agent
- SSH CA / access broker
- cloud-native control-plane access for admin sessions

## Credential classes

### Human credentials
- IdP sessions
- admin elevation grants
- short-lived SSH credentials
- workstation-generated ephemeral tokens

### Service credentials
- database usernames/passwords with TTL
- short-lived cloud access
- API tokens with limited scope and lifetime
- workload certificates for mTLS

### Key material
- KMS master keys
- Vault transit keys
- private CA keys
- break-glass recipients and recovery artifacts

### Repository encryption
- SOPS-encrypted YAML files
- environment-scoped keys
- per-environment policies and recipient separation

## Architecture decisions that matter

### Decision 1: source of truth for runtime secrets
Choose one:
- Vault is authoritative
- cloud native secret service is authoritative
- hybrid model where Vault brokers dynamic secrets and cloud secret service stores static unavoidable secrets

### Decision 2: Kubernetes delivery method
Choose by use case:
- **External Secrets** when the application expects Kubernetes Secrets and operational convenience matters
- **Secrets Store CSI** when direct mount to filesystem is preferable and you want to reduce Secret object proliferation
- **Vault Agent** when sidecar templating and lease renewal is the better model
- **cert-manager CSI** for ephemeral pod certificate/key pairs

### Decision 3: developer auth and local secret retrieval
Choose one or combine:
- direct OIDC into Vault
- cloud SSO plus short-lived token exchange
- brokered dev bootstrap script that obtains a scoped token and only then decrypts or fetches local secrets

### Decision 4: endpoint certificates in Microsoft-heavy environments
Choose one:
- Intune Cloud PKI root/issuing hierarchy
- Intune Cloud PKI in BYOCA mode anchored to your private CA
- separate enterprise private CA with Intune only as enrollment/distribution plane

## Recommended opinionated pattern

For most hybrid organizations, the strongest pattern is:

- **Entra/Okta** for human identity
- **Intune** for device management if using Microsoft endpoints
- **Vault** as central broker for dynamic credentials, SSH, Transit, and optionally PKI
- **Cloud KMS / Key Vault / Cloud KMS** as master key authorities and SOPS recipients
- **GitHub OIDC** for CI federation
- **External Secrets + CSI** in Kubernetes depending on sensitivity and application design
- **cert-manager** for certificates inside clusters
- **Private CA provider** for organizational certificate hierarchy

## Core non-negotiables

- no static cloud credentials in CI
- no plaintext secrets in Git
- no shared admin SSH private keys as the primary model
- no unbounded service account access
- no single CA trusted to sign everything everywhere
- no break-glass process that has never been tested
