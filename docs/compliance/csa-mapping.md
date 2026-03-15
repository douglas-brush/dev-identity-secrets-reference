# Cloud Security Alliance (CSA) Mapping

Maps reference architecture controls to CSA Cloud Controls Matrix (CCM) v4 and related CSA publications.

## CSA Cloud Controls Matrix (CCM) v4

### Identity & Access Management (IAM)

| Control ID | Control | Architecture Implementation |
|-----------|---------|---------------------------|
| IAM-01 | Identity and Access Management Policy and Procedures | Documented identity plane, credential taxonomy, control objectives |
| IAM-02 | Strong/Multi-Factor Authentication | IdP with phishing-resistant MFA, FIDO2 for privileged access |
| IAM-03 | Identity Inventory | Centralized IdP as identity source of truth |
| IAM-04 | Separation of Duties | Separate dev/staging/prod domains, dual-control break-glass |
| IAM-05 | Least Privilege | Per-workload Vault policies, scoped service accounts |
| IAM-06 | User Access Provisioning | Automated provisioning via IdP group mapping to Vault roles |
| IAM-07 | User Access Changes and Revocation | Central IdP revocation, Vault token expiry |
| IAM-08 | User Access Review | Credential age reports, stale access detection |
| IAM-09 | Segregation of Privileged Access Rights | PIM/PAM gating, SSH CA for admin access |
| IAM-10 | Management of Privileged Access Rights | Short-lived SSH certs, break-glass with dual control |
| IAM-12 | User ID Credentials | Dynamic credentials, no shared accounts |
| IAM-13 | Uniqueness of User ID Credentials | Per-identity Vault tokens, per-workload service accounts |
| IAM-14 | Strong Authentication | OIDC/SSO with MFA, certificate-based workload auth |
| IAM-15 | Passwords/Passphrases Policy | Dynamic credentials eliminate static passwords where possible |
| IAM-16 | Authorization Mechanisms | Vault policy evaluation, OIDC claim validation |

### Cryptography, Encryption & Key Management (CEK)

| Control ID | Control | Architecture Implementation |
|-----------|---------|---------------------------|
| CEK-01 | Encryption and Key Management Policy | Key management model documented, KMS selection guidance |
| CEK-02 | CEK Roles and Responsibilities | Key ownership: platform team (KMS), app team (app-level) |
| CEK-03 | Data Encryption | SOPS for data at rest, TLS for transit, Vault seal |
| CEK-04 | Encryption Algorithm | AES-256 via cloud KMS, RSA-2048+ for PKI |
| CEK-05 | Encryption Change Management | Key rotation procedures, SOPS re-encryption scripts |
| CEK-06 | Encryption Risk Management | Threat model addresses crypto failures |
| CEK-07 | Key Generation | Cloud KMS or HSM-backed key generation |
| CEK-08 | Key Rotation | Automated via Vault TTL, SOPS rotation script |
| CEK-09 | Key Storage | Cloud KMS/HSM, no plaintext key storage |
| CEK-10 | Key Revocation | Vault token/lease revocation, certificate CRL |
| CEK-11 | Key Destruction | KMS key scheduling, lease expiry |
| CEK-14 | Key Compromise | Secret exposure response runbook, rotation procedures |
| CEK-15 | Key Recovery | Break-glass age key in escrow, KMS key policies |
| CEK-16 | Key Inventory | KMS key registry, Vault engine listing, SOPS recipients |
| CEK-17 | Key Purpose | Separate keys per purpose (encryption, signing, PKI, SOPS) |
| CEK-18 | Cryptography and Key Management Audit | Cloud KMS audit logs, Vault audit backend |
| CEK-19 | Key Management Lifecycle | TTL-based lifecycle, automated renewal |
| CEK-20 | Approved Cloud Resources | Documented cloud KMS and secret manager choices |
| CEK-21 | Hardware-Backed Key Storage | Cloud HSM options documented for high-value keys |

### DevSecOps (DSP)

| Control ID | Control | Architecture Implementation |
|-----------|---------|---------------------------|
| DSP-01 | Security in Design | Three-plane security architecture |
| DSP-03 | Secure Development | Pre-commit hooks, no hardcoded secrets |
| DSP-04 | Automated Secure Application Design Testing | CI secret scanning, OPA policy tests |
| DSP-05 | Automated Secure Application Deployment | OIDC CI federation, automated secret delivery |
| DSP-07 | Secure Application Configuration | SOPS-encrypted configs, environment separation |
| DSP-10 | API Security | Vault API with authentication, short-lived tokens |

### Data Security & Privacy (DSI)

| Control ID | Control | Architecture Implementation |
|-----------|---------|---------------------------|
| DSI-01 | Data Security and Privacy Policy | No plaintext secrets, encrypted storage |
| DSI-02 | Data Inventory | Credential taxonomy with 7 classes |
| DSI-04 | Data Classification | Credential classes by sensitivity and lifetime |
| DSI-05 | Data Flow Documentation | Architecture diagrams showing credential flows |
| DSI-06 | Ownership and Stewardship | Per-credential ownership model |
| DSI-07 | Data Protection by Design | Encryption by default, short-lived by design |

### Infrastructure & Virtualization (IVS)

| Control ID | Control | Architecture Implementation |
|-----------|---------|---------------------------|
| IVS-03 | Network Security | K8s network policies for secret store access |
| IVS-04 | Segmentation and Segregation | Namespace isolation, environment separation |
| IVS-09 | Logging and Monitoring | Vault audit, cloud audit, credential reporting |

## CSA Top Threats — Credential-Related

| Threat | Architecture Mitigation |
|--------|------------------------|
| **Insufficient Identity, Credential, Access and Key Management** | Complete identity plane + credential lifecycle management |
| **Insecure Interfaces and APIs** | Vault policy enforcement, OIDC authentication, no static keys |
| **Account Hijacking** | Phishing-resistant MFA, short-lived sessions, central revocation |
| **Malicious Insiders** | Audit logging, least privilege, dual-control for sensitive ops |
| **Data Loss** | Encryption at rest (SOPS), encryption in transit (TLS), access controls |

## CSA STAR Certification Requirements

| Requirement Area | Architecture Coverage |
|-----------------|---------------------|
| Key management procedures | Documented KMS strategy, rotation procedures, break-glass |
| Encryption standards | AES-256, RSA-2048+, cloud KMS compliance (FIPS 140-2 Level 3) |
| Access control mechanisms | Vault RBAC, OIDC, least privilege, namespace isolation |
| Audit and monitoring | Vault audit, KMS audit, credential age reports |
| Incident response | Secret exposure response runbook |
| Compliance validation | OPA policies, compliance check scripts |
