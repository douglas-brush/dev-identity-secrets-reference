# NIST Standards Mapping

Maps reference architecture controls to NIST publications.

## NIST SP 800-53 Rev 5 — Security and Privacy Controls

### Access Control (AC) Family

| Control ID | Control Name | Architecture Component | Implementation |
|-----------|-------------|----------------------|----------------|
| AC-1 | Policy and Procedures | docs/06-controls-and-guardrails.md | Documented control objectives C1-C6 |
| AC-2 | Account Management | Identity Plane | Centralized IdP, group-based access, automated provisioning/deprovisioning |
| AC-2(1) | Automated Account Management | Vault OIDC + IdP | Automated role mapping from IdP groups to Vault policies |
| AC-2(3) | Disable Accounts | IdP + Vault | Central revocation; Vault token TTL auto-expiry |
| AC-3 | Access Enforcement | Vault policies, K8s RBAC | Least-privilege policies per workload, namespace isolation |
| AC-4 | Information Flow Enforcement | Network policies, Vault paths | Kubernetes network policies, Vault path-based ACLs |
| AC-5 | Separation of Duties | Environment separation | Separate dev/staging/prod trust domains, KMS keys, and policies |
| AC-6 | Least Privilege | All policies | One SA per app, scoped Vault policies, environment-bound roles |
| AC-6(1) | Authorize Access to Security Functions | PIM/PAM | Privileged role gating for administrative access |
| AC-6(5) | Privileged Accounts | SSH CA, break-glass | Short-lived SSH certs, dual-control break-glass |
| AC-6(9) | Log Use of Privileged Functions | Vault audit, cloud audit | Every credential request logged with identity and timestamp |
| AC-6(10) | Prohibit Non-Privileged Users from Executing Privileged Functions | Vault policy enforcement | Role-based policy boundaries |
| AC-10 | Concurrent Session Control | Vault token limits | Token use-count and TTL limits |
| AC-12 | Session Termination | Token TTL | Short-lived tokens with automatic expiry |
| AC-17 | Remote Access | SSH CA, VPN certs | Certificate-based remote access, no static SSH keys |
| AC-17(1) | Monitoring and Control | Vault audit log | All remote access credential issuance logged |
| AC-17(2) | Protection of Confidentiality and Integrity Using Encryption | Transit, TLS, SOPS | Encryption in transit and at rest for all credential flows |

### Identification and Authentication (IA) Family

| Control ID | Control Name | Architecture Component | Implementation |
|-----------|-------------|----------------------|----------------|
| IA-1 | Policy and Procedures | Architecture docs | Identity plane design and credential taxonomy |
| IA-2 | Identification and Authentication (Organizational Users) | IdP + OIDC | SSO with phishing-resistant MFA |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | Hardware MFA | Passkeys/FIDO2 for high-value actions |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | IdP MFA | Organization-wide MFA enforcement |
| IA-2(6) | Access to Accounts — Separate Device | Hardware tokens | Physical security keys for privileged access |
| IA-3 | Device Identification and Authentication | MDM/Intune | Device posture and compliance check before credential issuance |
| IA-4 | Identifier Management | IdP | Centralized identity lifecycle management |
| IA-5 | Authenticator Management | Vault, KMS | Dynamic credential issuance, automatic rotation, TTL enforcement |
| IA-5(1) | Password-Based Authentication | Vault dynamic creds | Dynamic database credentials eliminate static passwords |
| IA-5(2) | PKI-Based Authentication | cert-manager, Vault PKI | Certificate-based workload identity with lifecycle control |
| IA-5(7) | No Embedded Unencrypted Static Authenticators | SOPS, pre-commit | SOPS encryption + pre-commit scanning prevents plaintext secrets |
| IA-8 | Identification and Authentication (Non-Organizational Users) | OIDC federation | GitHub OIDC for CI, Kubernetes SA for workloads |
| IA-9 | Service Identification and Authentication | Workload identity | Per-service accounts, mTLS certificates, SPIFFE IDs |

### System and Communications Protection (SC) Family

| Control ID | Control Name | Architecture Component | Implementation |
|-----------|-------------|----------------------|----------------|
| SC-4 | Information in Shared Resources | Namespace isolation | Separate namespaces, secret stores, and policies per environment |
| SC-8 | Transmission Confidentiality and Integrity | TLS, mTLS | All credential delivery over encrypted channels |
| SC-8(1) | Cryptographic Protection | TLS 1.2+ | Mandatory TLS for Vault, cloud KMS, and all API calls |
| SC-12 | Cryptographic Key Establishment and Management | KMS, Vault Transit | Cloud KMS for master keys, Vault Transit for app-level crypto |
| SC-12(1) | Availability | Key rotation, break-glass | Tested break-glass procedure, key rotation without downtime |
| SC-13 | Cryptographic Protection | SOPS, KMS, Vault | Industry-standard algorithms via cloud KMS and Vault |
| SC-17 | PKI Certificates | cert-manager, Vault PKI | Automated certificate lifecycle with policy constraints |
| SC-28 | Protection of Information at Rest | SOPS, KMS encryption | All secrets encrypted at rest in Git and secret stores |
| SC-28(1) | Cryptographic Protection | Cloud KMS, age | Hardware-backed or managed encryption keys |

### Audit and Accountability (AU) Family

| Control ID | Control Name | Architecture Component | Implementation |
|-----------|-------------|----------------------|----------------|
| AU-2 | Event Logging | Vault audit, cloud audit | All credential operations generate audit events |
| AU-3 | Content of Audit Records | Vault audit log | Who, what, when, where, result for every secret access |
| AU-6 | Audit Record Review, Analysis, and Reporting | Audit tools | Credential age reports, access pattern analysis |
| AU-9 | Protection of Audit Information | Immutable audit logs | Write-once audit backends, separated from secret stores |
| AU-10 | Non-Repudiation | IdP-bound tokens | Every credential request tied to authenticated identity |
| AU-12 | Audit Record Generation | All components | End-to-end audit trail from identity through delivery |

## NIST SP 800-57 — Key Management Recommendations

| Recommendation | Architecture Implementation |
|---------------|---------------------------|
| Key hierarchy with separation of duties | Cloud KMS master keys -> Vault transit keys -> per-app keys |
| Key lifecycle management | Automated rotation via Vault/KMS, TTL-based expiry |
| Key usage period limits | Short-lived credentials (minutes to hours) |
| Key compromise recovery | Break-glass procedures, key rotation scripts |
| Cryptoperiod enforcement | TTL on dynamic creds, renewBefore on certificates |
| Key storage protection | HSM-backed KMS, no plaintext key storage |
| Key distribution | Secure delivery via OIDC, CSI, ESO — never plaintext |
| Key destruction | Automatic lease revocation, certificate CRL |

## NIST SP 800-63B — Digital Identity Guidelines

| Guideline | Architecture Implementation |
|-----------|---------------------------|
| AAL2: Multi-factor authentication | IdP with MFA enforcement |
| AAL3: Hardware-backed authentication | Passkeys/FIDO2 for privileged operations |
| Phishing resistance | FIDO2/WebAuthn for high-value actions |
| Session management | Short-lived tokens with explicit TTL |
| Reauthentication | Token refresh via OIDC, PIM time-boxing |

## NIST SP 800-204 / 204A — Microservices Security

| Recommendation | Architecture Implementation |
|---------------|---------------------------|
| Service identity | Per-service accounts, SPIFFE IDs, mTLS certs |
| Service-to-service authentication | cert-manager issued mTLS, Vault-signed certificates |
| Secret management for microservices | External Secrets Operator, CSI driver, Vault Agent |
| API gateway security | OIDC token validation, short-lived access tokens |
| Service mesh integration | Future: SPIFFE/SPIRE + service mesh mTLS |

## NIST Cybersecurity Framework 2.0

| Function | Category | Architecture Mapping |
|----------|----------|---------------------|
| **GOVERN** | GV.OC | Organizational context documented in architecture docs |
| **GOVERN** | GV.RM | Risk management via threat model and decision log |
| **GOVERN** | GV.SC | Supply chain risk via OIDC federation and signed artifacts (future) |
| **IDENTIFY** | ID.AM | Asset management: credential inventory, secret stores |
| **IDENTIFY** | ID.RA | Risk assessment: threat model with 7 threat scenarios |
| **PROTECT** | PR.AA | Identity management and access control: full identity plane |
| **PROTECT** | PR.DS | Data security: SOPS encryption, KMS, Transit |
| **PROTECT** | PR.PS | Platform security: namespace isolation, network policies |
| **PROTECT** | PR.IR | Infrastructure resilience: HA Vault, break-glass |
| **DETECT** | DE.CM | Continuous monitoring: Vault audit, secret scanning |
| **DETECT** | DE.AE | Adverse event analysis: credential age reports, anomaly detection |
| **RESPOND** | RS.MA | Incident management: secret exposure response runbook |
| **RESPOND** | RS.AN | Incident analysis: audit trail review procedures |
| **RECOVER** | RC.RP | Recovery planning: break-glass procedures, key rotation |

## NIST SP 800-152 — Key Management in Cloud

| Recommendation | Architecture Implementation |
|---------------|---------------------------|
| Cloud KMS for key protection | AWS KMS / Azure Key Vault / GCP Cloud KMS as master authorities |
| Key isolation per tenant/environment | Separate KMS keys per dev/staging/prod |
| Cloud-managed HSM for high-value keys | Azure Managed HSM / AWS CloudHSM options documented |
| Key access logging | Cloud KMS audit logs integrated with SIEM |
| Key import for BYOK scenarios | SOPS break-glass age keys, Vault Transit key import |
