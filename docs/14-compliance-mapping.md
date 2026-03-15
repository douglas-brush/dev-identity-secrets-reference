# Compliance and Standards Mapping

This document maps the reference architecture's controls, patterns, and design decisions to major security frameworks and standards. Each section identifies specific control IDs, their relevance to developer identity and secrets management, what this architecture satisfies, and where gaps may exist.

---

## 1. NIST SP 800-53 Rev 5

NIST SP 800-53 Rev 5 provides the most granular control catalog relevant to secrets and credential management. The following controls map directly to this architecture's scope.

### Identification and Authentication (IA) Family

| Control ID | Title | Secrets Management Relevance | Architecture Coverage | Gaps |
|---|---|---|---|---|
| IA-2 | Identification and Authentication (Organizational Users) | Requires unique identification and authentication for all organizational users accessing systems | Identity plane: IdP (Entra/Okta) with SSO, phishing-resistant MFA, hardware-backed passkeys (C5, C6) | None for covered scope; PAM integration depth depends on implementation |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | MFA required for all privileged access | PIM/PAM gating, hardware MFA for high-value actions, conditional access policies | Depends on IdP configuration completeness |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | MFA for standard accounts | IdP-enforced MFA across all developer access | None |
| IA-3 | Device Identification and Authentication | Devices must be identified and authenticated before connection | MDM (Intune) device posture checks, managed device preference, device trust as part of identity plane | BYOD scenarios may need additional controls |
| IA-4 | Identifier Management | Manage identifiers for users and devices throughout lifecycle | IdP-managed identities, one service account per workload (C3), clear ownership per automation identity (Rule 3) | Non-human identity inventory tooling not prescribed |
| IA-5 | Authenticator Management | Lifecycle management of all authenticators (passwords, keys, tokens, certificates) | Short-lived credentials by default, OIDC federation (C2), SSH CA certificates (C5), dynamic database credentials, TTL/renewal models (Rule 3) | Legacy static secret exceptions acknowledged in threat model |
| IA-5(2) | Public Key-Based Authentication | PKI-based authentication requirements | cert-manager for workload certificates, SSH CA, SPIFFE/SPIRE for workload identity, mTLS | None |
| IA-5(7) | No Embedded Unencrypted Static Authenticators | Prohibits embedding unencrypted static authenticators in applications or scripts | SOPS encryption (C1), pre-commit hooks, repo scanning, merge blocking, guardrail Rule 1 | Requires enforcement at developer workflow level |
| IA-9 | Service Identification and Authentication | Services must identify and authenticate before connection | Kubernetes service accounts, OIDC federation, Vault auth methods (K8s auth, JWT/OIDC), workload identity | None |

### Access Control (AC) Family

| Control ID | Title | Secrets Management Relevance | Architecture Coverage | Gaps |
|---|---|---|---|---|
| AC-2 | Account Management | Manage system accounts including creation, modification, disabling, and removal | Service account lifecycle (Rule 3): clear owner, defined purpose, TTL/renewal, rotation/revocation path; developer onboarding runbook | Automated deprovisioning depends on IdP integration |
| AC-3 | Access Enforcement | Enforce approved authorizations for access to resources | Vault policies (least privilege), per-environment separation (Rule 2), namespace isolation, role-scoped access | Policy enforcement depends on Vault policy completeness |
| AC-6 | Least Privilege | Employ principle of least privilege | C3 (workloads get only needed secrets), one SA per workload, separate stores/roles per environment, avoid wildcard access | Ongoing review process not automated in architecture |
| AC-6(1) | Authorize Access to Security Functions | Restrict access to security functions to authorized personnel | Vault admin policies, break-glass dual control (C6), PIM/PAM gating | None |
| AC-6(5) | Privileged Accounts | Restrict privileged accounts to specific personnel/roles | PIM/PAM, admin elevation grants, time-bounded admin access (Rule 4) | None |
| AC-6(9) | Log Use of Privileged Functions | Audit all use of privileged functions | Vault audit logs, break-glass logging (C6), attributable admin paths (Rule 4) | Centralized SIEM integration not prescribed |
| AC-6(10) | Prohibit Non-Privileged Users from Executing Privileged Functions | Prevent non-privileged users from executing privileged functions | Vault policy enforcement, RBAC, namespace-scoped roles | None |
| AC-17 | Remote Access | Manage and control remote access | SSH CA/broker (C5), control-plane alternatives, short-lived access, VPN/zero-trust network access | Network-level controls out of scope |

### System and Communications Protection (SC) Family

| Control ID | Title | Secrets Management Relevance | Architecture Coverage | Gaps |
|---|---|---|---|---|
| SC-4 | Information in Shared Resources | Prevent unauthorized information transfer via shared resources | Per-environment separation (Rule 2), namespace isolation, separate KMS keys per environment | Container isolation limits acknowledged in threat model |
| SC-8 | Transmission Confidentiality and Integrity | Protect information during transmission | mTLS via service mesh/SPIFFE, TLS certificates via cert-manager, encrypted API communications | None |
| SC-12 | Cryptographic Key Establishment and Management | Establish and manage cryptographic keys | Cloud KMS as master key authority, Vault transit engine, SOPS with KMS recipients, key hierarchy (master > intermediate > workload) | HSM backing optional, not mandatory |
| SC-12(1) | Availability | Ensure availability of cryptographic keys | Break-glass procedures (C6), key recovery, dual-control custody, age recipients for emergency access | Requires quarterly drill execution |
| SC-13 | Cryptographic Protection | Implement cryptographic mechanisms | SOPS encryption, Vault transit, TLS everywhere, KMS-backed encryption | FIPS 140-2 validation depends on provider configuration |
| SC-17 | Public Key Infrastructure Certificates | Issue, manage, and verify PKI certificates | cert-manager, Vault PKI engine, CA/intermediate separation (C4), policy-restricted issuance, lifecycle monitoring | None |
| SC-28 | Protection of Information at Rest | Protect information at rest | SOPS-encrypted secrets in Git, Vault encrypted storage, KMS-encrypted cloud secrets, etcd encryption for K8s secrets | None |
| SC-28(1) | Cryptographic Protection (at rest) | Use cryptographic mechanisms for information at rest | SOPS + KMS, Vault seal/unseal, cloud-native encryption | None |

### Audit and Accountability (AU) Family

| Control ID | Title | Secrets Management Relevance | Architecture Coverage | Gaps |
|---|---|---|---|---|
| AU-2 | Event Logging | Identify events that need to be logged | Vault audit logging, break-glass evidence capture, admin access logging (Rule 4), CI pipeline audit trails | Centralized log aggregation architecture not prescribed |
| AU-3 | Content of Audit Records | Define required audit record content | Vault audit logs include timestamp, identity, path, operation; break-glass logs include operator, action, evidence | Log format standardization not specified |
| AU-6 | Audit Record Review, Analysis, and Reporting | Review and analyze audit records | Reviewable admin paths (Rule 4), periodic stale-access review (C5), quarterly drills (C6) | Automated alerting on anomalous secret access not prescribed |
| AU-12 | Audit Record Generation | Generate audit records for defined events | Vault audit backend, Git commit history for SOPS changes, CI workflow logs | None |

---

## 2. NIST SP 800-204 Series (Microservices Security)

| Document | Relevance | Architecture Coverage | Gaps |
|---|---|---|---|
| SP 800-204 | Security strategies for microservices: authentication, access management, service discovery, secure communications | Service mesh patterns, workload identity (SPIFFE/SPIRE), mTLS, API-based secret delivery | Service mesh implementation details deferred to adopter |
| SP 800-204A | Service mesh as security kernel: Kubernetes + Istio reference platform | Kubernetes-native delivery (External Secrets, CSI, cert-manager CSI), workload certificates for mTLS | Specific service mesh product choice left to implementer |
| SP 800-204B | Attribute-based access control (ABAC) for microservices | Vault policy-based access, per-namespace/per-environment role separation | ABAC granularity depends on Vault policy design |
| SP 800-204C | DevSecOps for microservices with service mesh | OIDC federation for CI (C2), pre-commit scanning, SOPS guardrails, GitOps-compatible secret delivery | Full C-ATO pipeline not prescribed |

---

## 3. NIST SP 800-63B-4 (Digital Identity Guidelines)

| Requirement Area | Relevance | Architecture Coverage | Gaps |
|---|---|---|---|
| Authenticator Assurance Level 1 (AAL1) | Single-factor authentication | IdP with password + MFA exceeds AAL1 | None (architecture exceeds) |
| Authenticator Assurance Level 2 (AAL2) | MFA with approved authenticators | Phishing-resistant MFA, hardware-backed passkeys | None |
| Authenticator Assurance Level 3 (AAL3) | Hardware-based authentication | Hardware tokens, passkeys for high-value actions | Full AAL3 depends on hardware token deployment breadth |
| Authenticator Lifecycle | Binding, loss, recovery, revocation | Developer onboarding runbook, SSH CA revocation, break-glass recovery procedures | Automated authenticator binding lifecycle not fully prescribed |
| Credential Service Provider Requirements | Credential issuance and management | IdP as credential authority, Vault as machine credential authority | None |

---

## 4. NIST SP 800-57 (Key Management)

| Requirement Area | Relevance | Architecture Coverage | Gaps |
|---|---|---|---|
| Key Generation | Use approved algorithms and adequate key lengths | Cloud KMS key generation, Vault auto-generated keys, cert-manager key generation | Algorithm selection deferred to provider defaults |
| Key Storage | Protect keys at rest with access controls | KMS-backed storage, Vault sealed storage, SOPS key separation (keys separate from encrypted data) | HSM backing optional |
| Key Distribution | Secure distribution of keys | OIDC token exchange, Vault dynamic credential delivery, External Secrets sync, CSI mount | None |
| Key Usage | Enforce appropriate use of keys | Vault policies restrict key operations, transit engine for encryption-as-a-service, PKI role restrictions | None |
| Key Rotation | Periodic key rotation | TTL-based credential rotation, Vault lease renewal, cert-manager auto-renewal, rotation runbooks | Automated master key rotation cadence not specified |
| Key Revocation and Destruction | Revoke and destroy compromised keys | Secret exposure response runbook, SSH CA revocation, certificate revocation, break-glass rotation after use | CRL/OCSP infrastructure details not prescribed |
| Key Archival and Recovery | Archive and recover keys when needed | Break-glass procedures (C6), dual-control custody, age recipients for emergency access | Archive retention policy not specified |

---

## 5. NIST SP 800-152 (Federal CKMS Profile)

| Requirement Area | Relevance | Architecture Coverage | Gaps |
|---|---|---|---|
| CKMS Design | Design requirements for key management systems | Three-plane architecture (identity, crypto, runtime delivery), separation of concerns | Formal CKMS design document not produced |
| CKMS Procurement | Procurement requirements for CKMS components | Vendor-neutral architecture supporting Vault, cloud KMS, cert-manager | Procurement guidance is out of scope |
| Key Management Operations | Operational procedures for key lifecycle | Runbooks for onboarding, rotation, revocation, break-glass recovery | Operations depend on organizational procedures |
| CKMS Security Plan | Security plan requirements | Threat model (T1-T7), controls (C1-C6), guardrail rules | Formal security plan document is a gap |

---

## 6. NIST Cybersecurity Framework 2.0

| Function | Category | Subcategory | Architecture Coverage | Gaps |
|---|---|---|---|---|
| **Govern (GV)** | GV.OC | Organizational context for cybersecurity | Scope and purpose doc, design intent, architecture decisions | Formal governance policy not produced |
| **Govern (GV)** | GV.RM | Risk management strategy | Threat model (T1-T7), control objectives (C1-C6) | Formal risk register not produced |
| **Identify (ID)** | ID.AM | Asset management | Credential classes defined (human, service, key material, repo encryption), inventory of secret types | Non-human identity discovery tooling not prescribed |
| **Protect (PR)** | PR.AA | Identity management, authentication, access control | IdP + MFA, Vault RBAC, OIDC federation, least privilege policies, per-environment separation | None |
| **Protect (PR)** | PR.DS | Data security | SOPS encryption at rest, KMS protection, transit encryption, mTLS | None |
| **Protect (PR)** | PR.PS | Platform security | Kubernetes security patterns (CSI, External Secrets, pod security), pre-commit hooks, merge blocking | None |
| **Detect (DE)** | DE.CM | Continuous monitoring | Vault audit logs, repo scanning, lifecycle monitoring (C4), stale-access review | Automated anomaly detection not prescribed |
| **Detect (DE)** | DE.AE | Adverse event analysis | Secret exposure response runbook, access history audit | SIEM integration not prescribed |
| **Respond (RS)** | RS.AN | Incident analysis | Secret exposure response runbook with root cause analysis | None |
| **Respond (RS)** | RS.MI | Incident mitigation | Immediate revocation/rotation, distribution surface identification, guardrail gap remediation | None |
| **Recover (RC)** | RC.RP | Recovery planning | Break-glass procedures (C6), admin access recovery runbook, dual-control custody | None |

---

## 7. ISO 27001:2022 Annex A Controls

| Control ID | Title | Secrets Management Relevance | Architecture Coverage | Gaps |
|---|---|---|---|---|
| A.5.1 | Policies for information security | Overarching security policy framework | Controls document (C1-C6), guardrail rules, architecture decisions | Formal ISMS policy document not produced |
| A.5.9 | Inventory of information and other associated assets | Inventory of assets including credentials | Credential classes defined, secret path organization by environment | Automated credential inventory not prescribed |
| A.5.10 | Acceptable use of information and other associated assets | Rules for acceptable use of credentials | Guardrail rules (1-4), pre-commit hooks, developer onboarding | None |
| A.5.15 | Access control | Access control policy and implementation | Vault RBAC, least privilege (C3), per-environment separation (Rule 2) | None |
| A.5.16 | Identity management | Lifecycle management of identities | IdP-managed identities, service account lifecycle (Rule 3) | None |
| A.5.17 | Authentication information | Control allocation and management of authentication information (secrets) | Short-lived credentials, OIDC federation, SSH CA, dynamic DB credentials, no plaintext in Git | None |
| A.5.18 | Access rights | Provision, review, and revoke access rights | Vault policy management, periodic stale-access review (C5), environment-scoped roles | Automated access review not prescribed |
| A.5.23 | Information security for use of cloud services | Security controls for cloud service usage | Cloud KMS integration, OIDC federation to cloud providers, cloud-native secret services | None |
| A.5.33 | Protection of records | Protect records from loss, destruction, falsification | Vault audit logs, Git history for SOPS changes, break-glass evidence capture | Log integrity protection not specified |
| A.6.1 | Screening | Background verification of personnel | Out of scope | HR process dependency |
| A.7.10 | Storage media | Secure management of storage media | SOPS encryption for secrets in repos, KMS-backed storage | Media destruction procedures out of scope |
| A.8.2 | Privileged access rights | Restrict and manage privileged access | PIM/PAM, admin elevation grants, time-bounded access (Rule 4), dual-control break-glass | None |
| A.8.3 | Information access restriction | Restrict access to information per policy | Vault path-based policies, namespace isolation, per-environment separation | None |
| A.8.4 | Access to source code | Restrict access to source code | Git repository access controls, branch protection, merge blocking | Repository access management deferred to Git platform |
| A.8.5 | Secure authentication | Implement secure authentication mechanisms | SSO + phishing-resistant MFA, OIDC, hardware tokens, conditional access | None |
| A.8.9 | Configuration management | Manage configurations securely | SOPS for config secrets, GitOps patterns, `.sops.yaml` per environment | None |
| A.8.24 | Use of cryptography | Establish cryptography policy and key management | Cloud KMS, Vault transit, SOPS, cert-manager, CA hierarchy, key separation | Formal cryptography policy document not produced |
| A.8.25 | Secure development lifecycle | Security in development lifecycle | Pre-commit hooks, repo scanning, OIDC CI federation, SOPS guardrails | None |

---

## 8. ISO 27002:2022 Implementation Guidance

| Control | Implementation Guidance Area | Architecture Coverage | Gaps |
|---|---|---|---|
| 8.24 | Cryptography policy establishment | Architecture prescribes KMS hierarchy, SOPS patterns, Vault transit | Formal written policy needed for certification |
| 8.24 | Key generation procedures | Cloud KMS and Vault handle generation with approved algorithms | None |
| 8.24 | Key storage and protection | Keys stored in KMS/Vault, separated from encrypted data, SOPS keys separate from encrypted files | None |
| 8.24 | Key distribution mechanisms | OIDC token exchange, Vault dynamic delivery, External Secrets sync | None |
| 8.24 | Key backup and recovery | Break-glass procedures, dual-control custody, age recipients | Backup testing cadence not specified |
| 8.24 | Key disposal | Revocation runbooks, rotation after break-glass use | Cryptographic erasure procedures not detailed |
| 5.17 | Authentication information lifecycle | Full lifecycle: issuance, use, rotation, revocation via Vault + IdP | None |

---

## 9. ISO 27017 (Cloud Security)

| Guidance Area | Relevance | Architecture Coverage | Gaps |
|---|---|---|---|
| CLD.8.1 | Shared responsibility for cloud security | Architecture supports multi-cloud (AWS, Azure, GCP) with provider-agnostic patterns | Formal RACI matrix between CSP and customer not produced |
| CLD.9.5 | Virtual computing environment | Kubernetes security patterns, pod security, namespace isolation | None |
| 10.1.1 | Cryptographic controls for cloud | Cloud KMS integration, SOPS with cloud key recipients, Vault with cloud auth | None |
| 10.1.2 | Key management in cloud environments | Cloud KMS as master authority, Vault as broker, per-environment key separation | None |
| 9.2.1 | User registration and de-registration for cloud | Developer onboarding/offboarding runbooks, IdP lifecycle | Automated offboarding not prescribed |
| 12.4.1 | Event logging for cloud services | Vault audit logs, cloud provider audit trails | Cloud-specific log aggregation depends on implementation |
| Authentication information management | Provider guidance on secret authentication information handling | Dynamic credentials, short-lived tokens, no static cloud credentials in CI | None |

---

## 10. ISO 27018 (PII in Cloud)

| Control Area | Relevance | Architecture Coverage | Gaps |
|---|---|---|---|
| A.10.1 | Cryptographic protection of PII | SOPS encryption, KMS-backed storage protects any PII-containing configuration | None for secrets-layer scope |
| A.9.1 | Access control for PII | Vault RBAC, least privilege, per-environment isolation | None |
| A.11.1 | Consent-driven data handling | Out of primary scope (secrets architecture, not application logic) | Application-layer PII handling out of scope |

---

## 11. OWASP Secrets Management Cheat Sheet

| Recommendation | Architecture Coverage | Gaps |
|---|---|---|
| Centralize secrets management | Vault and/or cloud secret manager as central source of truth (Decision 1) | None |
| Apply least privilege to secret access | C3, one SA per workload, scoped Vault policies, avoid wildcards | None |
| Automate secret rotation | TTL-based credentials, Vault dynamic secrets, cert-manager auto-renewal | Legacy static secrets may require manual rotation |
| Audit secret access | Vault audit backend, Runbook 5 (exposure response) | Centralized SIEM not prescribed |
| Encrypt secrets at rest | SOPS + KMS, Vault encrypted storage | None |
| Encrypt secrets in transit | TLS/mTLS, Vault API over HTTPS, OIDC token exchange | None |
| Never store secrets in code | C1 (SOPS, pre-commit, merge blocking, repo scanning), Guardrail Rule 1 | None |
| Use temporary credentials | OIDC federation (C2), short TTL, dynamic DB credentials, SSH certificates | None |
| Implement break-glass procedures | C6, dual-control, logged, tested quarterly, recovery runbook | None |
| Separate encryption keys from data | SOPS keys in KMS, encrypted data in Git; Vault keys separate from secret data | None |

---

## 12. OWASP Top 10:2021

| Risk ID | Risk Name | Secrets Management Relevance | Architecture Coverage | Gaps |
|---|---|---|---|---|
| A02 | Cryptographic Failures | Hard-coded keys, missing encryption, poor key management, plaintext credentials | SOPS encryption (C1), KMS key hierarchy, Vault transit, no plaintext in Git, pre-commit scanning | None |
| A05 | Security Misconfiguration | Default credentials, unnecessary features enabled, improper secret storage | Per-environment separation (Rule 2), scoped policies, no wildcard access, Kubernetes security patterns | None |
| A07 | Identification and Authentication Failures | Weak authentication, credential stuffing, improper session management | IdP + MFA, phishing-resistant auth, OIDC federation, short-lived tokens | None |
| A08 | Software and Data Integrity Failures | CI/CD pipeline compromise, unsigned artifacts | OIDC federation (no stored tokens), branch/repo trust conditions, environment-scoped CI roles | Software signing not in scope |
| A09 | Security Logging and Monitoring Failures | Insufficient logging of authentication and access events | Vault audit logging, break-glass logging, admin path auditability | Centralized monitoring not prescribed |

---

## 13. OWASP ASVS 4.0

| Section | Requirement | Architecture Coverage | Gaps |
|---|---|---|---|
| V2.1 | Password Security | IdP-managed passwords with MFA | None (delegated to IdP) |
| V2.5 | Credential Recovery | Break-glass procedures, admin recovery runbook | None |
| V2.7 | Out-of-Band Verifier | Hardware tokens, passkeys | Depends on IdP configuration |
| V2.10 | Service Authentication | Vault service auth, Kubernetes SA, OIDC federation | None |
| V2.10.1 | No hard-coded credentials | C1, Guardrail Rule 1, pre-commit hooks, repo scanning | None |
| V2.10.2 | No default credentials | Per-workload service accounts, scoped policies | None |
| V2.10.3 | API keys with sufficient entropy | Vault-generated credentials, cloud KMS-generated keys | None |
| V2.10.4 | Service authentication with mutual TLS | cert-manager, SPIFFE/SPIRE, workload certificates | None |
| V3.1 | Session Management | Short-lived tokens, TTL-based credentials, no persistent sessions by default | None |
| V6.2 | Algorithms | Cloud KMS approved algorithms, Vault default algorithms | Algorithm audit not prescribed |
| V6.4 | Secret Management | Centralized secret management, encrypted storage, access controls, rotation | None |

---

## 14. OWASP Kubernetes Top 10

| Risk ID | Risk Name | Architecture Coverage | Gaps |
|---|---|---|---|
| K08 | Secrets Management Failures | External Secrets Operator, Secrets Store CSI Driver, Vault integration, etcd encryption, no base64-only secrets, sidecar pattern for secret delivery | None |
| K01 | Insecure Workload Configuration | Pod security context guidance, one SA per workload | Pod security standards enforcement deferred to implementer |
| K03 | Overly Permissive RBAC | Scoped Vault policies, namespace isolation, per-environment roles | K8s RBAC configuration details deferred |
| K09 | Misconfigured Cluster Components | etcd encryption, API server authentication | Cluster hardening details deferred to CIS benchmark |

---

## 15. OWASP CI/CD Security

| Recommendation | Architecture Coverage | Gaps |
|---|---|---|
| No hardcoded secrets in pipelines | OIDC federation (C2), no static credentials in CI | None |
| Use OIDC for cloud authentication | GitHub OIDC workflows for AWS, Azure, GCP, Vault | None |
| Least privilege for pipeline identities | Per-repo/per-branch trust conditions, environment-scoped roles, short TTL | None |
| Secret scanning in pipelines | Pre-commit hooks, repo scanning, merge blocking | None |
| Audit pipeline execution | CI workflow logs, Vault audit trail for credential issuance | None |
| Encrypt secrets at rest in CI | No secrets stored in CI; fetched dynamically via OIDC | None |

---

## 16. CSA Cloud Controls Matrix v4

| Domain | Control ID | Title | Architecture Coverage | Gaps |
|---|---|---|---|---|
| **IAM** | IAM-02 | Credential Lifecycle / Provision Management | Service account lifecycle (Rule 3), IdP management, developer onboarding runbook | None |
| **IAM** | IAM-04 | Policies and Procedures | Controls document (C1-C6), guardrail rules, architecture decisions | None |
| **IAM** | IAM-07 | Third Party Access | OIDC federation restricts third-party access to scoped, short-lived tokens | None |
| **IAM** | IAM-09 | Segregation of Privileges | Per-environment separation (Rule 2), least privilege (C3), namespace isolation | None |
| **IAM** | IAM-12 | User ID Credentials | IdP-managed identities, no shared credentials | None |
| **IAM** | IAM-14 | Strong / Multi-Factor Authentication | SSO + phishing-resistant MFA, hardware tokens, conditional access | None |
| **EKM** | EKM-01 | Encryption and Key Management Entitlement | Cloud KMS, Vault, per-environment key separation | None |
| **EKM** | EKM-02 | Key Generation | KMS and Vault key generation with approved algorithms | None |
| **EKM** | EKM-03 | Sensitive Data Protection | SOPS encryption, Vault encrypted storage, transit encryption | None |
| **EKM** | EKM-04 | Storage and Access | Key storage in KMS/Vault, access controlled by policy | None |
| **DSP** | DSP-01 | Security and Privacy Policy and Procedures | Architecture documentation, controls, threat model | Formal privacy policy not produced |
| **DSP** | DSP-10 | Sensitive Data in the Public Cloud | Cloud KMS encryption, no plaintext secrets in repos or CI | None |
| **IVS** | IVS-09 | Segmentation | Per-environment namespaces, separate KMS keys, Vault role separation | None |
| **LOG** | LOG-01 | Audit Logging / Intrusion Detection | Vault audit logs, break-glass logging, CI audit trails | IDS not in scope |
| **LOG** | LOG-03 | Security Monitoring and Alerting | Lifecycle monitoring (C4), stale-access review | Automated alerting not prescribed |
| **DCS** | DCS-01 | DevSecOps | OIDC CI, pre-commit hooks, SOPS guardrails, IaC security patterns | None |

---

## 17. CSA Top Threats to Cloud Computing (2024)

| Threat Rank | Threat | Architecture Mitigation | Gaps |
|---|---|---|---|
| 1 | Misconfiguration and Inadequate Change Control | SOPS `.sops.yaml` per environment, GitOps patterns, pre-commit validation, merge blocking | None |
| 2 | IAM and Access Control Weaknesses | IdP + MFA, Vault RBAC, OIDC federation, least privilege, per-environment isolation | None |
| 3 | Insecure Interfaces and APIs | Vault API auth, OIDC token validation, mTLS, no static API tokens in CI | None |
| 5 | Non-Human Identity Abuse | One SA per workload (C3), TTL/renewal models (Rule 3), dynamic credentials, no long-lived service tokens | Non-human identity discovery tooling not prescribed |
| 7 | Credential Theft | Short-lived credentials, OIDC (no stored tokens), SSH CA (no persistent keys), dynamic DB creds | None |

---

## 18. CIS Controls v8.1

| Control | Safeguard | Title | Architecture Coverage | Gaps |
|---|---|---|---|---|
| 3 | 3.11 | Encrypt Sensitive Data at Rest | SOPS + KMS, Vault encrypted storage, etcd encryption | None |
| 4 | 4.1 | Establish and Maintain a Secure Configuration Process | `.sops.yaml`, Vault policies, pre-commit hooks, GitOps | None |
| 4 | 4.7 | Manage Default Accounts on Enterprise Assets | No default credentials, per-workload SAs, scoped policies | None |
| 5 | 5.1 | Establish and Maintain an Inventory of Accounts | Service account inventory via Rule 3 (clear owner, defined purpose) | Automated inventory tooling not prescribed |
| 5 | 5.2 | Use Unique Passwords | Vault-generated dynamic credentials, no shared secrets | None |
| 5 | 5.3 | Disable Dormant Accounts | Periodic stale-access review (C5), TTL-based expiry | Automated dormant account detection not prescribed |
| 5 | 5.4 | Restrict Administrator Privileges to Dedicated Admin Accounts | PIM/PAM, admin elevation grants, time-bounded access | None |
| 6 | 6.1 | Establish an Access Granting Process | Developer onboarding runbook, Vault policy management | None |
| 6 | 6.2 | Establish an Access Revoking Process | Revocation paths (Rule 3), SSH CA revocation, secret exposure runbook | None |
| 6 | 6.3 | Require MFA for Externally-Exposed Applications | IdP + MFA for all access | None |
| 6 | 6.4 | Require MFA for Remote Network Access | IdP + MFA, conditional access | None |
| 6 | 6.5 | Require MFA for Administrative Access | PIM/PAM + MFA, hardware tokens for high-value actions | None |
| 6 | 6.8 | Define and Maintain Role-Based Access Control | Vault RBAC, per-environment roles, namespace-scoped policies | None |
| 16 | 16.1 | Establish and Maintain a Secure Application Development Process | Pre-commit hooks, OIDC CI federation, SOPS guardrails, IaC security | None |
| 16 | 16.12 | Implement Code-Level Security Checks | Pre-commit secret scanning, merge blocking on plaintext secrets | None |

---

## 19. CIS Kubernetes Benchmark

| Section | Recommendation | Architecture Coverage | Gaps |
|---|---|---|---|
| 1.2.6 | Encryption providers for data at rest | etcd encryption guidance, KMS provider integration | Specific provider configuration deferred |
| 1.2.29 | Ensure API server encryption provider configured | KMS-backed encryption at rest for etcd | None |
| 4.1.1 | Ensure kubelet authentication is required | Kubernetes auth via service accounts, Vault K8s auth | None |
| 5.4.1 | Prefer using secrets as files over environment variables | Secrets Store CSI Driver, Vault Agent file templates, cert-manager CSI | None |
| 5.4.2 | Consider external secret storage | External Secrets Operator, Vault integration | None |

---

## 20. SOC 2 Type II Trust Service Criteria

| Criteria | Title | Architecture Coverage | Gaps |
|---|---|---|---|
| CC5.2 | COSO Principle 12: Deploys Control Activities | Controls (C1-C6), guardrail rules, pre-commit hooks, merge blocking | None |
| CC6.1 | Logical and Physical Access Controls | Vault RBAC, IdP + MFA, OIDC federation, least privilege, namespace isolation | None |
| CC6.2 | System Credentials / Passwords | Dynamic credentials, Vault-managed secrets, no static passwords in CI | None |
| CC6.3 | Role-Based Access | Per-environment roles, scoped Vault policies, one SA per workload | None |
| CC6.6 | System Boundaries | Per-environment separation (Rule 2), namespace isolation, separate KMS keys | None |
| CC6.7 | Restrict Data Movement | SOPS encryption in Git, no plaintext secrets in transit, mTLS | None |
| CC6.8 | Prevent Unauthorized Access | Pre-commit hooks, merge blocking, Vault auth, conditional access | None |
| CC7.1 | Detect and Monitor Threats | Vault audit logs, repo scanning, lifecycle monitoring | Automated threat detection not prescribed |
| CC7.2 | Monitor for Anomalies | Stale-access review, break-glass logging | Real-time anomaly detection not prescribed |
| CC7.3 | Evaluate Detected Events | Secret exposure response runbook, root cause analysis | None |
| CC7.4 | Respond to Identified Events | Immediate revocation/rotation, distribution surface remediation | None |
| CC8.1 | Control Environment Changes | SOPS GitOps, Vault policy as code, infrastructure as code patterns | None |

---

## 21. PCI DSS 4.0

| Requirement | Sub-Requirement | Title | Architecture Coverage | Gaps |
|---|---|---|---|---|
| 3 | 3.5 | Primary account number (PAN) is secured wherever stored | SOPS encryption for any stored PAN, KMS-backed keys | PAN-specific controls depend on application scope |
| 3 | 3.6 | Cryptographic keys used to protect stored account data are secured | Cloud KMS as master key authority, key hierarchy, access-controlled key storage | None |
| 3 | 3.7 | Key management processes covering all aspects of key lifecycle | Key generation, storage, distribution, rotation, revocation procedures via Vault/KMS + runbooks | None |
| 6 | 6.2 | Bespoke and custom software developed securely | Pre-commit hooks, secret scanning, OIDC CI federation, SOPS guardrails | None |
| 6 | 6.3 | Security vulnerabilities identified and addressed | Repo scanning, vulnerability management in CI | None |
| 6 | 6.4 | Public-facing web applications protected | Out of primary scope (secrets infrastructure, not application WAF) | WAF/application security out of scope |
| 8 | 8.2 | User identification and authentication | IdP + MFA, unique identities, no shared accounts | None |
| 8 | 8.3 | Strong authentication for users and administrators | Phishing-resistant MFA, hardware tokens, AAL2+ authentication | None |
| 8 | 8.3.1 | Multi-factor authentication | MFA for all access via IdP | None |
| 8 | 8.3.6 | Credential complexity requirements for service accounts | Vault-generated credentials with sufficient entropy | None |
| 8 | 8.6 | Service account management | One SA per workload, clear owner, defined purpose, TTL/renewal (Rule 3) | None |

---

## 22. FedRAMP

| Requirement Area | Architecture Coverage | Gaps |
|---|---|---|
| FIPS 140-2/3 validated cryptographic modules | Cloud KMS providers offer FIPS-validated modules; Vault Enterprise supports FIPS | Requires explicit FIPS mode configuration |
| Automated key management and rotation | Vault dynamic credentials, cert-manager auto-renewal, TTL-based rotation | None |
| Least-privileged, role-based access | Vault RBAC, per-environment roles, OIDC scoped access | None |
| Continuous monitoring of access | Vault audit logs, stale-access review | ATO continuous monitoring package not produced |
| Encryption at rest and in transit | SOPS + KMS (rest), TLS/mTLS (transit) | None |
| Key Security Indicators (20x) | Secrets management, encryption, access control, monitoring addressed | Formal KSI documentation not produced |

---

## 23. CISA Zero Trust Maturity Model v2.0

| Pillar | Maturity Area | Architecture Coverage | Level Achieved |
|---|---|---|---|
| **Identity** | Authentication | IdP + phishing-resistant MFA, hardware tokens, conditional access | Advanced |
| **Identity** | Identity stores | Centralized IdP (Entra/Okta), Vault for machine identity | Advanced |
| **Identity** | Risk assessment | Device posture checks, conditional access policies | Initial to Advanced |
| **Identity** | Access management | Vault RBAC, OIDC federation, least privilege, dynamic credentials | Advanced |
| **Identity** | Identity lifecycle | Onboarding/offboarding runbooks, SA lifecycle (Rule 3) | Initial to Advanced |
| **Devices** | Policy enforcement | MDM (Intune), device posture, managed device preference | Advanced |
| **Devices** | Asset management | Device trust as part of identity plane | Initial |
| **Networks** | Micro-segmentation | Per-environment namespaces, network policy guidance | Initial |
| **Applications & Workloads** | Access authorization | OIDC federation, Vault auth, workload identity (SPIFFE) | Advanced |
| **Applications & Workloads** | Threat protection | Pre-commit scanning, SOPS guardrails, CI security | Initial to Advanced |
| **Data** | Data encryption | SOPS at rest, TLS in transit, KMS protection | Advanced |
| **Data** | Data access management | Vault path-based policies, least privilege, per-environment separation | Advanced |

---

## Gap Summary

The following gaps are systemic across multiple frameworks and represent areas where the reference architecture intentionally defers to the adopting organization:

| Gap Category | Affected Frameworks | Remediation Path |
|---|---|---|
| Formal policy documents (ISMS, cryptography policy, acceptable use) | ISO 27001, ISO 27002, FedRAMP, SOC 2 | Produce formal policy documents using architecture as technical basis |
| Automated non-human identity inventory and discovery | NIST CSF 2.0, CSA Top Threats, CIS Controls | Integrate NHI discovery tooling (Aembit, Astrix, etc.) |
| Centralized SIEM integration and automated alerting | NIST 800-53 AU, SOC 2 CC7, CSA CCM LOG | Integrate Vault audit logs with organizational SIEM |
| Automated dormant account/credential detection | CIS Controls 5.3, ISO 27001 A.5.18 | Implement automated credential usage monitoring |
| FIPS 140-2/3 explicit mode configuration | FedRAMP, NIST 800-53 SC-13 | Enable FIPS mode on Vault Enterprise, verify cloud KMS FIPS status |
| HSM backing for root key material | NIST 800-57, NIST 800-152, PCI DSS 3.6 | Deploy HSM-backed KMS or Vault Enterprise with HSM seal |
| CRL/OCSP revocation infrastructure | NIST 800-57, ISO 27001 A.8.24 | Deploy certificate revocation infrastructure alongside PKI |
| Formal ATO/certification packages | FedRAMP, ISO 27001 | Produce certification documentation using this mapping as foundation |

---

## How to Use This Mapping

1. **For compliance readiness**: Identify which framework applies to your organization, find the relevant section, and verify that your implementation covers the architecture patterns described.

2. **For gap analysis**: Use the gap columns to identify where additional organizational controls, tooling, or documentation are needed beyond what this architecture provides.

3. **For auditor communication**: Reference specific control IDs when demonstrating how your secrets management practices satisfy framework requirements. The architecture's control objectives (C1-C6) and guardrail rules (1-4) map cleanly to most framework requirements.

4. **For RFP/client responses**: Use the mapping tables to demonstrate framework alignment in security questionnaires and compliance documentation.

---

## Source References

- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-204 Series](https://csrc.nist.gov/pubs/sp/800/204/final)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
- [NIST SP 800-57 Part 1 Rev 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST SP 800-152](https://csrc.nist.gov/pubs/sp/800/152/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html)
- [ISO/IEC 27017:2015](https://www.iso.org/standard/43757.html)
- [ISO/IEC 27018:2019](https://www.iso.org/standard/76559.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [OWASP Top 10:2021](https://owasp.org/Top10/2021/)
- [OWASP ASVS 4.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Kubernetes Top 10](https://owasp.org/www-project-kubernetes-top-ten/)
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html)
- [CSA Cloud Controls Matrix v4](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4)
- [CSA Top Threats to Cloud Computing 2024](https://cloudsecurityalliance.org/artifacts/top-threats-to-cloud-computing-2024)
- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [SOC 2 Trust Service Criteria](https://cloudsecurityalliance.org/blog/2023/10/05/the-5-soc-2-trust-services-criteria-explained)
- [PCI DSS 4.0](https://www.pcisecuritystandards.org)
- [FedRAMP](https://www.fedramp.gov)
- [CISA Zero Trust Maturity Model v2.0](https://www.cisa.gov/zero-trust-maturity-model)
