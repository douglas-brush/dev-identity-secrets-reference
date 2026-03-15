# SOC 2, PCI DSS 4.0, and FedRAMP Mapping

Maps reference architecture controls to SOC 2 Type II, PCI DSS 4.0, and FedRAMP requirements.

## SOC 2 Type II — Trust Service Criteria

### CC6: Logical and Physical Access Controls

| Criteria | Description | Architecture Implementation |
|----------|-------------|---------------------------|
| CC6.1 | Logical access security software, infrastructure, and architectures | Vault RBAC, K8s RBAC, namespace isolation, network policies |
| CC6.2 | Prior to issuing credentials, the entity registers and authorizes new users | Application onboarding runbook, IdP provisioning, Vault role binding |
| CC6.3 | The entity authorizes, modifies, or removes access based on authorized personnel | Central IdP + Vault: add/remove users, modify policies, revoke tokens |
| CC6.6 | The entity implements logical access security measures to protect against threats | OIDC authentication, MFA, least-privilege policies, encryption |
| CC6.7 | The entity restricts the transmission, movement, and removal of information | Network policies, TLS encryption, SOPS for data at rest |
| CC6.8 | The entity implements controls to prevent or detect unauthorized changes | Pre-commit hooks, branch protection, secret scanning |

### CC7: System Operations

| Criteria | Description | Architecture Implementation |
|----------|-------------|---------------------------|
| CC7.1 | The entity uses detection and monitoring procedures | Vault audit logging, secret scanning, credential age reporting |
| CC7.2 | The entity monitors system components for anomalies | Credential access patterns, Vault telemetry, KMS audit |
| CC7.3 | The entity evaluates identified security events | Secret exposure response runbook |
| CC7.4 | The entity responds to identified security incidents | Automated secret rotation, revocation procedures |

### CC8: Change Management

| Criteria | Description | Architecture Implementation |
|----------|-------------|---------------------------|
| CC8.1 | Changes are authorized and managed | Git-based config management, PR reviews, SOPS encryption |

### CC9: Risk Mitigation

| Criteria | Description | Architecture Implementation |
|----------|-------------|---------------------------|
| CC9.1 | The entity identifies, selects, and develops risk mitigation activities | Threat model with 7 scenarios, control objectives C1-C6 |

### A1: Availability

| Criteria | Description | Architecture Implementation |
|----------|-------------|---------------------------|
| A1.2 | Environmental protections, backup, and recovery | HA Vault (Raft), break-glass procedures, KMS redundancy |

### C1: Confidentiality

| Criteria | Description | Architecture Implementation |
|----------|-------------|---------------------------|
| C1.1 | Confidential information is identified and protected | Credential classification, SOPS encryption, access controls |
| C1.2 | Confidential information is disposed of securely | TTL-based credential expiry, lease revocation, key destruction |

## PCI DSS 4.0 — Key Requirements

### Requirement 3: Protect Stored Account Data

| Sub-Req | Description | Architecture Implementation |
|---------|-------------|---------------------------|
| 3.1.1 | Policies for protecting stored data | SOPS encryption policy, Vault storage encryption |
| 3.5.1 | Restrict access to cryptographic keys | Cloud KMS access policies, Vault seal key protection |
| 3.5.1.1 | Additional requirement for service providers | HSM-backed KMS option for key protection |
| 3.6.1 | Key management procedures | Documented key hierarchy, rotation procedures |
| 3.6.1.1 | Key generation from approved sources | Cloud KMS key generation (FIPS 140-2 Level 3) |
| 3.6.1.2 | Secure key distribution | OIDC token exchange, CSI mount, encrypted channels |
| 3.6.1.3 | Secure key storage | Cloud KMS/HSM, Vault seal, no plaintext keys |
| 3.6.1.4 | Key rotation at end of cryptoperiod | TTL-based rotation, SOPS key rotation script |
| 3.7.1 | Key management documentation | Architecture docs, key hierarchy documentation |

### Requirement 6: Develop and Maintain Secure Systems

| Sub-Req | Description | Architecture Implementation |
|---------|-------------|---------------------------|
| 6.2.3 | Code reviewed for security | Pre-commit secret scanning, PR secret detection |
| 6.2.3.1 | Code changes reviewed for all custom software | CI secret scanning workflow on every PR |
| 6.3.2 | Maintain inventory of custom and bespoke software | Documented tooling, versioned infrastructure |
| 6.4.1 | Web applications protected | OIDC authentication, no hardcoded API keys |

### Requirement 7: Restrict Access by Business Need to Know

| Sub-Req | Description | Architecture Implementation |
|---------|-------------|---------------------------|
| 7.1.1 | Access control policies defined | Vault policy model, RBAC documentation |
| 7.2.1 | Access control system in place | Vault + IdP integration, policy enforcement |
| 7.2.2 | Appropriate privileges assigned | Least-privilege policies per workload |
| 7.2.4 | All user accounts and privileges reviewed | Credential age reports, access reviews |
| 7.2.5 | All application/system accounts reviewed | Service account inventory, dynamic credentials |

### Requirement 8: Identify Users and Authenticate Access

| Sub-Req | Description | Architecture Implementation |
|---------|-------------|---------------------------|
| 8.2.1 | All users assigned unique IDs | IdP unique identities, per-workload service accounts |
| 8.2.2 | Group/shared accounts controlled | No shared credentials by design, dynamic per-workload |
| 8.3.1 | Strong authentication for all access | OIDC/SSO with MFA |
| 8.3.2 | Strong authentication for non-console admin | SSH CA with MFA, no static admin keys |
| 8.3.6 | Passwords/passphrases meet complexity | Dynamic credentials eliminate manual passwords |
| 8.3.9 | Change passwords/passphrases at least every 90 days | TTL-based auto-expiry (minutes to hours, not days) |
| 8.4.2 | MFA for all access into CDE | Phishing-resistant MFA for all secret store access |
| 8.6.1 | Manage system/application accounts | Automated via Vault policies and K8s service accounts |
| 8.6.2 | Passwords for application/system accounts changed periodically | Dynamic credentials rotate per-request |
| 8.6.3 | Passwords for application/system accounts hardened | Generated by Vault with sufficient entropy |

### Requirement 10: Log and Monitor All Access

| Sub-Req | Description | Architecture Implementation |
|---------|-------------|---------------------------|
| 10.2.1 | Audit logs enabled and active | Vault audit backend, cloud KMS audit |
| 10.2.1.1 | Audit logs capture all access to cardholder data | All credential access logged with identity |
| 10.2.1.2 | Audit logs capture all admin actions | Vault audit captures all administrative operations |
| 10.2.2 | Audit logs capture identity of each user | Vault audit includes authenticated entity |
| 10.3.1 | Read access to audit logs restricted | Audit log storage with separate access controls |

## FedRAMP — Key Management Controls

| FedRAMP Control | NIST 800-53 Mapping | Architecture Implementation |
|----------------|--------------------|-----------------------------|
| SC-12 | Cryptographic Key Establishment and Management | Cloud KMS hierarchy, Vault Transit, SOPS |
| SC-12(1) | Availability | Break-glass procedures, KMS redundancy |
| SC-13 | Cryptographic Protection | FIPS-validated algorithms via cloud KMS |
| SC-28 | Protection of Information at Rest | SOPS, Vault seal, cloud encryption |
| IA-2(1) | MFA to Privileged Accounts | Hardware MFA for all privileged access |
| IA-5 | Authenticator Management | Centralized credential lifecycle via Vault |
| AC-2 | Account Management | IdP + Vault automated provisioning |
| AU-2 | Event Logging | Vault audit, cloud audit, complete audit trail |

### FedRAMP Specific Considerations

| Requirement | Implementation Notes |
|-------------|---------------------|
| FIPS 140-2 Level 3 key storage | Cloud KMS with HSM backing (AWS CloudHSM, Azure Managed HSM) |
| Continuous monitoring | Vault telemetry + audit log streaming to SIEM |
| Boundary protection | Network policies, TLS enforcement, no public secret endpoints |
| Configuration management | Git-based IaC, SOPS-encrypted configs |
| Incident response | Secret exposure response runbook with evidence collection |
