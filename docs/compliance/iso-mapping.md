# ISO 27001:2022 / ISO 27002:2022 / ISO 27017 Mapping

Maps reference architecture controls to ISO information security standards.

## ISO 27001:2022 — Annex A Controls

### A.5 — Organizational Controls

| Control | Title | Architecture Implementation |
|---------|-------|---------------------------|
| A.5.1 | Policies for information security | Control objectives C1-C6, guardrail rules 1-4 |
| A.5.2 | Information security roles and responsibilities | Credential ownership model: app owner, platform owner, security lead |
| A.5.3 | Segregation of duties | Separate dev/staging/prod trust domains, dual-control break-glass |
| A.5.9 | Inventory of information and other associated assets | Credential taxonomy, secret store inventory, KMS key registry |
| A.5.10 | Acceptable use of information and other associated assets | Guardrail rules define acceptable credential handling |
| A.5.15 | Access control | Vault policies, Kubernetes RBAC, namespace isolation |
| A.5.16 | Identity management | Centralized IdP, automated provisioning/deprovisioning |
| A.5.17 | Authentication information | Dynamic credentials, short-lived tokens, no static passwords |
| A.5.18 | Access rights | Least-privilege per workload, role-based Vault policies |
| A.5.23 | Information security for use of cloud services | Cloud KMS, OIDC federation, cloud-native secret managers |
| A.5.25 | Assessment and decision on information security events | Vault audit log analysis, secret exposure response runbook |
| A.5.26 | Response to information security incidents | Secret exposure response runbook (Runbook 5) |
| A.5.28 | Collection of evidence | Vault audit logs, credential access history |
| A.5.29 | Information security during disruption | Break-glass procedures, HA Vault, recovery runbook |
| A.5.34 | Privacy and protection of PII | No credentials in logs, masked audit entries, SOPS encryption |
| A.5.36 | Compliance with policies, rules and standards | Pre-commit hooks, CI scanning, OPA policies, compliance checks |

### A.7 — Physical Controls

| Control | Title | Architecture Implementation |
|---------|-------|---------------------------|
| A.7.9 | Security of assets off-premises | MDM/Intune device compliance, no local durable secrets |
| A.7.10 | Storage media | No secrets on removable media, SOPS for Git encryption |

### A.8 — Technological Controls

| Control | Title | Architecture Implementation |
|---------|-------|---------------------------|
| A.8.1 | User endpoint devices | MDM enforcement, device posture checking, managed devices |
| A.8.2 | Privileged access rights | PIM/PAM gating, short-lived SSH certs, break-glass controls |
| A.8.3 | Information access restriction | Vault path-based ACLs, namespace isolation, scoped tokens |
| A.8.4 | Access to source code | Branch protection, signed commits, PR review requirements |
| A.8.5 | Secure authentication | OIDC/SSO with phishing-resistant MFA, FIDO2 for privileged ops |
| A.8.7 | Protection against malware | Pre-commit scanning, secret detection, gitleaks integration |
| A.8.9 | Configuration management | SOPS-encrypted config, version-controlled infrastructure |
| A.8.10 | Information deletion | Automatic credential expiry via TTL, lease revocation |
| A.8.11 | Data masking | Vault Transit encryption-as-a-service, no plaintext in logs |
| A.8.12 | Data leakage prevention | Pre-commit hooks, secret scanning, network policies |
| A.8.15 | Logging | Vault audit backend, cloud KMS audit logs, CI workflow logs |
| A.8.16 | Monitoring activities | Credential age reports, access anomaly detection |
| A.8.20 | Networks security | Kubernetes network policies, TLS for all Vault communication |
| A.8.21 | Security of network services | mTLS for service-to-service, cert-manager issued certificates |
| A.8.24 | Use of cryptography | Cloud KMS, Vault Transit, SOPS, cert-manager PKI |
| A.8.25 | Secure development life cycle | OIDC CI federation, secret scanning in pipelines |
| A.8.26 | Application security requirements | No hardcoded secrets, external secret delivery |
| A.8.27 | Secure system architecture and engineering principles | Three-plane architecture, defense in depth |
| A.8.28 | Secure coding | Pre-commit secret detection, no credentials in source |
| A.8.31 | Separation of development, test and production environments | Separate KMS keys, Vault namespaces, K8s namespaces per env |
| A.8.33 | Test information | Dynamic test credentials, no production data in dev |

## ISO 27002:2022 — Key Management Guidance (Section 8.24)

| Guidance | Implementation |
|----------|---------------|
| Key generation using approved methods | Cloud KMS key generation, Vault-managed key creation |
| Key distribution through secure channels | OIDC token exchange, CSI driver mount, encrypted delivery |
| Key storage with appropriate protection | HSM-backed KMS, Vault seal protection, no plaintext storage |
| Key rotation at defined intervals | Automated rotation via Vault policies, SOPS key rotation script |
| Key revocation and destruction | Vault lease revocation, certificate CRL, KMS key scheduling |
| Key archiving for legal requirements | Audit log retention, break-glass key escrow |
| Logging of key management activities | Cloud KMS audit, Vault audit backend |
| Defined cryptographic key lifetimes | TTL enforcement on all dynamic credentials |
| Protection of private keys | SOPS encryption, 0600 permissions, memory-backed mounts |

## ISO 27017 — Cloud Security Controls

| Control | Title | Architecture Implementation |
|---------|-------|---------------------------|
| CLD.6.3 | Shared roles and responsibilities | Documented cloud vs. organization responsibility for key management |
| CLD.8.1 | Virtualization security | Container isolation, no secrets in images, runtime delivery |
| CLD.9.5 | Virtual machine hardening | No embedded secrets in VM images, Vault Agent for runtime |
| CLD.12.1 | Cloud service admin operations | OIDC federation, no static cloud admin keys |
| CLD.12.4 | Multi-tenant environment monitoring | Namespace isolation, per-tenant secret stores |
| CLD.13.1 | Cloud network management | Network policies restricting secret store access |

## ISO 27001:2022 — Statement of Applicability (SoA) Template

The following controls are directly implemented by this reference architecture:

```
A.5.1   ✅ Implemented — documented policies and controls
A.5.3   ✅ Implemented — environment separation, dual-control
A.5.15  ✅ Implemented — Vault RBAC, K8s RBAC
A.5.16  ✅ Implemented — centralized IdP
A.5.17  ✅ Implemented — dynamic credentials, no static passwords
A.5.18  ✅ Implemented — least privilege policies
A.5.23  ✅ Implemented — cloud KMS, OIDC federation
A.8.2   ✅ Implemented — PIM/PAM, SSH CA
A.8.3   ✅ Implemented — path-based ACLs
A.8.5   ✅ Implemented — OIDC/SSO with MFA
A.8.9   ✅ Implemented — SOPS, version-controlled config
A.8.12  ✅ Implemented — pre-commit scanning, network policies
A.8.15  ✅ Implemented — Vault audit, cloud audit
A.8.24  ✅ Implemented — KMS, Transit, SOPS, PKI
A.8.31  ✅ Implemented — separate environments with separate keys
```
