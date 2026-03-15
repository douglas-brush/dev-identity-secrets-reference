# CISA Zero Trust Maturity Model Mapping

Maps reference architecture to the CISA Zero Trust Maturity Model pillars.

## Overview

The CISA Zero Trust Maturity Model defines five pillars: Identity, Devices, Networks, Applications & Workloads, and Data. Each pillar progresses through Traditional, Initial, Advanced, and Optimal maturity levels.

This reference architecture targets **Advanced** maturity across all credential-related capabilities.

## Pillar 1: Identity

| Maturity Level | Capability | Architecture Implementation | Status |
|---------------|------------|---------------------------|--------|
| **Traditional** | Password-based authentication | Eliminated — SSO with MFA required | Exceeded |
| **Initial** | MFA deployed, basic identity governance | IdP with phishing-resistant MFA | Exceeded |
| **Advanced** | Phishing-resistant MFA, automated identity lifecycle | FIDO2/passkeys, IdP automation, Vault OIDC | Target |
| **Optimal** | Continuous identity validation, risk-based auth | Device posture + real-time risk (IdP conditional access) | Partial |

### Identity Capabilities

| Capability | Implementation |
|-----------|---------------|
| Identity stores | Centralized IdP (Entra ID / Okta) as single source of truth |
| MFA | Phishing-resistant (FIDO2/WebAuthn) for privileged, push/TOTP for standard |
| Identity lifecycle | Automated provisioning/deprovisioning via IdP groups |
| Privileged access | PIM/PAM with time-boxed elevation |
| Machine identities | Per-workload service accounts, SPIFFE IDs, mTLS certificates |
| Federation | OIDC for CI (GitHub), Kubernetes SA auth, cloud workload identity |

## Pillar 2: Devices

| Maturity Level | Capability | Architecture Implementation | Status |
|---------------|------------|---------------------------|--------|
| **Traditional** | Limited device inventory | N/A | Exceeded |
| **Initial** | Basic device management | MDM/Intune managed devices | Exceeded |
| **Advanced** | Device compliance gated access, posture checks | Conditional access policies, device trust verification | Target |
| **Optimal** | Real-time device health, automated remediation | Continuous compliance (Intune + conditional access) | Partial |

### Device Capabilities

| Capability | Implementation |
|-----------|---------------|
| Device inventory | MDM-managed fleet with compliance reporting |
| Endpoint compliance | Intune device compliance policies gate secret access |
| Device certificates | Cloud PKI / BYOCA for device identity |
| Posture checking | Pre-authentication device health validation |
| Developer workstations | No durable secrets, bootstrap-on-demand, cleanup on exit |

## Pillar 3: Networks

| Maturity Level | Capability | Architecture Implementation | Status |
|---------------|------------|---------------------------|--------|
| **Traditional** | Perimeter-based security | Eliminated — identity-based access | Exceeded |
| **Initial** | Basic network segmentation | Kubernetes network policies | Exceeded |
| **Advanced** | Micro-segmentation, encrypted internal traffic | Default-deny policies, mTLS, Vault network isolation | Target |
| **Optimal** | Full micro-segmentation with dynamic policies | Service mesh mTLS (future), SPIFFE identity | Planned |

### Network Capabilities

| Capability | Implementation |
|-----------|---------------|
| Segmentation | Kubernetes namespaces, network policies |
| Encryption | TLS 1.2+ for all Vault/KMS communication |
| Micro-segmentation | Default deny-all network policy, explicit allow rules |
| Secret store access | Network policies restrict access to Vault endpoints |
| East-west encryption | mTLS via cert-manager (current), service mesh (future) |

## Pillar 4: Applications & Workloads

| Maturity Level | Capability | Architecture Implementation | Status |
|---------------|------------|---------------------------|--------|
| **Traditional** | Static credentials embedded in applications | Eliminated — external secret delivery | Exceeded |
| **Initial** | Centralized secret storage | Vault KV, cloud secret managers | Exceeded |
| **Advanced** | Dynamic credentials, automated lifecycle, policy enforcement | Vault dynamic creds, TTL, Kyverno policies | Target |
| **Optimal** | Continuous verification, runtime security | SPIFFE workload identity, continuous cert rotation | Partial |

### Application Capabilities

| Capability | Implementation |
|-----------|---------------|
| Secret delivery | ESO, CSI driver, Vault Agent — no hardcoded secrets |
| Dynamic credentials | Vault database engine, OIDC token exchange |
| Certificate lifecycle | cert-manager with automatic rotation |
| Workload identity | Kubernetes service accounts, SPIFFE IDs |
| CI/CD security | OIDC federation, no stored deployment secrets |
| Admission control | Kyverno policies enforce secret management patterns |
| Secret scanning | Pre-commit hooks, CI scanning, gitleaks |

## Pillar 5: Data

| Maturity Level | Capability | Architecture Implementation | Status |
|---------------|------------|---------------------------|--------|
| **Traditional** | Basic encryption | Eliminated — comprehensive encryption | Exceeded |
| **Initial** | Data classification, basic encryption | Credential taxonomy, SOPS encryption | Exceeded |
| **Advanced** | Granular data protection, automated classification | Per-environment KMS keys, Vault Transit, automated scanning | Target |
| **Optimal** | Dynamic data protection, content-aware policies | Transit encryption-as-a-service, policy-driven access | Partial |

### Data Capabilities

| Capability | Implementation |
|-----------|---------------|
| Data encryption at rest | SOPS + Cloud KMS, Vault seal, Kubernetes etcd encryption |
| Data encryption in transit | TLS for all credential flows |
| Data classification | 7-class credential taxonomy with handling rules |
| Data access controls | Vault path-based ACLs, KMS key policies |
| Data lifecycle | TTL-based automatic expiry, lease revocation |
| Data loss prevention | Pre-commit scanning, network policies, audit logging |
| Encryption-as-a-service | Vault Transit for application-level encryption |

## Cross-Cutting Capabilities

### Visibility and Analytics

| Capability | Implementation |
|-----------|---------------|
| Audit logging | Vault audit backend with complete who/what/when/result |
| Centralized monitoring | SIEM integration pipeline |
| Credential reporting | Credential age reports, stale access detection |
| Anomaly detection | Access pattern analysis from audit logs |
| Compliance dashboards | OPA policy tests, compliance check scripts |

### Automation and Orchestration

| Capability | Implementation |
|-----------|---------------|
| Automated provisioning | IdP group -> Vault role automation |
| Automated credential rotation | TTL-based auto-expiry, Vault lease renewal |
| Automated secret delivery | ESO, CSI, Vault Agent — zero manual steps |
| Automated scanning | CI/CD pipeline secret detection |
| Automated remediation | Secret exposure response: revoke, rotate, notify |
| Infrastructure as Code | Terraform modules for KMS, OIDC, Vault setup |

### Governance

| Capability | Implementation |
|-----------|---------------|
| Policy definition | Control objectives C1-C6, guardrail rules |
| Policy enforcement | Kyverno admission control, Vault policy evaluation |
| Compliance mapping | NIST, ISO, OWASP, CSA, CIS, SOC2, PCI DSS, FedRAMP |
| Risk management | Threat model with 7 scenarios and mitigations |
| Incident response | Secret exposure response runbook |
| Recovery procedures | Break-glass with dual control, tested quarterly |

## Maturity Assessment Summary

| Pillar | Current Target | Key Gap |
|--------|---------------|---------|
| Identity | Advanced | Continuous risk-based auth requires runtime telemetry |
| Devices | Advanced | Real-time posture depends on MDM maturity |
| Networks | Advanced | Full service mesh mTLS is future phase |
| Applications | Advanced | SPIFFE/SPIRE rollout is future phase |
| Data | Advanced | Content-aware DLP is future phase |
