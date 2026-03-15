# CIS Controls v8 & SANS Mapping

Maps reference architecture controls to CIS Controls v8, CIS Benchmarks, and SANS resources.

## CIS Controls v8

### Implementation Group 1 (IG1) — Essential Cyber Hygiene

| Control | Sub-Control | Title | Architecture Implementation |
|---------|------------|-------|---------------------------|
| 3 | 3.1 | Establish and Maintain a Data Management Process | Credential taxonomy, secret classification by environment |
| 3 | 3.4 | Enforce Data Retention Management | TTL-based credential expiry, lease auto-revocation |
| 3 | 3.6 | Encrypt Data on End-User Devices | SOPS for developer workstations, no plaintext secrets locally |
| 3 | 3.10 | Encrypt Sensitive Data in Transit | TLS for all Vault/KMS communication |
| 3 | 3.11 | Encrypt Sensitive Data at Rest | SOPS + KMS encryption, Vault seal |
| 4 | 4.1 | Establish and Maintain a Secure Configuration Process | SOPS config templates, environment separation |
| 4 | 4.7 | Manage Default Accounts on Enterprise Assets | No default credentials, dynamic credential issuance |
| 5 | 5.1 | Establish and Maintain an Inventory of Accounts | Centralized IdP, Vault identity entities |
| 5 | 5.2 | Use Unique Passwords | Dynamic per-workload credentials, no shared passwords |
| 5 | 5.3 | Disable Dormant Accounts | TTL-based expiry, credential age reporting |
| 5 | 5.4 | Restrict Admin Privileges to Dedicated Admin Accounts | PIM/PAM gating, separate admin roles |
| 6 | 6.1 | Establish an Access Granting Process | Application onboarding runbook, Vault policy creation |
| 6 | 6.2 | Establish an Access Revoking Process | Central IdP revocation, Vault token revocation |
| 6 | 6.3 | Require MFA for Externally-Exposed Applications | OIDC with MFA for all human access |
| 6 | 6.4 | Require MFA for Remote Network Access | Phishing-resistant MFA for VPN/SSH access |
| 6 | 6.5 | Require MFA for Administrative Access | Hardware MFA/passkeys for privileged operations |
| 6 | 6.7 | Centralize Access Control | Vault as central credential broker |
| 6 | 6.8 | Define and Maintain Role-Based Access Control | Vault policies by role (developer, CI, admin) |

### Implementation Group 2 (IG2)

| Control | Sub-Control | Title | Architecture Implementation |
|---------|------------|-------|---------------------------|
| 3 | 3.12 | Segment Data Processing and Storage Based on Sensitivity | Environment separation (dev/staging/prod), separate KMS keys |
| 4 | 4.2 | Establish and Maintain a Secure Configuration Process for Network Infrastructure | Network policies for secret store access |
| 5 | 5.5 | Establish and Maintain an Inventory of Service Accounts | Service account inventory via Vault entities |
| 5 | 5.6 | Centralize Account Management | IdP + Vault centralized identity |
| 8 | 8.2 | Collect Audit Logs | Vault audit backend, cloud KMS audit, CI logs |
| 8 | 8.3 | Ensure Adequate Audit Log Storage | Log retention policies, SIEM integration |
| 8 | 8.5 | Collect Detailed Audit Logs | Vault audit captures who/what/when/result |
| 8 | 8.9 | Centralize Audit Logs | Vault audit -> SIEM pipeline |
| 8 | 8.11 | Conduct Audit Log Reviews | Credential age reports, anomaly detection |
| 16 | 16.1 | Establish and Maintain a Secure Application Development Process | Pre-commit hooks, CI scanning, OIDC federation |
| 16 | 16.7 | Use Standard Hardening Configuration Templates for Application Infrastructure | Vault policy templates, K8s manifest templates |
| 16 | 16.12 | Implement Code-Level Security Checks | Pre-commit secret scanning, gitleaks in CI |

### Implementation Group 3 (IG3)

| Control | Sub-Control | Title | Architecture Implementation |
|---------|------------|-------|---------------------------|
| 3 | 3.9 | Encrypt Data on Removable Media | N/A — no secrets on removable media by design |
| 8 | 8.12 | Collect Service Provider Logs | Cloud KMS audit logs from AWS/Azure/GCP |
| 13 | 13.1 | Centralize Security Event Alerting | Vault audit alerting, secret exposure alerts |
| 16 | 16.9 | Train Developers in Application Security Concepts and Secure Coding | Developer onboarding runbook includes security training |

## CIS Benchmarks — Kubernetes Secrets

| Benchmark Item | Recommendation | Architecture Implementation |
|---------------|---------------|---------------------------|
| 5.4.1 | Prefer using secrets as Files over secrets as Environment Variables | CSI driver file mounts, cert-manager CSI |
| 5.4.2 | Consider external secret storage | External Secrets Operator, Vault integration |
| 1.2.29 | Ensure encryption providers are configured | Kubernetes encryption at rest + external Vault |
| 5.1.1 | Ensure cluster-admin role is only used where required | Scoped roles, no cluster-admin for secret access |
| 5.1.2 | Minimize access to secrets | Namespace-scoped SecretStores, per-app service accounts |
| 5.1.3 | Minimize wildcard use in RBAC | No wildcard verb access in Vault policies |
| 5.1.5 | Ensure default service account is not actively used | Kyverno policy blocks default SA usage |
| 5.1.6 | Ensure Service Account Tokens are only mounted where necessary | automountServiceAccountToken: false by default |

## CIS Benchmarks — Vault

| Benchmark Item | Recommendation | Architecture Implementation |
|---------------|---------------|---------------------------|
| 1.1 | Enable audit logging | File and/or syslog audit backend |
| 1.2 | Set TLS on all listeners | TLS 1.2+ required for all listeners |
| 1.3 | Disable root token after initial setup | Root token revoked after initial config |
| 2.1 | Use auto-unseal | Cloud KMS auto-unseal (AWS/Azure/GCP) |
| 2.2 | Configure seal with multiple shares | Shamir with 3-of-5 or cloud auto-unseal |
| 3.1 | Use OIDC/LDAP for human auth | OIDC auth method configured |
| 3.2 | Use AppRole/Kubernetes for machine auth | Kubernetes auth, JWT/GitHub for CI |
| 4.1 | Apply least-privilege policies | Per-role policies with explicit paths |
| 4.2 | Avoid wildcard policies | No wildcard paths in any policy |
| 5.1 | Enable telemetry | Prometheus metrics endpoint |
| 5.2 | Monitor seal status | Health check endpoints, alerting |

## SANS Top 20 / Critical Security Controls

| SANS Area | Architecture Coverage |
|-----------|---------------------|
| **Inventory of Authorized Software** | Documented tooling requirements, devcontainer with pinned tools |
| **Secure Configuration** | SOPS templates, Vault policy templates, K8s manifests |
| **Continuous Vulnerability Assessment** | CI secret scanning, credential age reporting |
| **Controlled Use of Admin Privileges** | PIM/PAM gating, SSH CA, break-glass controls |
| **Maintenance and Monitoring of Audit Logs** | Vault audit, cloud audit, SIEM integration |
| **Account Monitoring and Control** | Centralized IdP, credential TTL, access reviews |
| **Data Protection** | SOPS encryption, KMS, Transit, network policies |
| **Incident Response** | Secret exposure response runbook |

## SANS DevSecOps — Secrets in CI/CD

| SANS Recommendation | Architecture Implementation |
|--------------------|---------------------------|
| Never store secrets in version control | SOPS encryption, pre-commit scanning |
| Use ephemeral CI credentials | OIDC federation, no stored deployment secrets |
| Scan for secrets in every build | gitleaks CI workflow on every PR |
| Use dynamic secrets in CI | Vault dynamic credentials via OIDC |
| Rotate CI credentials regularly | OIDC eliminates stored credentials entirely |
| Monitor for secret leakage | Secret scanning, audit logging |
| Implement break-glass for CI | Documented emergency deployment procedures |
