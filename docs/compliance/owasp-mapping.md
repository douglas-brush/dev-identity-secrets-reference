# OWASP Standards Mapping

Maps reference architecture controls to OWASP publications and guidelines.

## OWASP Secrets Management Cheat Sheet

| Recommendation | Architecture Implementation | Status |
|---------------|---------------------------|--------|
| **Centralized secrets management** | Vault as central broker, cloud secret managers | Implemented |
| **No hardcoded secrets** | SOPS encryption, pre-commit scanning, gitleaks | Implemented |
| **Short-lived credentials** | Dynamic DB creds, OIDC tokens, SSH certs (minutes-hours) | Implemented |
| **Least privilege access** | Per-workload Vault policies, scoped K8s service accounts | Implemented |
| **Encrypt secrets at rest** | SOPS + Cloud KMS, Vault seal encryption | Implemented |
| **Encrypt secrets in transit** | TLS 1.2+ for all credential delivery | Implemented |
| **Audit all secret access** | Vault audit backend, cloud KMS audit logs | Implemented |
| **Rotate secrets regularly** | TTL-based auto-expiry, rotation scripts | Implemented |
| **Use environment-specific secrets** | Separate KMS keys, Vault paths, namespaces per env | Implemented |
| **Never log secrets** | Vault audit masking, no plaintext in CI logs | Implemented |
| **Detect secrets in code** | gitleaks, custom pre-commit, CI scanning | Implemented |
| **Use dynamic secrets where possible** | Vault database engine, OIDC federation | Implemented |
| **Implement break-glass procedures** | Dual-control escrow, tested recovery, rotation after use | Implemented |
| **Separate secret management from application code** | External Secrets, CSI, Vault Agent delivery | Implemented |
| **Manage machine identities** | K8s service accounts, SPIFFE IDs, mTLS certs | Implemented |
| **Use hardware-backed key storage** | Cloud KMS with HSM option, FIDO2 for humans | Implemented |

## OWASP Top 10 (2021) — Secrets-Related Risks

| Risk | How Secrets Mismanagement Contributes | Architecture Mitigation |
|------|--------------------------------------|------------------------|
| **A01: Broken Access Control** | Overly permissive API keys, shared credentials | Least-privilege Vault policies, one SA per app, scoped tokens |
| **A02: Cryptographic Failures** | Weak key management, plaintext secrets, poor key rotation | Cloud KMS, SOPS, automated rotation, TTL enforcement |
| **A03: Injection** | Connection strings with elevated privileges | Dynamic credentials with minimal grants, parameterized queries |
| **A04: Insecure Design** | No separation of secret planes, shared keys | Three-plane architecture, environment separation |
| **A05: Security Misconfiguration** | Default credentials, exposed admin interfaces | No default passwords, Vault ACLs, network policies |
| **A06: Vulnerable/Outdated Components** | Compromised dependencies accessing secrets | Container isolation, no secrets in images, runtime-only delivery |
| **A07: Identification and Authentication Failures** | Static API keys, weak authentication | OIDC/SSO, phishing-resistant MFA, short-lived tokens |
| **A08: Software and Data Integrity Failures** | Tampered CI credentials, unsigned artifacts | OIDC CI federation, claim-based trust, artifact signing (future) |
| **A09: Security Logging and Monitoring Failures** | No audit trail for credential access | Vault audit, cloud audit, credential age reporting |
| **A10: Server-Side Request Forgery** | SSRF to metadata APIs for credential theft | Network policies, IMDS v2, no static cloud credentials |

## OWASP Application Security Verification Standard (ASVS) v4.0

### V2: Authentication

| Requirement | Level | Architecture Implementation |
|-------------|-------|---------------------------|
| 2.1.1 | L1 | Passwords >= 12 chars (enforced by IdP) |
| 2.2.1 | L1 | Anti-automation on auth (IdP rate limiting) |
| 2.5.4 | L1 | No shared/default credentials (dynamic creds) |
| 2.7.1 | L1 | OTP/MFA for privileged access (IdP enforcement) |
| 2.8.1 | L2 | Time-based tokens (Vault TTL enforcement) |
| 2.10.1 | L2 | No hardcoded service credentials (Vault dynamic) |
| 2.10.2 | L2 | Service credentials rotated (TTL-based) |
| 2.10.3 | L2 | API keys scoped to least privilege (Vault policies) |
| 2.10.4 | L3 | No service credentials in code (SOPS, pre-commit) |

### V3: Session Management

| Requirement | Level | Architecture Implementation |
|-------------|-------|---------------------------|
| 3.1.1 | L1 | Session expiry enforced (Vault token TTL) |
| 3.3.1 | L1 | Logout invalidates session (Vault token revoke) |
| 3.5.2 | L2 | Token-based sessions (Vault/OIDC tokens) |
| 3.7.1 | L1 | Session timeout for idle (Vault token use-limit) |

### V6: Stored Cryptography

| Requirement | Level | Architecture Implementation |
|-------------|-------|---------------------------|
| 6.1.1 | L1 | Regulated data encrypted at rest (SOPS, KMS) |
| 6.2.1 | L1 | Approved algorithms (AES-256 via KMS) |
| 6.2.3 | L2 | Random values from CSPRNG (cloud KMS, Vault) |
| 6.3.1 | L2 | Key management process defined (KMS + Vault) |
| 6.3.2 | L2 | Symmetric key rotation possible (SOPS key rotation) |
| 6.4.1 | L1 | Key management solution in use (Cloud KMS) |
| 6.4.2 | L2 | Hardware-backed key storage available (HSM option) |

### V10: Malicious Code

| Requirement | Level | Architecture Implementation |
|-------------|-------|---------------------------|
| 10.3.1 | L1 | No hardcoded credentials (pre-commit enforcement) |
| 10.3.2 | L2 | No hidden backdoor accounts (dynamic credentials) |

### V14: Configuration

| Requirement | Level | Architecture Implementation |
|-------------|-------|---------------------------|
| 14.1.1 | L1 | Separate config from code (SOPS, external delivery) |
| 14.2.2 | L2 | No unnecessary features in prod (scoped policies) |
| 14.3.3 | L1 | Secrets not in environment variables or config files unencrypted (SOPS) |

## OWASP Kubernetes Security Cheat Sheet

| Recommendation | Architecture Implementation |
|---------------|---------------------------|
| Use Kubernetes Secrets only via external operators | External Secrets Operator, CSI driver |
| Encrypt etcd | Kubernetes encryption at rest (cluster config) |
| Use RBAC to limit Secret access | Namespace isolation, per-app service accounts |
| Avoid mounting default service account | Kyverno policy to block default SA |
| Use network policies | Default deny-all, explicit allow for secret stores |
| Rotate credentials automatically | Vault TTL, ESO refresh interval |
| Audit Secret access | Kubernetes audit logs, Vault audit |
| Use admission controllers for policy | Kyverno policies for secret management compliance |
| Separate namespaces per environment | dev/staging/prod namespace isolation |
| Limit secret scope to namespace | Namespace-scoped SecretStores preferred |

## OWASP DevSecOps Guidelines — CI/CD Security

| Guideline | Architecture Implementation |
|-----------|---------------------------|
| No secrets in CI configuration | OIDC federation, no stored deployment secrets |
| Ephemeral CI credentials | GitHub OIDC tokens with minute-level TTL |
| Branch-scoped CI access | OIDC claim restrictions on repo, branch, environment |
| Scan for secrets in PRs | CI workflow with gitleaks on every PR |
| Signed commits and artifacts | Branch protection, artifact signing (future) |
| Environment-based deployment gates | GitHub environment protection rules |
| Immutable CI runners | Ephemeral GitHub-hosted runners, no persistent state |
