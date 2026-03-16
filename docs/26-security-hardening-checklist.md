# Security Hardening Checklist

Comprehensive checklist for hardening all components of the secrets and identity architecture. Each item includes a status column for tracking and a reference to the relevant control, document, or tool.

Status legend: `[ ]` Not started | `[~]` In progress | `[x]` Complete | `[N/A]` Not applicable

---

## 1. Vault Hardening (33 items)

### 1.1 Access Control

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| V-01 | Root token is generated only during ceremonies and revoked immediately after | `[ ]` | `docs/18-key-ceremony-guide.md` |
| V-02 | No long-lived root tokens exist in any environment | `[ ]` | `vault list auth/token/accessors` -- audit for root policy |
| V-03 | All Vault policies follow least-privilege (no `path "*"` with broad capabilities) | `[ ]` | `platform/vault/policies/` |
| V-04 | Wildcard paths (`+` or `*`) are justified and documented in policy comments | `[ ]` | Policy review checklist |
| V-05 | `sudo` capability is restricted to break-glass policies only | `[ ]` | `platform/vault/sentinel/` |
| V-06 | Sentinel policies enforce governance rules (if Vault Enterprise) | `[ ]` | `platform/vault/sentinel/` |
| V-07 | Default policy does not grant any secret read access | `[ ]` | `vault policy read default` |
| V-08 | Token TTLs are set appropriately (max 24h for service, 8h for human) | `[ ]` | Auth method `default_lease_ttl` / `max_lease_ttl` |
| V-09 | Orphan token creation is restricted | `[ ]` | Check `token_no_parent` in auth configs |
| V-10 | Response wrapping is used for initial secret distribution | `[ ]` | Vault client config |

### 1.2 Authentication

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| V-11 | OIDC/JWT auth for humans is bound to specific audiences and issuers | `[ ]` | `vault read auth/oidc/config` |
| V-12 | Kubernetes auth is scoped per namespace and service account | `[ ]` | `vault read auth/kubernetes/role/<role>` |
| V-13 | AppRole auth has `bind_secret_id=true` and `secret_id_num_uses=1` for CI | `[ ]` | `vault read auth/approle/role/<role>` |
| V-14 | JWT auth for CI has `bound_claims` restricting repository and branch | `[ ]` | C2 in `docs/06-controls-and-guardrails.md` |
| V-15 | All unused auth methods are disabled | `[ ]` | `vault auth list` |
| V-16 | Userpass auth is disabled (use OIDC/LDAP instead) | `[ ]` | `vault auth list` |

### 1.3 Audit and Logging

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| V-17 | At least one audit device is enabled | `[ ]` | `vault audit list` |
| V-18 | Audit log is written to durable storage (not just local file) | `[ ]` | Forward to SIEM |
| V-19 | Audit log HMAC keys are rotated periodically | `[ ]` | `vault operator key-status` |
| V-20 | Audit log captures all requests and responses (no filtered paths) | `[ ]` | Verify audit device options |
| V-21 | Vault audit log alerts are configured for sensitive operations | `[ ]` | SIEM rules: root login, policy change, seal/unseal |

### 1.4 Seal and Storage

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| V-22 | Auto-unseal is configured with cloud KMS (not Shamir for production) | `[ ]` | `vault status` -- check seal type |
| V-23 | Shamir keys (if used) are split 3-of-5 minimum | `[ ]` | `docs/18-key-ceremony-guide.md` |
| V-24 | Storage backend has encryption at rest enabled | `[ ]` | Consul/Raft/cloud storage encryption config |
| V-25 | Storage backend has regular backups with tested restore | `[ ]` | Backup schedule + restore drill date |
| V-26 | Raft snapshots (if Raft storage) are encrypted and access-controlled | `[ ]` | `vault operator raft snapshot` |

### 1.5 Network and TLS

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| V-27 | Vault listener uses TLS (never plain HTTP in any environment) | `[ ]` | `vault status` -- check API address scheme |
| V-28 | TLS certificate is from internal CA, not self-signed | `[ ]` | `docs/16-mtls-workload-identity-guide.md` |
| V-29 | `tls_disable_client_certs` is false where mTLS is feasible | `[ ]` | Vault server config |
| V-30 | Vault API is not exposed to the public internet | `[ ]` | Network policy / firewall rules |
| V-31 | Cluster-to-cluster Vault replication uses mTLS (if Enterprise) | `[ ]` | Replication config |

### 1.6 Secrets Engines

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| V-32 | Dynamic secrets are used instead of static where the backend supports it | `[ ]` | Database, AWS, Azure, GCP secrets engines |
| V-33 | KV v2 secrets have `max_versions` set to limit history | `[ ]` | `vault read <kv-mount>/config` |

---

## 2. SOPS Hardening (12 items)

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| S-01 | `.sops.yaml` exists at repo root with creation rules for all environments | `[ ]` | `docs/15-sops-bootstrap-guide.md` |
| S-02 | Production creation rules use cloud KMS (not age-only) | `[ ]` | `.sops.yaml` -- prod rules |
| S-03 | Break-glass age key is included as recipient on every rule | `[ ]` | `.sops.yaml` -- all rules |
| S-04 | `encrypted_regex` covers all sensitive field names used in configs | `[ ]` | Audit against actual secret field names |
| S-05 | Break-glass age private key is stored offline in split custody | `[ ]` | `docs/15-sops-bootstrap-guide.md` section 3 |
| S-06 | Developer age private keys are stored only at `~/.config/sops/age/keys.txt` | `[ ]` | No copies in repo, cloud, or shared storage |
| S-07 | SOPS creation rules enforce per-environment key separation | `[ ]` | Dev/staging/prod have different KMS keys and recipients |
| S-08 | Re-encryption is performed after every recipient change | `[ ]` | `tools/rotate/rotate_sops_keys.sh` |
| S-09 | `.sops.yaml` changes require PR review (CODEOWNERS enforced) | `[ ]` | `.github/CODEOWNERS` |
| S-10 | Pre-commit hook blocks plaintext secrets in `secrets/` paths | `[ ]` | `bootstrap/scripts/check_no_plaintext_secrets.sh` |
| S-11 | CI validates SOPS decryption after every `.sops.yaml` change | `[ ]` | CI pipeline config |
| S-12 | MAC verification is never globally disabled (`--ignore-mac` not in scripts) | `[ ]` | Grep scripts for `--ignore-mac` |

---

## 3. CI/CD Hardening (18 items)

### 3.1 Authentication and Secrets

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| CI-01 | No long-lived cloud credentials stored as CI secrets | `[ ]` | C2 in `docs/06-controls-and-guardrails.md` |
| CI-02 | OIDC federation is used for cloud and Vault authentication | `[ ]` | `platform/github-actions/`, `platform/gitlab-ci/` |
| CI-03 | OIDC subject claims are scoped to specific repository and branch | `[ ]` | `bound_claims` on Vault JWT role |
| CI-04 | Environment protection rules require reviewer approval for production | `[ ]` | GitHub/GitLab environment settings |
| CI-05 | CI secrets are scoped to environments (not org/repo-wide for prod secrets) | `[ ]` | CI platform secret configuration |
| CI-06 | Secret masking is enabled for all CI platforms | `[ ]` | Platform-specific masking config |

### 3.2 Pipeline Integrity

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| CI-07 | Workflow files (`.github/workflows/`, `.gitlab-ci.yml`) are protected by CODEOWNERS | `[ ]` | `.github/CODEOWNERS` |
| CI-08 | Third-party actions/steps are pinned to commit SHA (not tag) | `[ ]` | `@sha256:...` or `@<commit-hash>` |
| CI-09 | Fork PRs cannot access production secrets or deploy to production | `[ ]` | CI platform fork policy |
| CI-10 | Container images are signed after build (`tools/signing/`) | `[ ]` | `tools/signing/`, cosign config |
| CI-11 | Image digests (not tags) are used for production deployments | `[ ]` | Deployment manifests use `@sha256:` |
| CI-12 | Dependency scanning runs on every PR (SCA/SBOM generation) | `[ ]` | CI pipeline config |

### 3.3 Runner Security

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| CI-13 | Self-hosted runners are ephemeral (destroyed after each job) | `[ ]` | Runner configuration |
| CI-14 | Self-hosted runners do not run in privileged mode | `[ ]` | Container/VM configuration |
| CI-15 | Runner images are hardened and regularly rebuilt | `[ ]` | Base image update schedule |
| CI-16 | Runners have no ambient cloud credentials (OIDC only) | `[ ]` | Instance metadata / role bindings |
| CI-17 | Runner network egress is restricted to required endpoints | `[ ]` | Network policy / firewall |
| CI-18 | CI platform audit logs are forwarded to SIEM | `[ ]` | GitHub audit log streaming / GitLab audit events |

---

## 4. Network and Transport (12 items)

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| N-01 | All service-to-service communication uses mTLS | `[ ]` | `docs/16-mtls-workload-identity-guide.md` |
| N-02 | TLS 1.2 is the minimum version; TLS 1.3 preferred | `[ ]` | Load balancer / ingress config |
| N-03 | Weak cipher suites are disabled (no RC4, 3DES, NULL, export) | `[ ]` | TLS configuration audit |
| N-04 | Certificate validity periods are short (90 days max for leaf certs) | `[ ]` | Vault PKI role `max_ttl` |
| N-05 | OCSP stapling or short CRL publication is enabled | `[ ]` | CA / web server config |
| N-06 | Kubernetes network policies restrict pod-to-pod and pod-to-external traffic | `[ ]` | NetworkPolicy resources per namespace |
| N-07 | Vault API is accessible only from authorized networks | `[ ]` | Firewall / security group rules |
| N-08 | Secrets are never transmitted in URL query parameters | `[ ]` | Application code review |
| N-09 | Internal DNS uses split-horizon (no internal hostnames resolvable externally) | `[ ]` | DNS configuration |
| N-10 | Egress filtering blocks unauthorized outbound connections from workloads | `[ ]` | Network policy / proxy config |
| N-11 | etcd traffic is encrypted (TLS peer and client) | `[ ]` | Kubernetes etcd configuration |
| N-12 | Kubernetes API server uses TLS with a certificate from internal CA | `[ ]` | kubeadm / managed K8s config |

---

## 5. Monitoring and Alerting (13 items)

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| M-01 | Vault audit log alerts for: root token use, policy changes, seal/unseal events | `[ ]` | SIEM correlation rules |
| M-02 | Vault audit log alerts for: bulk secret reads, unusual auth patterns | `[ ]` | SIEM anomaly detection |
| M-03 | Secret scanner alerts (gitleaks, GitHub Advanced Security) route to security team | `[ ]` | Alert routing configuration |
| M-04 | Certificate expiry monitoring alerts at 30, 14, and 7 days before expiry | `[ ]` | `tools/secrets-doctor/`, monitoring stack |
| M-05 | SOPS decryption failures generate alerts | `[ ]` | CI pipeline failure notifications |
| M-06 | CI pipeline anomaly detection (unusual run times, unexpected branches, new actors) | `[ ]` | CI platform + SIEM integration |
| M-07 | Kubernetes audit log captures secret access events | `[ ]` | K8s audit policy with Secret resource logging |
| M-08 | Cloud IAM anomaly detection is enabled (GuardDuty, Azure Defender, GCP SCC) | `[ ]` | Cloud security service configuration |
| M-09 | Break-glass activation generates a P0 alert to security team | `[ ]` | Alert configuration for break-glass log events |
| M-10 | Secrets-doctor health check runs on a schedule (daily or weekly) | `[ ]` | `tools/secrets-doctor/`, cron/scheduled pipeline |
| M-11 | Identity inventory runs on a schedule to detect credential sprawl | `[ ]` | `tools/audit/`, cron/scheduled pipeline |
| M-12 | Alert fatigue management: alerts are tuned, false positives are addressed | `[ ]` | Quarterly alert review |
| M-13 | Dashboards exist for: Vault health, cert expiry, secret age, scan results | `[ ]` | Grafana / monitoring platform |

---

## 6. Operational Security (14 items)

### 6.1 Access Management

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| O-01 | All human admin access is via IdP with phishing-resistant MFA | `[ ]` | C5 in `docs/06-controls-and-guardrails.md` |
| O-02 | SSH access uses CA-signed certificates, not personal key files | `[ ]` | T5 mitigations in `docs/07-threat-model.md` |
| O-03 | Break-glass procedure is tested quarterly | `[ ]` | `docs/incident-playbooks/break-glass-procedure.md` -- drill section |
| O-04 | Break-glass materials are rotated after every real use and every drill | `[ ]` | Post-drill checklist |
| O-05 | Service accounts have defined owners, purposes, TTLs, and rotation plans | `[ ]` | C3 in `docs/06-controls-and-guardrails.md` |

### 6.2 Secret Lifecycle

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| O-06 | All secrets have a defined rotation schedule | `[ ]` | `tools/audit/` credential age report |
| O-07 | Rotation scripts are tested and alert on failure | `[ ]` | `tools/rotate/`, monitoring |
| O-08 | Deprovisioned users have all credentials revoked within 24 hours | `[ ]` | Offboarding runbook |
| O-09 | NHI (non-human identity) inventory is maintained and current | `[ ]` | `tools/audit/` identity inventory |
| O-10 | Third-party API keys have documented owners and rotation procedures | `[ ]` | Vendor credential register |

### 6.3 Incident Readiness

| # | Check | Status | Notes / Reference |
|---|-------|--------|-------------------|
| O-11 | Incident response playbooks are documented and accessible | `[ ]` | `docs/25-incident-playbooks.md` |
| O-12 | SIRM framework is tested with a tabletop exercise at least annually | `[ ]` | `docs/19-sirm-framework.md` |
| O-13 | Evidence collection procedures are documented and practiced | `[ ]` | SIRM evidence management section |
| O-14 | Post-incident review template is available and used consistently | `[ ]` | `docs/incident-playbooks/secret-exposure-response.md` -- Phase 4 |

---

## Checklist Usage

### Initial Assessment

1. Work through each section sequentially
2. Mark each item with current status
3. For items marked `[x]`, record the verification date in the Notes column
4. For items marked `[ ]`, create a remediation task with priority and owner

### Ongoing Maintenance

- Review the full checklist quarterly
- Review Vault and CI/CD sections after any infrastructure change
- Review SOPS section after any key management change
- Review monitoring section after any alerting change
- Attach completed checklists to SIRM sessions as compliance evidence

### Priority Matrix

| Priority | Criteria | Target Completion |
|----------|----------|-------------------|
| P0 | Root token, admin credential, or break-glass deficiency | Immediate |
| P1 | Production secret access control or rotation gap | 1 week |
| P2 | Monitoring or alerting gap | 2 weeks |
| P3 | Documentation or process improvement | 1 month |

## Related Documents

- Controls and guardrails: `docs/06-controls-and-guardrails.md`
- Threat model: `docs/07-threat-model.md`
- Attack trees: `docs/24-attack-trees.md`
- Incident playbooks: `docs/25-incident-playbooks.md`
- SIRM framework: `docs/19-sirm-framework.md`
- SOPS bootstrap guide: `docs/15-sops-bootstrap-guide.md`
- mTLS guide: `docs/16-mtls-workload-identity-guide.md`
- Key ceremony guide: `docs/18-key-ceremony-guide.md`
- Compliance mapping: `docs/14-compliance-mapping.md`
