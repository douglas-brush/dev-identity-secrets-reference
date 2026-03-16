# Vendor and Pattern Profiles

This document provides deployment pattern profiles for organizations at different stages, scales, and regulatory postures. Each pattern is a cohesive, tested combination of tools and practices drawn from the reference architecture. The vendor comparison matrix and decision framework at the end help teams select the right pattern for their constraints.

---

## Pattern A — Microsoft-Heavy Hybrid

### Use when

- Entra ID (formerly Azure AD) and Intune are already the primary IdP and MDM
- Developer devices are mostly Windows/macOS managed through Intune
- Internal VPN, endpoint certificates, and conditional access are Microsoft-centric
- The organization has Microsoft E3/E5 licensing and wants to maximize that investment
- Azure is the primary (but not necessarily exclusive) cloud provider

### Recommended stack

| Layer | Tool | Role |
|-------|------|------|
| Identity provider | Entra ID | SSO, conditional access, PIM for JIT admin roles |
| Device management | Intune | Compliance policies, certificate deployment, app protection |
| PKI | Microsoft Cloud PKI (BYOCA mode) | Device certificates under a unified private trust hierarchy; integrates directly with Intune SCEP/PKCS profiles |
| Secrets engine | HashiCorp Vault (or OpenBao) | Dynamic credentials, SSH CA, Transit encrypt/decrypt, database credential brokering |
| Git-encrypted secrets | SOPS | Encrypted values in-repo, decrypted at deploy time via Azure Key Vault KMS or Vault Transit |
| KMS / HSM | Azure Key Vault (Premium SKU for HSM-backed keys) | Root-of-trust for SOPS, Vault auto-unseal, TLS cert storage |
| CI/CD federation | GitHub Actions OIDC → Entra ID workload identity federation | No long-lived CI secrets; short-lived tokens scoped per repo/environment |
| Runtime delivery | External Secrets Operator or CSI Secrets Store Driver | Sync secrets from Vault or Azure Key Vault into Kubernetes pods |
| Certificate lifecycle | cert-manager with Vault PKI or ACME issuer | Automated TLS rotation for cluster workloads |

### Architecture notes

- **Conditional access as a gate**: Entra conditional access policies enforce device compliance (Intune-managed, disk encrypted, OS patched) before granting access to Vault, Azure resources, or internal portals. This creates a hardware-attested trust chain from device to workload.
- **BYOCA Cloud PKI**: Bring Your Own CA mode lets you anchor Microsoft Cloud PKI under your existing private root CA. This means Intune-distributed device certificates and Vault-issued workload certificates share a common trust hierarchy, simplifying mTLS validation across the estate.
- **Vault as the dynamic layer**: Azure Key Vault handles static secrets and KMS well, but lacks dynamic credential generation. Vault fills this gap with database secret engines (PostgreSQL, MySQL, MSSQL), SSH certificate signing, and Transit encryption-as-a-service.
- **SOPS + Azure Key Vault KMS**: Developers encrypt secrets in Git using SOPS with Azure Key Vault as the KMS backend. Decryption happens only in CI/CD pipelines or at deploy time, never on developer laptops.

### Tradeoffs

- Heavy Microsoft licensing dependency (E3/E5 costs)
- Cloud PKI is relatively new; some edge cases may require ADCS fallback
- Vault adds operational overhead beyond what pure Azure Key Vault provides
- Works best when Azure is the primary cloud; multi-cloud adds complexity

---

## Pattern B — Multi-Cloud Platform Team

### Use when

- Workloads span two or more of AWS, Azure, and GCP
- The platform team needs a cloud-agnostic secrets and identity layer
- Both container orchestrators (Kubernetes) and VM workloads exist
- Portability and vendor independence are explicit requirements
- The team has (or is building) platform engineering capability

### Recommended stack

| Layer | Tool | Role |
|-------|------|------|
| Identity provider | Entra ID or Okta | Centralized SSO, SCIM provisioning to all downstream systems |
| Secrets engine | HashiCorp Vault (HA cluster) | Single control plane for secrets across all clouds; dynamic credentials, PKI, Transit, SSH CA |
| Git-encrypted secrets | SOPS | Per-environment encryption using cloud-specific KMS keys (AWS KMS in prod-aws, Azure Key Vault in prod-azure, GCP KMS in prod-gcp) |
| KMS | Cloud-native KMS per environment | Vault auto-unseal, SOPS encryption, envelope encryption for data-at-rest |
| CI/CD federation | GitHub Actions OIDC → target cloud IAM + Vault JWT auth | Separate trust chains per cloud; CI jobs get cloud-specific and Vault-specific tokens |
| Runtime delivery | External Secrets Operator (Kubernetes) + Vault Agent (VMs) | ESO for K8s workloads; Vault Agent sidecar or envconsul for VM/bare-metal |
| Certificate lifecycle | cert-manager + Vault PKI backend | Vault acts as intermediate CA; cert-manager requests short-lived certs per workload |
| Workload identity | SPIFFE/SPIRE (optional, phase 2+) | Cryptographic workload identity across clouds and runtimes; removes reliance on network-based trust |
| Policy | OPA/Gatekeeper | Enforce secret access policies, namespace isolation, label requirements |

### Architecture notes

- **Vault as the unifying abstraction**: In multi-cloud, Vault is the critical portability layer. Applications request secrets from Vault using a consistent API regardless of whether the underlying credential is an AWS IAM role, Azure service principal, or GCP service account key.
- **Cloud-specific KMS for envelope encryption**: Each cloud environment uses its native KMS for Vault auto-unseal and SOPS encryption. This keeps the root-of-trust cloud-native (benefiting from the cloud provider's HSM infrastructure) while keeping the secrets API portable.
- **SPIFFE/SPIRE for workload identity**: When workloads communicate across clouds (e.g., a service in AWS calling an API in GCP), network-based trust breaks down. SPIFFE provides cryptographic identity (SVIDs) that work regardless of network topology. This is a maturity play — implement after the core secrets layer is stable.
- **Per-environment SOPS keys**: A single SOPS file can reference different KMS keys per environment. The `prod-aws` section encrypts with AWS KMS, `prod-azure` with Azure Key Vault, and `prod-gcp` with GCP KMS. CI/CD pipelines decrypt only the section relevant to the target environment.

### Tradeoffs

- Highest operational complexity of any pattern; requires a dedicated platform team
- Vault HA cluster is a critical dependency — needs monitoring, backup, DR planning
- SPIFFE/SPIRE adds significant complexity; defer unless cross-cloud mTLS is a hard requirement
- Cost of running Vault infrastructure across regions and clouds

---

## Pattern C — Lean Startup / Small Team

### Use when

- The team is fewer than 15 engineers
- Dynamic secrets and SSH CA are not phase-one requirements
- The main need is encrypted config in Git, federated CI/CD, and runtime secret retrieval
- Operational overhead must be minimized — no one is on call for a Vault cluster
- A single cloud provider is the primary target

### Recommended stack

| Layer | Tool | Role |
|-------|------|------|
| Identity provider | Any (Entra, Okta, Google Workspace) | SSO for internal tools; SCIM if available |
| Device management | Intune, Jamf, or Kandji | Baseline device compliance; disk encryption enforcement |
| Secrets storage | Cloud-native secret manager (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) | No self-hosted infrastructure; fully managed |
| Git-encrypted secrets | SOPS | Encrypt non-secret config and bootstrap values in Git |
| KMS | Cloud-native KMS | SOPS encryption backend; managed key rotation |
| CI/CD federation | GitHub Actions OIDC → cloud IAM | Zero long-lived CI credentials |
| Runtime delivery | External Secrets Operator or CSI Secrets Store Driver | Sync cloud secrets into Kubernetes |
| Certificates | cert-manager with ACME (Let's Encrypt) or cloud CA | Automated TLS without running a CA |

### Architecture notes

- **No Vault, no problem (for now)**: For small teams, the operational cost of running Vault exceeds the benefit. Cloud-native secret managers provide adequate functionality for static secrets, and OIDC federation eliminates the need for dynamic credential generation in most CI/CD scenarios.
- **SOPS as the Git-side encryption layer**: Even without Vault, teams need a way to store encrypted configuration in Git. SOPS with cloud KMS provides this without any additional infrastructure.
- **Growth path**: This pattern is explicitly designed to evolve. When the team hits the limits (need for dynamic database credentials, SSH CA, cross-cloud portability), the migration path is to add Vault (Pattern B) or stay cloud-native and add ESO (Pattern E).

### Tradeoffs

- No dynamic secrets — database credentials are static and rotated manually or via cloud-native rotation (often limited)
- No SSH CA — SSH access relies on cloud-native solutions (AWS SSM, Azure Bastion, GCP IAP) or manual key management
- No Transit encryption-as-a-service
- Weaker when workloads span multiple clouds
- Limited audit trail compared to Vault's comprehensive audit log

### When to graduate

Move to Pattern B or E when any of these become true:
- Team grows past 15-20 engineers
- Dynamic database credentials become a compliance requirement
- Workloads span multiple clouds
- SSH CA or workload identity (SPIFFE) becomes necessary
- Audit requirements exceed what cloud-native secret managers provide

---

## Pattern D — Open-Source First

### Use when

- The organization has a policy against BSL (Business Source License) or proprietary-licensed infrastructure
- HashiCorp's license change from MPL 2.0 to BSL 1.1 (August 2023) is a blocker
- The team wants full freedom to modify, fork, and redistribute their secrets infrastructure
- Cost optimization is critical — no per-node or per-cluster licensing
- The team has Vault operational experience and wants API compatibility

### Context: The HashiCorp BSL licensing change

In August 2023, HashiCorp changed the license for Vault (and all other major products) from Mozilla Public License 2.0 (MPL 2.0) to Business Source License 1.1 (BSL 1.1). The BSL prohibits using the software in a production environment that competes with HashiCorp's commercial offerings. While this does not affect most end-user organizations, it has significant implications for:

- **Managed service providers** offering Vault-as-a-service
- **Platform vendors** embedding Vault in their product
- **Organizations with blanket OSS-only policies** that prohibit BSL/SSPL/proprietary licenses
- **Government and defense contractors** with specific license-approval requirements

In response, the Linux Foundation launched **OpenBao** in December 2023 as a community-driven fork of Vault, maintaining the MPL 2.0 license. OpenBao tracks the last MPL-licensed Vault codebase and continues independent development.

### Recommended stack

| Layer | Tool | License | Role |
|-------|------|---------|------|
| Secrets engine | OpenBao | MPL 2.0 | API-compatible Vault replacement; dynamic secrets, PKI, Transit, SSH CA |
| Git-encrypted secrets | SOPS | MPL 2.0 | Git-side encryption with any KMS backend |
| Certificate lifecycle | cert-manager | Apache 2.0 | Automated certificate issuance and rotation |
| Workload identity | SPIFFE/SPIRE | Apache 2.0 | Cryptographic workload identity |
| Policy engine | OPA (Open Policy Agent) | Apache 2.0 | Fine-grained access policy enforcement |
| Runtime delivery | External Secrets Operator | Apache 2.0 | Sync secrets from OpenBao into Kubernetes |
| KMS | Cloud-native KMS or SoftHSM | Varies | Auto-unseal, SOPS backend |
| Identity provider | Keycloak or Authentik | Apache 2.0 / MIT-variant | Fully open-source IdP (if avoiding Entra/Okta licensing) |
| CI/CD | Gitea Actions, Woodpecker, or GitHub Actions | Varies | OIDC federation to OpenBao |

### OpenBao compatibility note

OpenBao maintains API compatibility with Vault. This means:

- **All tooling in this reference architecture that references Vault works with OpenBao** — ESO, cert-manager Vault issuer, SOPS with Vault Transit, Vault Agent, envconsul, and CSI driver all function against an OpenBao endpoint.
- **Migration from Vault to OpenBao** is operationally similar to a Vault version upgrade — export/import of secrets, update endpoint URLs, re-issue leases.
- **CLI compatibility**: The `bao` CLI mirrors the `vault` CLI syntax. Many teams alias `vault` to `bao` during migration.
- **Divergence risk**: Over time, OpenBao and Vault will diverge in features. Track the OpenBao roadmap for features that may not exist in Vault and vice versa.

### Architecture notes

- **Full stack open-source**: Every component in this pattern is OSS with a permissive license (MPL 2.0, Apache 2.0, or MIT). No BSL, SSPL, or proprietary components.
- **Operational cost is real**: Open-source does not mean free. OpenBao requires the same operational investment as Vault — HA deployment, monitoring, backup, unsealing, audit log management. The difference is licensing cost and freedom, not operational complexity.
- **SPIFFE/SPIRE as the identity mesh**: Without a commercial IdP, SPIFFE/SPIRE becomes more important for workload-to-workload authentication. Combined with OPA for policy enforcement, this creates a fully open-source zero-trust layer.

### Tradeoffs

- No commercial support (unless a third-party vendor emerges for OpenBao)
- OpenBao community is smaller than Vault's; fewer tutorials, Stack Overflow answers, and consultants
- Feature parity with Vault is not guaranteed long-term
- Some enterprise Vault features (namespaces, Sentinel policies, replication) may not exist in OpenBao
- If the IdP is also open-source (Keycloak), that adds another critical system to operate

---

## Pattern E — Cloud-Native Minimal

### Use when

- The team wants zero self-hosted secrets infrastructure
- All workloads run on a single cloud provider (or each cloud manages its own secrets)
- The organization trusts cloud provider secret managers as the system of record
- Operational simplicity is the top priority
- Vault is explicitly out of scope (no budget, no expertise, no appetite for the operational overhead)

### Recommended stack

| Layer | Tool | Role |
|-------|------|------|
| Secrets storage | AWS Secrets Manager / Azure Key Vault / GCP Secret Manager | Fully managed secret storage with native IAM integration |
| Unifying layer | External Secrets Operator (ESO) | Abstracts cloud-specific APIs; syncs secrets into Kubernetes as native Secret objects |
| Git-encrypted configs | SOPS | Encrypt non-secret config values and bootstrap parameters in Git |
| KMS | Cloud-native KMS | SOPS encryption, envelope encryption, managed rotation |
| CI/CD federation | GitHub Actions OIDC → cloud IAM | Short-lived tokens; no stored credentials |
| Runtime delivery | ESO (Kubernetes) or cloud-native SDK (non-K8s) | ESO for K8s; AWS SDK / Azure SDK / GCP client libraries for Lambda, Cloud Functions, etc. |
| Certificates | cert-manager + ACME or AWS ACM / Azure App Service Managed Certs | Managed TLS; no self-hosted CA |
| Secret rotation | Cloud-native rotation (AWS Secrets Manager rotation Lambda, Azure Key Vault rotation) | Automated rotation for supported secret types (RDS credentials, service account keys) |
| Identity provider | Entra ID, Okta, or Google Workspace | SSO; provides the OIDC trust anchor for CI/CD federation |

### Architecture notes

- **ESO as the unifying abstraction**: External Secrets Operator is the key enabler. It lets Kubernetes workloads consume secrets from any cloud provider through a consistent `ExternalSecret` CRD. When teams operate across clouds, ESO provides the portability that Vault would otherwise provide — without running Vault.
- **No dynamic secrets**: Cloud-native secret managers do not generate dynamic, short-lived credentials the way Vault does. This is the primary functional gap. Mitigation strategies:
  - Use IAM roles (AWS) / managed identities (Azure) / workload identity federation (GCP) instead of secrets where possible
  - Use cloud-native rotation for supported secret types (e.g., AWS Secrets Manager + Lambda rotation for RDS passwords)
  - Accept longer-lived credentials for services that don't support IAM-native auth, with compensating controls (rotation, monitoring, least-privilege)
- **SOPS for the Git layer**: Even without Vault Transit, SOPS with cloud KMS provides secure encrypted-at-rest config in Git. This covers the common need for environment-specific configuration that shouldn't be plaintext in the repo.
- **Multi-cloud variant**: For multi-cloud, deploy ESO with multiple `SecretStore` resources — one per cloud provider. Each `ExternalSecret` references the appropriate store. This is simpler than running Vault but provides less abstraction (applications may still need to understand which cloud backs their secrets).

### Tradeoffs

- No dynamic credential generation
- No SSH CA
- No Transit encryption-as-a-service
- Cloud-native rotation support is limited to specific secret types
- Audit trails are cloud-specific and not unified
- Vendor lock-in to cloud provider secret manager APIs (mitigated by ESO abstraction at the K8s layer)
- Multi-cloud requires managing separate secret stores per cloud

---

## Pattern F — Regulated / FedRAMP

### Use when

- The organization must meet FedRAMP, FIPS 140-2/3, PCI DSS, HIPAA, or equivalent regulatory frameworks
- Hardware Security Modules (HSMs) are required for key storage and cryptographic operations
- Formal key ceremonies with split knowledge and dual control are mandatory
- Comprehensive, tamper-evident audit trails are a compliance requirement
- A Change Advisory Board (CAB) or equivalent approval workflow governs infrastructure changes

### Recommended stack

| Layer | Tool | Requirement |
|-------|------|-------------|
| Secrets engine | HashiCorp Vault Enterprise (or OpenBao with FIPS-validated TLS) | HSM auto-unseal via PKCS#11; Vault Enterprise provides FIPS 140-2 validated binary |
| HSM | AWS CloudHSM, Azure Dedicated HSM, Thales Luna, or nCipher nShield | FIPS 140-2 Level 3 validated; provides root-of-trust for all cryptographic operations |
| KMS | Cloud-native KMS backed by HSM (AWS KMS Custom Key Store, Azure Key Vault Managed HSM) | FIPS 140-2 Level 3 for key storage; Level 2 minimum for KMS operations |
| Git-encrypted secrets | SOPS with HSM-backed KMS | All encryption keys stored in FIPS-validated modules |
| Certificate lifecycle | cert-manager + Vault PKI with HSM-backed root CA | Root CA private key never leaves HSM; intermediates may be software-based with compensating controls |
| Identity provider | Entra ID (GCC High for FedRAMP) or Okta (FedRAMP authorized) | FedRAMP-authorized IdP; CAC/PIV smart card support for federal environments |
| CI/CD | GitHub Enterprise (FedRAMP authorized) or self-hosted GitLab | FedRAMP ATO required for CI/CD platform |
| Audit | Vault audit backend → immutable log storage (S3 with Object Lock, Azure Immutable Blob) | Tamper-evident, cryptographically signed audit logs with minimum 7-year retention |
| Policy | Vault Sentinel (Enterprise) or OPA | Codified approval policies; CAB workflow enforcement |
| Runtime delivery | CSI Secrets Store Driver (FIPS-validated TLS) | Secrets never written to etcd; injected directly into pod memory |

### Key ceremony requirements

Regulated environments require formal key ceremonies for root CA creation, Vault unseal key generation, and HSM initialization. The key ceremony process (detailed in `docs/18-key-ceremony-guide.md`) must include:

1. **Split knowledge**: No single person holds a complete key. Vault unseal keys use Shamir's Secret Sharing (e.g., 5 shares, threshold of 3).
2. **Dual control**: At least two authorized individuals must be present for any key operation.
3. **Ceremony documentation**: Written procedure, witness signatures, video recording (where policy requires), hash verification of all artifacts.
4. **HSM initialization**: Performed in a physically secure room with access controls. Security Officer and Crypto Officer roles assigned per PKCS#11 conventions.
5. **Key backup**: Encrypted key backup stored in a physically separate, access-controlled location. Backup recovery tested annually.

### FIPS compliance notes

- **FIPS 140-2 Level 3 for HSMs**: The HSM hardware must have NIST CMVP validation at Level 3 (physical tamper resistance). This is non-negotiable for FedRAMP High and PCI DSS.
- **FIPS-validated crypto modules**: Vault Enterprise provides a FIPS 140-2 validated binary that uses BoringCrypto (Go's FIPS-validated crypto module). OpenBao does not currently offer a FIPS-validated build — this is a key differentiator for regulated environments.
- **TLS everywhere**: All inter-component communication must use TLS 1.2+ with FIPS-approved cipher suites. Self-signed certificates are not acceptable; all certs must chain to the HSM-backed root CA.
- **Key rotation schedules**: Document and enforce rotation periods — 90 days for symmetric keys, 1 year for asymmetric keys, 2 years for root CA (with re-ceremony). Rotation must be automated where possible and audited where manual.

### CAB approval workflow

For regulated environments, infrastructure changes follow a formal Change Advisory Board process:

1. **Change request**: Engineer submits a change request (CR) describing the change, risk assessment, rollback plan, and affected systems.
2. **Security review**: Security team reviews the CR for compliance impact, secret exposure risk, and audit implications.
3. **CAB approval**: The CAB (or equivalent) approves/rejects the CR. Emergency changes follow a fast-track process with post-hoc review.
4. **Implementation window**: Changes execute during the approved maintenance window with audit logging enabled.
5. **Post-implementation review**: Verify the change, confirm audit logs captured all operations, update documentation.

Vault Sentinel policies (Enterprise) or OPA policies can codify parts of this workflow — for example, preventing secret engine mounts without an approved CR number in the metadata.

### Tradeoffs

- Highest cost of all patterns (HSM hardware/service, Vault Enterprise licensing, FedRAMP-authorized SaaS)
- Slowest velocity — CAB approvals, ceremony scheduling, and compliance documentation add days to weeks
- Requires dedicated security engineering staff with HSM and compliance expertise
- Vault Enterprise is required for FIPS binary and Sentinel policies; OpenBao may not meet FIPS requirements
- Ongoing compliance maintenance (annual audits, penetration testing, control assessments)

---

## Vendor Comparison Matrix

| Tool | Purpose | License | Self-Hosted | SaaS | FIPS 140-2 | K8s Native | CI/CD Integration | Maturity |
|------|---------|---------|:-----------:|:----:|:----------:|:----------:|:-----------------:|:--------:|
| HashiCorp Vault | Secrets engine, PKI, Transit, SSH CA | BSL 1.1 | Yes | HCP Vault | Enterprise only | Via CSI, ESO, Agent | OIDC, JWT, AppRole | High — 10+ years, massive ecosystem |
| OpenBao | Vault fork — same capabilities | MPL 2.0 | Yes | No | No | Via CSI, ESO, Agent | OIDC, JWT, AppRole | Low-Medium — active development, API-compatible with Vault |
| AWS Secrets Manager | Managed secret storage + rotation | Proprietary | No | Yes | Yes (service-level) | Via ESO | IAM roles, OIDC | High — deeply integrated with AWS |
| Azure Key Vault | Managed secrets, keys, certificates | Proprietary | No | Yes | Premium/Managed HSM | Via ESO, CSI | Managed Identity, OIDC | High — deeply integrated with Azure |
| GCP Secret Manager | Managed secret storage | Proprietary | No | Yes | Yes (service-level) | Via ESO | Workload Identity, OIDC | High — deeply integrated with GCP |
| CyberArk Conjur | Enterprise secrets management | Dual (OSS + Commercial) | Yes | Yes | Enterprise only | Via ESO, Sidecar | REST API, Summon CLI | High — enterprise focus, complex setup |
| Doppler | Secrets management platform | Proprietary | No | Yes | No | Via ESO, CLI | Native GitHub/GitLab/etc. | Medium — developer-friendly, growing adoption |
| 1Password Connect | Team secret sharing → automation | Proprietary | Partial (Connect Server) | Yes | No | Via ESO | CLI, SDK | Medium — strong for team secrets, newer for infra |
| Infisical | Open-source secrets management | MIT + Enterprise | Yes | Yes | No | Via ESO, Operator | Native integrations | Medium — fast-growing OSS alternative |
| SOPS | Git-side secret encryption | MPL 2.0 | Yes (CLI) | No | Via KMS backend | Decrypt in CI/CD | Works with any CI | High — widely adopted, stable |
| Sealed Secrets | K8s-native encrypted secrets | Apache 2.0 | Yes | No | No | Native (CRD) | Limited | Medium — K8s only, Bitnami maintained |
| External Secrets Operator | Sync external secrets → K8s Secrets | Apache 2.0 | Yes | No | N/A (transport) | Native (CRD) | Via SecretStore CRDs | High — CNCF project, broad provider support |
| cert-manager | Certificate lifecycle management | Apache 2.0 | Yes | No | Via issuer backend | Native (CRD) | Automated renewal | High — CNCF graduated, de facto standard |
| SPIFFE/SPIRE | Workload identity framework | Apache 2.0 | Yes | No | Depends on config | Via SPIRE Agent | Attestation-based | Medium — CNCF incubating, growing adoption |
| Sigstore (Cosign, Fulcio, Rekor) | Software supply chain signing | Apache 2.0 | Yes | Yes (public instance) | No | Via policy controllers | Native GitHub Actions | Medium-High — CNCF, rapidly maturing |

### Reading the matrix

- **FIPS 140-2**: "Yes" means the tool itself or its backing infrastructure has FIPS validation. "Via KMS/issuer backend" means the tool delegates crypto to a backend that may or may not be FIPS-validated.
- **K8s Native**: Indicates whether the tool has a Kubernetes-native integration (CRD, operator, controller) versus requiring a sidecar, init container, or external sync.
- **CI/CD Integration**: Primary mechanisms for authenticating CI/CD pipelines to the tool.
- **Maturity**: Subjective assessment based on age, ecosystem size, production adoption, and documentation quality.

---

## Decision Framework

Use the following decision tree to select a starting pattern. This is not a permanent choice — patterns are designed as evolutionary stages, and organizations commonly graduate from one to the next.

### Step 1: Regulatory requirements

| Regulatory posture | Patterns available | Rationale |
|--------------------|--------------------|-----------|
| FedRAMP High / DoD IL4+ | F only | HSM and FIPS binary requirements eliminate all other patterns |
| FedRAMP Moderate | F (preferred) or B with FIPS KMS | Vault Enterprise FIPS binary preferred; cloud-native KMS acceptable with documentation |
| PCI DSS | B, E, or F | Depends on scope; if HSM is required for key storage, Pattern F; otherwise B or E with compensating controls |
| HIPAA | B, C, E, or F | HIPAA requires encryption and access controls but does not mandate HSMs; any pattern with audit trails works |
| SOC 2 Type II | Any pattern | SOC 2 is control-framework based; all patterns can satisfy with proper documentation |
| No specific regulation | A, B, C, D, or E | Choose based on team and infrastructure factors below |

### Step 2: Team size and platform maturity

| Team size | Vault experience | Recommended patterns |
|-----------|------------------|----------------------|
| < 10 engineers | None | C or E — minimize operational overhead |
| < 10 engineers | Some | C, D, or E — Vault is optional at this scale |
| 10-50 engineers | None | E — cloud-native secret managers with ESO; add Vault later if needed |
| 10-50 engineers | Some | A or B — Vault adds value at this scale |
| 10-50 engineers | Expert | B or D — full Vault or OpenBao deployment justified |
| 50+ engineers | Any | B or D — platform team should own the secrets infrastructure |
| 50+ engineers (regulated) | Any | F — regulatory requirements dominate at this scale |

### Step 3: Cloud strategy

| Cloud strategy | Recommended patterns | Notes |
|----------------|----------------------|-------|
| Single cloud (AWS/Azure/GCP) | A (if Azure), C, or E | Cloud-native tools are sufficient; Vault adds complexity without multi-cloud payoff |
| Multi-cloud (2+ providers) | B or D | Vault/OpenBao as the unifying abstraction layer is the strongest multi-cloud play |
| Hybrid (cloud + on-prem) | B or F | On-prem workloads need Vault Agent or SPIRE for secret delivery; cloud-only patterns don't reach |
| On-prem only | B, D, or F | Cloud-native secret managers are unavailable; Vault or OpenBao is required |

### Step 4: Identity provider

| Existing IdP | Pattern affinity | Notes |
|--------------|------------------|-------|
| Entra ID (Azure AD) | A | Maximum synergy with Microsoft conditional access, PIM, Intune, Azure Key Vault |
| Okta | B or E | Okta is cloud-agnostic; pairs well with multi-cloud or cloud-native patterns |
| Google Workspace | E | Native integration with GCP IAM and Secret Manager |
| Keycloak / Authentik (self-hosted) | D | Open-source IdP aligns with open-source infrastructure |
| None / Starting fresh | C or E | Pick the IdP that matches your primary cloud provider |

### Step 5: Licensing philosophy

| License policy | Eligible patterns |
|----------------|-------------------|
| No restrictions | A, B, C, E, F |
| OSS-preferred but BSL acceptable | A, B, C, E, F |
| OSS-only (no BSL, no proprietary infra) | D |
| OSS-only but cloud SaaS is acceptable | D or E |

### Quick-reference decision matrix

For teams that want a single answer:

| You are... | Start with |
|------------|------------|
| A small team on AWS, no Vault experience | **Pattern E** |
| A small team on Azure with Entra ID | **Pattern A** (simplified) or **Pattern C** |
| A mid-size team going multi-cloud | **Pattern B** |
| An OSS-principled team with Vault experience | **Pattern D** |
| Regulated (FedRAMP, PCI with HSM mandate) | **Pattern F** |
| A startup that just needs encrypted secrets in Git and CI/CD federation | **Pattern C** |
| A platform team building an internal developer platform | **Pattern B** or **Pattern D** |

### Graduation paths

Patterns are not permanent. Common evolution paths:

```
C (Lean) ──→ E (Cloud-Native) ──→ B (Multi-Cloud) ──→ F (Regulated)
                                        ↑
D (Open-Source) ────────────────────────┘

A (Microsoft) ──→ B (Multi-Cloud) ──→ F (Regulated)
```

- **C → E**: Add ESO and cloud-native rotation when the team outgrows manual secret management
- **C → B**: Add Vault when dynamic secrets or SSH CA become requirements
- **E → B**: Add Vault when multi-cloud portability or dynamic credentials are needed
- **A → B**: Add non-Azure clouds; Vault becomes the unifying layer
- **B → F**: Add HSM, FIPS binary, formal key ceremonies when entering regulated markets
- **D → B**: If OpenBao gaps emerge, migrating to Vault Enterprise is straightforward due to API compatibility
