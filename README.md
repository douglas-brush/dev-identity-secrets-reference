# Dev Identity & Secrets Reference Architecture

**Stop copying and pasting API keys. Stop sharing secrets in Slack. Stop pretending `.env` files are secure.**

This repository is a production-ready reference architecture for centralized **developer identity**, **PKI**, **secrets management**, and **credential lifecycle** across developer workstations, CI/CD, Kubernetes, VMs, and administrative operations.

It is designed to be forked, adapted, and deployed — not just read.

---

## The Problem

Every organization fails the same way:

| Anti-Pattern | What Actually Happens |
|-------------|----------------------|
| Long-lived API keys on laptops | Keys outlive projects, people, and even the company |
| Static secrets in CI/CD | `DEPLOY_TOKEN` set once, never rotated, used by everything |
| `.env` files in Slack/email | "Just send me the creds" — now in 4 message logs forever |
| Shared SSH keys | One key, five people, zero attribution, no revocation |
| Kubernetes Secret sprawl | 47 secrets in the cluster, nobody knows who owns them |
| Break-glass = "call Dave" | Dave is on vacation. Dave quit. Dave's laptop is in a cab. |

This repository eliminates these patterns with a brokered trust architecture where credentials are **centrally issued**, **short-lived**, **scoped**, and **auditable**.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        IDENTITY PLANE                               │
│  IdP (Entra/Okta) → MFA → Device Posture → PIM/PAM → Role Grant   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ authenticated identity
┌──────────────────────────────▼──────────────────────────────────────┐
│                    SECRETS & CRYPTO PLANE                            │
│  Vault ←→ Cloud KMS ←→ SOPS ←→ PKI CA ←→ Transit                  │
│  (dynamic creds, SSH CA, cert signing, encryption-as-a-service)     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ scoped, short-lived credentials
┌──────────────────────────────▼──────────────────────────────────────┐
│                    RUNTIME DELIVERY PLANE                            │
│  GitHub OIDC │ External Secrets │ CSI Driver │ cert-manager │       │
│  Vault Agent │ SSH CA           │ Cloud IAM  │ SPIFFE/SPIRE │       │
└─────────────────────────────────────────────────────────────────────┘
```

Three planes, deliberately separated:

1. **Identity Plane** — Who is asking, from what device, with what role?
2. **Secrets & Crypto Plane** — What exists, who may use it, for how long?
3. **Runtime Delivery Plane** — How does a workload get what it needs without storing it?

---

## What's In This Repo

```
dev-identity-secrets-reference/
├── docs/                          # Architecture, threat model, user stories, MVP plan
│   ├── compliance/                # NIST, ISO 27001, OWASP, CSA, CIS, SOC2, PCI DSS, CISA ZT
│   └── incident-playbooks/        # Secret exposure response, break-glass procedures
├── diagrams/                      # Mermaid architecture diagrams and decision trees
├── platform/
│   ├── vault/                     # Server config, policies, auth methods, examples
│   │   ├── config/                # Production server, Vault Agent (K8s + VM)
│   │   ├── policies/              # 8 least-privilege policies
│   │   └── examples/              # Complete setup scripts, roles, engines
│   ├── terraform/                 # IaC modules for all three clouds + Vault
│   │   └── modules/
│   │       ├── aws-kms-oidc/      # KMS + GitHub OIDC + IAM roles
│   │       ├── azure-keyvault-oidc/ # Key Vault + federated identity
│   │       ├── gcp-kms-oidc/      # Cloud KMS + Workload Identity
│   │       └── vault-setup/       # Complete Vault configuration via Terraform
│   ├── kubernetes/                # Production manifests
│   │   ├── external-secrets/      # ESO stores for Vault, AWS, Azure, GCP
│   │   ├── csi/                   # Secrets Store CSI for Vault + AWS
│   │   ├── cert-manager/          # Issuers, certificates, CSI driver
│   │   ├── spiffe/                # SPIRE server, agent, CSI, ClusterSPIFFEID
│   │   ├── kyverno/               # 5 admission policies for secrets compliance
│   │   └── network-policies/      # Default deny + allow rules for secret stores
│   ├── github-actions/            # Reusable workflows + cloud-specific examples
│   │   ├── reusable/              # OIDC auth, secret scanning, SOPS decrypt
│   │   └── workflows/             # Full examples: Vault, AWS, Azure, GCP, deploy
│   ├── local-dev/                 # direnv, env templates, encrypted config examples
│   └── devcontainer/              # Zero-secret container with post-create bootstrap
├── bootstrap/scripts/             # Developer automation
│   ├── bootstrap_dev.sh           # Complete workstation setup
│   ├── check_no_plaintext_secrets.sh  # 15+ secret pattern scanner
│   ├── vault_login_oidc.sh        # Vault OIDC auth with token management
│   ├── fetch_dev_env.sh           # Dynamic secret retrieval to temp files
│   └── onboard_app.sh             # Application onboarding automation
├── tools/
│   ├── secrets-doctor/            # Diagnostic CLI: deps, SOPS, Vault, K8s, git health
│   ├── rotate/                    # SOPS key rotation automation
│   └── audit/                     # Credential age reporting
├── tests/
│   ├── opa/                       # Rego policies for secrets + CI compliance
│   ├── compliance/                # Control objective validation scripts
│   └── integration/               # Vault dynamic credential tests
├── examples/
│   ├── app/                       # K8s app with ESO + CSI + encrypted Helm values
│   ├── vm/                        # Cloud-init + systemd + Vault Agent patterns
│   └── policies/                  # Branch protection checklist
├── secrets/                       # SOPS-encrypted secrets (dev/staging/prod)
├── .github/
│   ├── workflows/                 # CI: secret scanning, validation, secrets-doctor
│   └── ISSUE_TEMPLATE/            # Secret exposure report, app onboarding request
├── .sops.yaml                     # Multi-environment SOPS configuration
├── .pre-commit-config.yaml        # gitleaks + custom hooks + shellcheck + terraform
└── Makefile                       # validate, scan, audit, test, doctor, diagrams
```

---

## Credential Lifecycle — No More Static Keys

| Credential Type | Source | Lifetime | Delivery | Replaces |
|----------------|--------|----------|----------|----------|
| Human admin session | IdP / PIM | Minutes-hours | SSO | Static cloud keys |
| CI cloud auth | OIDC federation | Minutes | Token exchange | Stored deployment secrets |
| Database creds | Vault dynamic | Minutes-hours | API/CSI/Agent | Static DB passwords |
| App API secrets | Vault KV + rotation | Rotated by policy | ESO/CSI | `.env` files in Slack |
| Workload mTLS cert | cert-manager | Hours-days | cert-manager CSI | Self-signed certs |
| SSH admin access | SSH CA | Minutes-hours | Signed certificate | Shared private keys |
| Repo encryption | SOPS + KMS | Persistent master | Git encrypted | Plaintext config files |

---

## Quick Start

### 1. Fork and Configure

```bash
# Clone
git clone https://github.com/BrushCyber/dev-identity-secrets-reference.git
cd dev-identity-secrets-reference

# Install hooks
make setup

# Run diagnostics
make doctor
```

### 2. Replace Placeholders

Update `.sops.yaml` with your actual KMS ARNs/Key Vault URLs, then:

```bash
# Scan for remaining placeholders
grep -rn "REPLACE\|example\.internal\|111122223333" platform/ bootstrap/ .sops.yaml
```

### 3. Choose Your Pattern

| If You Have... | Start With |
|----------------|-----------|
| Microsoft + Azure | [Pattern A](docs/10-vendor-and-pattern-profiles.md) — Entra + Key Vault + Vault |
| Multi-cloud | [Pattern B](docs/10-vendor-and-pattern-profiles.md) — Okta + Vault + multi-KMS |
| Small team, one cloud | [Pattern C](docs/10-vendor-and-pattern-profiles.md) — Cloud-native + SOPS |

### 4. Deploy Infrastructure

```bash
# AWS
cd platform/terraform/environments/dev
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars
terraform init && terraform apply

# Azure / GCP — same pattern with respective modules
```

### 5. Bootstrap Developer Workstations

```bash
export VAULT_ADDR=https://vault.your-domain.com
./bootstrap/scripts/bootstrap_dev.sh
```

### 6. Onboard Applications

```bash
./bootstrap/scripts/onboard_app.sh my-api dev --delivery eso --cert --db-role
```

---

## Compliance Coverage

This architecture maps to major security frameworks with documented control-by-control coverage:

| Framework | Document | Key Areas |
|-----------|----------|-----------|
| **NIST SP 800-53 Rev 5** | [nist-mapping.md](docs/compliance/nist-mapping.md) | AC, IA, SC, AU families — 50+ controls |
| **ISO 27001:2022** | [iso-mapping.md](docs/compliance/iso-mapping.md) | Annex A controls + ISO 27002 key management |
| **OWASP** | [owasp-mapping.md](docs/compliance/owasp-mapping.md) | Secrets Cheat Sheet, ASVS, Top 10, K8s Security |
| **CSA CCM v4** | [csa-mapping.md](docs/compliance/csa-mapping.md) | IAM, CEK, DSP domains |
| **CIS Controls v8** | [cis-sans-mapping.md](docs/compliance/cis-sans-mapping.md) | IG1-IG3 + K8s/Vault benchmarks |
| **SOC 2 / PCI DSS 4.0** | [soc2-pci-mapping.md](docs/compliance/soc2-pci-mapping.md) | Trust criteria + Requirements 3,6,7,8,10 |
| **CISA Zero Trust** | [cisa-zero-trust.md](docs/compliance/cisa-zero-trust.md) | All 5 pillars — Advanced maturity |

---

## Non-Negotiables

These are not recommendations. They are requirements.

- **No static cloud credentials in CI.** Use OIDC federation.
- **No plaintext secrets in Git.** Use SOPS + cloud KMS.
- **No shared admin SSH keys.** Use SSH CA or access broker.
- **No unbounded service account access.** One SA per app, least privilege.
- **No single CA signing everything.** Separate intermediates by purpose.
- **No untested break-glass.** Drill quarterly, rotate after test.

---

## Tools Included

### `secrets-doctor` — Repository Health Diagnostic

```bash
./tools/secrets-doctor/doctor.sh          # Full diagnostic
./tools/secrets-doctor/doctor.sh deps     # Check tool dependencies
./tools/secrets-doctor/doctor.sh sops     # Validate SOPS config
./tools/secrets-doctor/doctor.sh vault    # Check Vault connectivity
./tools/secrets-doctor/doctor.sh k8s      # Audit Kubernetes secrets
./tools/secrets-doctor/doctor.sh git      # Validate git security
```

### Secret Scanning

```bash
make scan                                 # Run secret scanner
make validate                             # Full validation suite
make test                                 # OPA policies + compliance checks
make audit                                # Full security audit
```

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure `make validate` passes
4. Submit a PR

All contributions must pass the pre-commit hooks (secret scanning, shellcheck, YAML validation).

---

## References

- [Architecture Documentation](docs/02-reference-architecture.md)
- [Threat Model](docs/07-threat-model.md)
- [MVP Plan](docs/05-mvp-plan.md)
- [Decision Log](docs/08-decision-log.md)
- [Official References](docs/11-references.md)

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built by [Brush Cyber](https://brushcyber.com). Because your secrets deserve better than a Slack DM.*
