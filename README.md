# Dev Identity & Secrets Reference Architecture

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Vault](https://img.shields.io/badge/HashiCorp-Vault-7B42BC?logo=vault)](https://www.vaultproject.io/)
[![SOPS](https://img.shields.io/badge/Mozilla-SOPS-FF7139)](https://github.com/getsops/sops)
[![OPA](https://img.shields.io/badge/OPA-Policy--as--Code-7D9FC3)](https://www.openpolicyagent.org/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](lib/python/)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](lib/go/)
[![TypeScript 5.4+](https://img.shields.io/badge/TypeScript-5.4+-3178C6?logo=typescript&logoColor=white)](lib/typescript/)

**Stop copying and pasting API keys. Stop sharing secrets in Slack. Stop pretending `.env` files are secure.**

A platform-independent reference architecture for centralized **developer identity**, **PKI**, **secrets management**, and **credential lifecycle**. Covers developer workstations, CI/CD pipelines, VMs, and administrative operations.

Designed to be forked, adapted, and implemented on whatever infrastructure you run -- cloud, on-prem, hybrid. Not locked to any cloud provider, orchestrator, or IaC tool.

---

## The Problem

Every organization fails the same way:

| Anti-Pattern | What Actually Happens |
|---|---|
| Long-lived API keys on laptops | Keys outlive projects, people, and even the company |
| Static secrets in CI/CD | `DEPLOY_TOKEN` set once, never rotated, used by everything |
| `.env` files in Slack/email | "Just send me the creds" -- now in 4 message logs forever |
| Shared SSH keys | One key, five people, zero attribution, no revocation |
| Break-glass = "call Dave" | Dave is on vacation. Dave quit. Dave's laptop is in a cab. |

This repository eliminates these patterns with a brokered trust architecture where credentials are **centrally issued**, **short-lived**, **scoped**, and **auditable**.

---

## Architecture Overview

```
+---------------------------------------------------------------------------+
|                          IDENTITY PLANE                                   |
|  IdP (Entra/Okta/any) -> MFA -> Device Posture -> PIM/PAM -> Role        |
+------------------------------------+--------------------------------------+
                                     | authenticated identity
+------------------------------------v--------------------------------------+
|                      SECRETS & CRYPTO PLANE                               |
|  Vault <-> KMS <-> SOPS <-> PKI CA <-> Transit                           |
|  (dynamic creds, SSH CA, cert signing, encryption-as-a-service)           |
+------------------------------------+--------------------------------------+
                                     | scoped, short-lived credentials
+------------------------------------v--------------------------------------+
|                      RUNTIME DELIVERY PLANE                               |
|  CI/CD OIDC | Vault Agent | SSH CA | SOPS Decrypt | API Auth             |
|  (implement with your platform's native delivery mechanisms)              |
+---------------------------------------------------------------------------+
```

Three planes, deliberately separated:

1. **Identity Plane** -- Who is asking, from what device, with what role?
2. **Secrets & Crypto Plane** -- What exists, who may use it, for how long?
3. **Runtime Delivery Plane** -- How does a workload get what it needs without storing it?

---

## Feature Highlights

| Category | Capability | Status |
|---|---|---|
| **Identity & Auth** | OIDC federation, SSH CA, mTLS workload identity | Implemented |
| **Secrets Management** | Vault dynamic creds, SOPS encryption, KMS integration | Implemented |
| **PKI** | Root/intermediate CA ceremonies, cert monitoring, auto-renewal patterns | Implemented |
| **Signing** | Artifact signing via cosign/notation with Vault-backed keys | Implemented |
| **Scanning** | Secret detection, entropy analysis, DLP pattern matching | Implemented |
| **Compliance** | 7 framework mappings, automated evidence collection, OPA policies | Implemented |
| **Incident Response** | SIRM session framework, evidence chain, timeline builder | Implemented |
| **SDKs** | Python, Go, TypeScript client libraries | Implemented |
| **CI/CD** | Templates for GitHub Actions, GitLab CI, Azure DevOps, Jenkins, CircleCI | Implemented |
| **Local Dev** | Docker Compose environment, Vault dev proxy, direnv patterns | Implemented |
| **JIT Access** | Just-in-time privileged access elevation patterns | Implemented |
| **Break-Glass** | Drill runner, documented procedures, tested playbooks | Implemented |

---

## Repository Structure

```
dev-identity-secrets-reference/
├── bootstrap/scripts/                  # Developer workstation automation
│   ├── bootstrap_dev.sh                #   Workstation setup
│   ├── check_no_plaintext_secrets.sh   #   15+ secret pattern scanner
│   ├── vault_login_oidc.sh             #   Vault OIDC auth with token mgmt
│   ├── fetch_dev_env.sh                #   Dynamic secret retrieval to temp files
│   └── onboard_app.sh                  #   Application onboarding automation
├── dev/                                # Docker Compose local dev environment
│   ├── postgres/                       #   PostgreSQL for dynamic cred demos
│   └── vault/                          #   Vault dev server config
├── diagrams/                           # Mermaid architecture diagrams (.mmd + .svg)
├── docs/                               # Architecture, threat model, runbooks
│   ├── compliance/                     #   7 framework mappings (NIST, ISO, etc.)
│   └── incident-playbooks/             #   Secret exposure response, break-glass
├── evidence/                           # Compliance evidence artifacts
├── examples/                           # Integration examples by language/pattern
│   ├── app/                            #   Application integration patterns
│   ├── compliance/                     #   SOC2 evidence, PCI-DSS validation
│   ├── dlp/                            #   DLP integration guide
│   ├── dotnet/                         #   .NET integration examples
│   ├── go/                             #   Go integration examples
│   ├── jit-access/                     #   JIT privileged access patterns
│   │   └── cloud-jit/                  #     Cloud provider JIT examples
│   ├── mtls/                           #   mTLS patterns
│   │   ├── app-direct/                 #     Direct application mTLS
│   │   └── envoy-sidecar/              #     Envoy sidecar proxy mTLS
│   ├── node/                           #   Node.js integration examples
│   ├── policies/                       #   Branch protection checklist
│   ├── python/                         #   Python integration examples
│   ├── shell/                          #   Shell integration examples
│   ├── siem/                           #   Vault audit log -> Splunk/ELK
│   ├── signing/                        #   Artifact signing examples
│   ├── sirm/                           #   SIRM session examples
│   └── vm/                             #   Cloud-init + systemd + Vault Agent
│       └── systemd/                    #     systemd service patterns
├── lib/                                # SDKs (multi-language)
│   ├── python/                         #   Python SDK (secrets-sdk)
│   ├── go/                             #   Go SDK
│   └── typescript/                     #   TypeScript SDK (@brush-cyber/secrets-sdk)
├── platform/                           # Platform configs and CI templates
│   ├── vault/                          #   Server config, policies, auth methods
│   │   ├── config/                     #     Production server config, VM agent
│   │   ├── policies/                   #     8 least-privilege policies
│   │   └── examples/                   #     Setup scripts, roles, engines
│   ├── github-actions/                 #   Reusable workflows + deployment examples
│   │   ├── reusable/                   #     OIDC auth, scanning, signing, SOPS
│   │   └── workflows/                  #     OIDC-to-Vault, deploy-with-secrets
│   ├── gitlab-ci/                      #   GitLab CI pipeline templates
│   ├── azure-pipelines/                #   Azure DevOps pipeline templates
│   ├── jenkins/                        #   Jenkins pipeline templates
│   ├── circleci/                       #   CircleCI pipeline templates
│   ├── local-dev/                      #   direnv, env templates, Vault proxy
│   └── ci-integration-guide.md         #   Cross-platform CI integration guide
├── secrets/                            # SOPS-encrypted secrets (dev/staging/prod)
├── tests/                              # Test suites
│   ├── opa/                            #   Rego policies for secrets + CI compliance
│   ├── compliance/                     #   Control objective validation
│   ├── integration/                    #   SOPS, PKI, SSH CA, Transit tests
│   └── e2e/                            #   End-to-end reference validation
├── tools/                              # Operational tooling
│   ├── audit/                          #   Credential age, cert inventory, monitoring
│   ├── ceremony/                       #   PKI key ceremony (root + intermediate CA)
│   ├── compliance/                     #   Control matrix, evidence generation
│   ├── drill/                          #   Break-glass drill runner
│   ├── rotate/                         #   SOPS key + Vault secret rotation
│   ├── scanning/                       #   Secret scanning + entropy analysis
│   ├── secrets-doctor/                 #   Diagnostic CLI for repo health
│   ├── signing/                        #   Artifact signing/verification
│   └── sirm/                           #   SIRM session management (IR/forensics)
├── .github/                            # GitHub workflows and issue templates
│   ├── workflows/                      #   CI: scan, test, validate, monitor
│   └── ISSUE_TEMPLATE/                 #   Onboarding, secret exposure templates
├── .sops.yaml                          # Multi-environment SOPS configuration
├── .pre-commit-config.yaml             # gitleaks + shellcheck + YAML validation
├── Makefile                            # 40+ targets for all operations
├── CHANGELOG.md                        # Release history
└── LICENSE                             # MIT
```

---

## Quick Start

### Path 1: Local Development Environment

Spin up a full Vault environment with Docker Compose -- no external dependencies needed:

```bash
git clone https://github.com/BrushCyber/dev-identity-secrets-reference.git
cd dev-identity-secrets-reference

make setup              # Install pre-commit hooks, check dependencies
make dev-up             # Start Vault + PostgreSQL
make dev-setup          # Initialize and configure Vault
make dev-demo           # Run the interactive demo
```

Tear down: `make dev-reset`

### Path 2: SDK Integration

Install the SDK for your language and start managing secrets programmatically:

**Python:**
```bash
pip install -e lib/python
```
```python
from secrets_sdk import VaultClient

client = VaultClient()
secret = client.get_secret("myapp/config", "api_key")
```

**Go:**
```go
import "github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/vault"

client, _ := vault.NewClient(vault.DefaultConfig())
secret, _ := client.GetSecret("myapp/config", "api_key")
```

**TypeScript:**
```bash
npm install @brush-cyber/secrets-sdk
```
```typescript
import { VaultClient } from '@brush-cyber/secrets-sdk';

const client = new VaultClient();
const secret = await client.getSecret('myapp/config', 'api_key');
```

### Path 3: Tool Usage

Run diagnostics, scanning, and auditing directly:

```bash
make doctor             # Full repository health check
make scan               # Secret pattern scanning
make scan-enhanced      # Enhanced scanner with DLP patterns
make audit              # Full security audit
make test               # OPA policies + compliance checks
```

---

## SDK Comparison

| Feature | Python | Go | TypeScript |
|---|:---:|:---:|:---:|
| Vault KV read/write | Yes | Yes | Yes |
| SOPS decrypt | Yes | Yes | Yes |
| Config validation | Yes | Yes | Yes |
| Secret rotation | Yes | -- | Yes |
| SIRM integration | Yes | -- | -- |
| CLI tool | Yes | Yes | Yes |
| Test files | 8 | 3 | 3 |
| Maturity | Alpha | Alpha | Alpha |
| Min runtime | 3.10+ | 1.22+ | Node 18+ |

All SDKs: `lib/python/` | `lib/go/` | `lib/typescript/`

---

## Tool Inventory

| Tool | Path | Description |
|---|---|---|
| `secrets-doctor` | `tools/secrets-doctor/` | Repository health diagnostic -- deps, SOPS, Vault, git security |
| `scan_repo` | `tools/scanning/` | Enhanced secret scanning with custom gitleaks rules |
| `entropy_check` | `tools/scanning/` | Entropy-based high-risk secret detection |
| `sign_artifact` | `tools/signing/` | Artifact signing with cosign or notation (Vault-backed keys) |
| `verify_artifact` | `tools/signing/` | Artifact signature verification |
| `root_ca_ceremony` | `tools/ceremony/` | Root CA key ceremony with HSM support and quorum enforcement |
| `intermediate_ca_ceremony` | `tools/ceremony/` | Intermediate CA ceremony with audit logging |
| `import_to_vault` | `tools/ceremony/` | Import ceremony output into Vault PKI |
| `credential_age_report` | `tools/audit/` | Credential age and staleness reporting |
| `identity_inventory` | `tools/audit/` | Non-human identity inventory scanner |
| `cert_inventory` | `tools/audit/` | Certificate inventory across endpoints |
| `cert_monitor` | `tools/audit/` | Certificate expiry monitoring and alerting |
| `control_matrix` | `tools/compliance/` | Compliance control matrix generator |
| `generate_evidence` | `tools/compliance/` | Automated compliance evidence collection |
| `rotate_vault_secrets` | `tools/rotate/` | Vault secret rotation checker |
| `rotate_sops_keys` | `tools/rotate/` | SOPS encryption key rotation |
| `break_glass_drill` | `tools/drill/` | Break-glass procedure drill runner |
| `sirm-bootstrap` | `tools/sirm/` | SIRM session initialization |
| `sirm-session` | `tools/sirm/` | SIRM session management (status, report, seal) |
| `sirm-evidence` | `tools/sirm/` | SIRM evidence registration with SHA-256 verification |
| `sirm-timeline` | `tools/sirm/` | SIRM timeline event builder with F/O/I/H classification |

---

## CI/CD Template Matrix

| Platform | Templates | Key Features |
|---|---|---|
| **GitHub Actions** | `platform/github-actions/reusable/` | OIDC Vault auth, secret scanning, artifact signing, SOPS decrypt |
| | `platform/github-actions/workflows/` | OIDC-to-Vault, deploy-with-secrets |
| | `.github/workflows/` | PR scanning, SDK tests (Python/Go/TS), cert monitoring, validation |
| **GitLab CI** | `platform/gitlab-ci/` | Vault OIDC auth, pipeline example |
| **Azure DevOps** | `platform/azure-pipelines/` | Vault OIDC auth, pipeline example |
| **Jenkins** | `platform/jenkins/` | Vault shared library, Jenkinsfile example |
| **CircleCI** | `platform/circleci/` | Vault integration config |

Cross-platform guide: [`platform/ci-integration-guide.md`](platform/ci-integration-guide.md)

---

## Compliance Coverage

| Framework | Document | Key Areas |
|---|---|---|
| **NIST SP 800-53 Rev 5** | [nist-mapping.md](docs/compliance/nist-mapping.md) | AC, IA, SC, AU families |
| **ISO 27001:2022** | [iso-mapping.md](docs/compliance/iso-mapping.md) | Annex A controls + key management |
| **OWASP** | [owasp-mapping.md](docs/compliance/owasp-mapping.md) | Secrets Cheat Sheet, ASVS, Top 10 |
| **CSA CCM v4** | [csa-mapping.md](docs/compliance/csa-mapping.md) | IAM, CEK, DSP domains |
| **CIS Controls v8** | [cis-sans-mapping.md](docs/compliance/cis-sans-mapping.md) | IG1-IG3 implementation groups |
| **SOC 2 / PCI DSS 4.0** | [soc2-pci-mapping.md](docs/compliance/soc2-pci-mapping.md) | Trust criteria + Requirements 3,6,7,8,10 |
| **CISA Zero Trust** | [cisa-zero-trust.md](docs/compliance/cisa-zero-trust.md) | All 5 pillars |

Automated compliance tooling: `tools/compliance/` (control matrix generation, evidence collection) and `examples/compliance/` (SOC2 evidence, PCI-DSS validation scripts).

---

## Credential Lifecycle

| Credential Type | Source | Lifetime | Delivery | Replaces |
|---|---|---|---|---|
| Human admin session | IdP / PIM | Minutes-hours | SSO | Static cloud keys |
| CI auth | OIDC federation | Minutes | Token exchange | Stored deployment secrets |
| Database creds | Vault dynamic | Minutes-hours | API / Agent | Static DB passwords |
| App API secrets | Vault KV + rotation | Rotated by policy | Agent / API | `.env` files in Slack |
| SSH admin access | SSH CA | Minutes-hours | Signed certificate | Shared private keys |
| Repo encryption | SOPS + KMS | Persistent master | Git encrypted | Plaintext config files |

---

## Non-Negotiables

These are not recommendations. They are requirements.

- **No static credentials in CI.** Use OIDC federation.
- **No plaintext secrets in Git.** Use SOPS + KMS.
- **No shared admin SSH keys.** Use SSH CA or access broker.
- **No unbounded service account access.** One SA per app, least privilege.
- **No untested break-glass.** Drill quarterly, rotate after test.

---

## Documentation

| # | Document | Description |
|---|---|---|
| 01 | [Scope & Purpose](docs/01-scope-purpose.md) | Project scope and goals |
| 02 | [Reference Architecture](docs/02-reference-architecture.md) | Full architecture design |
| 03 | [Dev Environment Architecture](docs/03-dev-environment-architecture.md) | Developer workstation patterns |
| 04 | [User Stories](docs/04-user-stories.md) | Personas and workflows |
| 05 | [MVP Plan](docs/05-mvp-plan.md) | Implementation plan |
| 06 | [Controls & Guardrails](docs/06-controls-and-guardrails.md) | Security controls framework |
| 07 | [Threat Model](docs/07-threat-model.md) | Attack surface analysis |
| 08 | [Decision Log](docs/08-decision-log.md) | Architecture decision records |
| 09 | [Runbooks](docs/09-runbooks.md) | Operational runbooks |
| 10 | [Vendor & Pattern Profiles](docs/10-vendor-and-pattern-profiles.md) | Implementation patterns A/B/C |
| 11 | [References](docs/11-references.md) | Official references |
| 12 | [Architecture Summary](docs/12-architecture-summary-for-gpt-ingest.md) | Condensed architecture summary |
| 13 | [Future Enhancements](docs/13-future-enhancements.md) | Roadmap and completed work |
| 14 | [Compliance Mapping](docs/14-compliance-mapping.md) | Cross-framework compliance index |
| 15 | [SOPS Bootstrap Guide](docs/15-sops-bootstrap-guide.md) | SOPS setup and key management |
| 16 | [mTLS & Workload Identity](docs/16-mtls-workload-identity-guide.md) | mTLS patterns and SPIFFE |
| 17 | [JIT Access Patterns](docs/17-jit-access-patterns.md) | Just-in-time privileged access |
| 18 | [Key Ceremony Guide](docs/18-key-ceremony-guide.md) | Root/intermediate CA ceremonies |
| 19 | [SIRM Framework](docs/19-sirm-framework.md) | Session-based incident response |
| 20 | [SIRM Session Protocol](docs/20-sirm-session-protocol.md) | SIRM operational runbook |
| 21 | [Compliance Automation](docs/21-compliance-automation.md) | Automated evidence and controls |

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure `make validate` passes
4. Submit a PR

All contributions must pass the pre-commit hooks (secret scanning, shellcheck, YAML validation).

---

## License

MIT License -- see [LICENSE](LICENSE)

---

*Built by [Brush Cyber](https://brushcyber.com). Because your secrets deserve better than a Slack DM.*
