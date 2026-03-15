# Dev Identity & Secrets Reference Architecture

**Stop copying and pasting API keys. Stop sharing secrets in Slack. Stop pretending `.env` files are secure.**

A platform-independent reference architecture for centralized **developer identity**, **PKI**, **secrets management**, and **credential lifecycle**. Covers developer workstations, CI/CD pipelines, VMs, and administrative operations.

Designed to be forked, adapted, and implemented on whatever infrastructure you run — cloud, on-prem, hybrid. Not locked to any cloud provider, orchestrator, or IaC tool.

---

## The Problem

Every organization fails the same way:

| Anti-Pattern | What Actually Happens |
|-------------|----------------------|
| Long-lived API keys on laptops | Keys outlive projects, people, and even the company |
| Static secrets in CI/CD | `DEPLOY_TOKEN` set once, never rotated, used by everything |
| `.env` files in Slack/email | "Just send me the creds" — now in 4 message logs forever |
| Shared SSH keys | One key, five people, zero attribution, no revocation |
| Break-glass = "call Dave" | Dave is on vacation. Dave quit. Dave's laptop is in a cab. |

This repository eliminates these patterns with a brokered trust architecture where credentials are **centrally issued**, **short-lived**, **scoped**, and **auditable**.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        IDENTITY PLANE                               │
│  IdP (Entra/Okta/any) → MFA → Device Posture → PIM/PAM → Role     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ authenticated identity
┌──────────────────────────────▼──────────────────────────────────────┐
│                    SECRETS & CRYPTO PLANE                            │
│  Vault ←→ KMS ←→ SOPS ←→ PKI CA ←→ Transit                        │
│  (dynamic creds, SSH CA, cert signing, encryption-as-a-service)     │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ scoped, short-lived credentials
┌──────────────────────────────▼──────────────────────────────────────┐
│                    RUNTIME DELIVERY PLANE                            │
│  CI/CD OIDC │ Vault Agent │ SSH CA │ SOPS Decrypt │ API Auth       │
│  (implement with your platform's native delivery mechanisms)        │
└─────────────────────────────────────────────────────────────────────┘
```

Three planes, deliberately separated:

1. **Identity Plane** — Who is asking, from what device, with what role?
2. **Secrets & Crypto Plane** — What exists, who may use it, for how long?
3. **Runtime Delivery Plane** — How does a workload get what it needs without storing it?

This model is platform-agnostic. Implement each plane with whatever tooling fits your infrastructure — the separation of concerns is what matters.

---

## What's In This Repo

```
dev-identity-secrets-reference/
├── docs/                              # Architecture, threat model, compliance, runbooks
│   ├── compliance/                    # NIST, ISO 27001, OWASP, CSA, CIS, SOC2, PCI DSS, CISA ZT
│   └── incident-playbooks/            # Secret exposure response, break-glass procedures
├── diagrams/                          # Mermaid architecture diagrams and decision trees
├── lib/python/                        # Python SDK for secrets management integration
├── dev/                               # Docker Compose local dev environment
├── platform/
│   ├── vault/                         # Server config, policies, auth methods, examples
│   │   ├── config/                    # Production server config, VM agent config
│   │   ├── policies/                  # 8 least-privilege policies
│   │   └── examples/                  # Setup scripts, roles, engines
│   ├── github-actions/                # Reusable workflows + deployment examples
│   │   ├── reusable/                  # OIDC Vault auth, secret scanning, SOPS decrypt
│   │   └── workflows/                 # OIDC-to-Vault, deploy-with-secrets
│   ├── gitlab-ci/                     # GitLab CI pipeline templates
│   ├── azure-pipelines/               # Azure DevOps pipeline templates
│   ├── jenkins/                       # Jenkins pipeline templates
│   ├── circleci/                      # CircleCI pipeline templates
│   └── local-dev/                     # direnv, env templates, encrypted config examples
├── bootstrap/scripts/                 # Developer automation
│   ├── bootstrap_dev.sh               # Workstation setup
│   ├── check_no_plaintext_secrets.sh  # 15+ secret pattern scanner
│   ├── vault_login_oidc.sh            # Vault OIDC auth with token management
│   ├── fetch_dev_env.sh               # Dynamic secret retrieval to temp files
│   └── onboard_app.sh                 # Application onboarding automation
├── tools/
│   ├── secrets-doctor/                # Diagnostic CLI: deps, SOPS, Vault, git health
│   ├── rotate/                        # SOPS key + Vault secret rotation
│   ├── audit/                         # Credential age reporting, identity inventory
│   └── drill/                         # Break-glass drill runner
├── tests/
│   ├── opa/                           # Rego policies for secrets + CI compliance
│   ├── compliance/                    # Control objective validation scripts
│   ├── integration/                   # Vault dynamic credential tests
│   └── e2e/                           # End-to-end reference validation
├── examples/
│   ├── python/                        # Python integration examples
│   ├── node/                          # Node.js integration examples
│   ├── go/                            # Go integration examples
│   ├── dotnet/                        # .NET integration examples
│   ├── shell/                         # Shell integration examples
│   ├── app/                           # Application integration patterns
│   ├── vm/                            # Cloud-init + systemd + Vault Agent patterns
│   ├── siem/                          # Vault audit log → Splunk/ELK integration
│   └── policies/                      # Branch protection checklist
├── secrets/                           # SOPS-encrypted secrets (dev/staging/prod)
├── .sops.yaml                         # Multi-environment SOPS configuration
├── .pre-commit-config.yaml            # gitleaks + custom hooks + shellcheck
└── Makefile                           # validate, scan, audit, test, doctor
```

---

## Credential Lifecycle — No More Static Keys

| Credential Type | Source | Lifetime | Delivery | Replaces |
|----------------|--------|----------|----------|----------|
| Human admin session | IdP / PIM | Minutes-hours | SSO | Static cloud keys |
| CI auth | OIDC federation | Minutes | Token exchange | Stored deployment secrets |
| Database creds | Vault dynamic | Minutes-hours | API / Agent | Static DB passwords |
| App API secrets | Vault KV + rotation | Rotated by policy | Agent / API | `.env` files in Slack |
| SSH admin access | SSH CA | Minutes-hours | Signed certificate | Shared private keys |
| Repo encryption | SOPS + KMS | Persistent master | Git encrypted | Plaintext config files |

---

## Quick Start

### 1. Fork and Configure

```bash
git clone https://github.com/BrushCyber/dev-identity-secrets-reference.git
cd dev-identity-secrets-reference

# Install hooks
make setup

# Run diagnostics
make doctor
```

### 2. Replace Placeholders

Update `.sops.yaml` with your KMS key references, then:

```bash
grep -rn "REPLACE\|example\.internal\|111122223333" platform/ bootstrap/ .sops.yaml
```

### 3. Choose Your Pattern

| If You Have... | Start With |
|----------------|-----------|
| Microsoft + Azure | [Pattern A](docs/10-vendor-and-pattern-profiles.md) — Entra + Key Vault + Vault |
| Multi-cloud | [Pattern B](docs/10-vendor-and-pattern-profiles.md) — Okta + Vault + multi-KMS |
| Small team, one cloud | [Pattern C](docs/10-vendor-and-pattern-profiles.md) — Cloud-native + SOPS |

### 4. Bootstrap Developer Workstations

```bash
export VAULT_ADDR=https://vault.your-domain.com
./bootstrap/scripts/bootstrap_dev.sh
```

### 5. Onboard Applications

```bash
./bootstrap/scripts/onboard_app.sh my-api dev
```

---

## Local Development

Spin up a full Vault environment locally with Docker Compose:

```bash
make dev-up          # Start Vault + supporting services
make dev-setup       # Initialize and configure Vault
make dev-demo        # Run the interactive demo
```

To tear down and start fresh:

```bash
make dev-reset       # Destroy volumes and recreate
```

---

## SDK

Install the Python SDK for programmatic secrets management:

```bash
pip install -e lib/python

# Or via make
make sdk-install
```

Basic usage:

```python
from secrets_sdk import VaultClient

client = VaultClient()
secret = client.get_secret("myapp/config", "api_key")
```

Run SDK tests and linting:

```bash
make sdk-test
make sdk-lint
```

---

## Compliance Coverage

This architecture maps to major security frameworks with documented control-by-control coverage:

| Framework | Document | Key Areas |
|-----------|----------|-----------|
| **NIST SP 800-53 Rev 5** | [nist-mapping.md](docs/compliance/nist-mapping.md) | AC, IA, SC, AU families |
| **ISO 27001:2022** | [iso-mapping.md](docs/compliance/iso-mapping.md) | Annex A controls + key management |
| **OWASP** | [owasp-mapping.md](docs/compliance/owasp-mapping.md) | Secrets Cheat Sheet, ASVS, Top 10 |
| **CSA CCM v4** | [csa-mapping.md](docs/compliance/csa-mapping.md) | IAM, CEK, DSP domains |
| **CIS Controls v8** | [cis-sans-mapping.md](docs/compliance/cis-sans-mapping.md) | IG1-IG3 implementation groups |
| **SOC 2 / PCI DSS 4.0** | [soc2-pci-mapping.md](docs/compliance/soc2-pci-mapping.md) | Trust criteria + Requirements 3,6,7,8,10 |
| **CISA Zero Trust** | [cisa-zero-trust.md](docs/compliance/cisa-zero-trust.md) | All 5 pillars |

---

## Non-Negotiables

These are not recommendations. They are requirements.

- **No static credentials in CI.** Use OIDC federation.
- **No plaintext secrets in Git.** Use SOPS + KMS.
- **No shared admin SSH keys.** Use SSH CA or access broker.
- **No unbounded service account access.** One SA per app, least privilege.
- **No untested break-glass.** Drill quarterly, rotate after test.

---

## Tools Included

### `secrets-doctor` — Repository Health Diagnostic

```bash
./tools/secrets-doctor/doctor.sh          # Full diagnostic
./tools/secrets-doctor/doctor.sh deps     # Check tool dependencies
./tools/secrets-doctor/doctor.sh sops     # Validate SOPS config
./tools/secrets-doctor/doctor.sh vault    # Check Vault connectivity
./tools/secrets-doctor/doctor.sh git      # Validate git security
```

### Scanning and Validation

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
- [SOPS Bootstrap Guide](docs/15-sops-bootstrap-guide.md)
- [Official References](docs/11-references.md)

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built by [Brush Cyber](https://brushcyber.com). Because your secrets deserve better than a Slack DM.*
