# Architecture Overview

This document provides a high-level view of the system architecture, component inventory, data flows, and extension points for the Dev Identity & Secrets Reference.

---

## System Context

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          EXTERNAL SYSTEMS                                │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   IdP     │  │  Cloud   │  │   CI/CD  │  │   SIEM   │  │   HSM    │ │
│  │(Entra/   │  │  KMS     │  │(GitHub/  │  │(Splunk/  │  │(Cloud/   │ │
│  │ Okta)    │  │(AWS/GCP/ │  │ GitLab/  │  │ ELK)     │  │ On-prem) │ │
│  │          │  │ Azure)   │  │ Jenkins) │  │          │  │          │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ │
└───────┼──────────────┼─────────────┼─────────────┼─────────────┼────────┘
        │              │             │             │             │
        ▼              ▼             ▼             ▲             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     IDENTITY PLANE                                       │
│                                                                          │
│  IdP authentication ──► MFA enforcement ──► Device posture ──► PIM/PAM  │
│                                                                          │
│  Output: authenticated identity with role, device trust, and elevation   │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │ identity token / OIDC claim
                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                  SECRETS & CRYPTO PLANE                                   │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ Vault KV v2  │  │ Vault PKI    │  │ Vault Transit│  │ SOPS + KMS  │ │
│  │ (static +    │  │ (cert issue, │  │ (encrypt-as- │  │ (git-stored │ │
│  │  dynamic)    │  │  SSH CA)     │  │  a-service)  │  │  secrets)   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│         │                 │                 │                 │         │
│  ┌──────┴─────────────────┴─────────────────┴─────────────────┴──────┐  │
│  │           Policy Engine (Vault policies, OPA, rotation rules)     │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │ scoped, short-lived credentials
                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                  RUNTIME DELIVERY PLANE                                   │
│                                                                          │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐           │
│  │ CI OIDC    │ │ Vault Agent│ │ SSH CA     │ │ SOPS       │           │
│  │ token      │ │ sidecar    │ │ signed     │ │ decrypt    │           │
│  │ exchange   │ │ injection  │ │ certs      │ │ at deploy  │           │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘           │
│        ▼              ▼              ▼              ▼                    │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    WORKLOADS                                      │   │
│  │   CI pipelines │ Kubernetes │ VMs │ Serverless │ Dev laptops     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Component Inventory

### Repository Structure

| Directory | Purpose | Key Files |
|-----------|---------|-----------|
| `bootstrap/scripts/` | Developer workstation automation — onboarding, OIDC login, secret fetch, plaintext scan | `bootstrap_dev.sh`, `onboard_app.sh`, `vault_login_oidc.sh`, `fetch_dev_env.sh`, `check_no_plaintext_secrets.sh` |
| `dev/` | Docker Compose local development environment (Vault + Postgres) | `docker-compose.yml`, `demo.sh`, `vault/setup.sh` |
| `diagrams/` | Mermaid architecture diagrams — reference architecture, credential flow, runtime delivery, decision tree | `01-reference-architecture.md` through `04-decision-tree.md` |
| `docs/` | Architecture docs, threat model, compliance mappings, runbooks, guides | Numbered `01-` through `21-` plus `compliance/` and `incident-playbooks/` |
| `evidence/` | SOC 2 and compliance evidence artifacts | `soc2-*` directories |
| `examples/` | Integration examples across languages and patterns | `python/`, `go/`, `node/`, `dotnet/`, `shell/`, `app/`, `vm/`, `mtls/`, `jit-access/`, `signing/`, `sirm/`, `siem/`, `dlp/`, `policies/` |
| `lib/python/` | Python SDK — Vault client, SOPS, config validation, rotation, SIRM, CLI | `secrets_sdk/`, `tests/`, `pyproject.toml` |
| `lib/go/` | Go SDK — Vault client, SOPS decrypt, config management | `vault/`, `sops/`, `config/`, `cmd/` |
| `lib/typescript/` | TypeScript SDK — Vault client, SOPS, config validation, rotation | `src/`, `tests/`, `package.json` |
| `logs/` | Operational logs, drill records | `drills/` |
| `platform/vault/` | Vault server config, policies (8 least-privilege), auth method setup, engine examples | `config/`, `policies/`, `examples/` |
| `platform/github-actions/` | GitHub Actions reusable workflows — OIDC Vault auth, secret scanning, SOPS decrypt | `reusable/`, `workflows/` |
| `platform/gitlab-ci/` | GitLab CI pipeline templates | |
| `platform/azure-pipelines/` | Azure DevOps pipeline templates | |
| `platform/jenkins/` | Jenkins pipeline templates | |
| `platform/circleci/` | CircleCI pipeline templates | |
| `platform/local-dev/` | direnv config, env templates, local Vault dev proxy | `vault-dev-proxy.sh` |
| `secrets/` | SOPS-encrypted secrets per environment | `dev/`, `staging/`, `prod/` |
| `tests/opa/` | Rego policies for secrets access and CI compliance | |
| `tests/compliance/` | Control objective validation scripts | `check_controls.sh` |
| `tests/integration/` | Integration tests — SOPS, PKI, SSH CA, Transit | `run_all.sh` |
| `tests/e2e/` | End-to-end reference validation | `validate_reference.sh` |
| `tests/unit/` | Unit tests | |
| `tools/audit/` | Credential age reporting, non-human identity inventory | `identity_inventory.sh` |
| `tools/ceremony/` | PKI key ceremony scripts (root + intermediate CA) with HSM support | `root_ca_ceremony.sh`, `intermediate_ca_ceremony.sh` |
| `tools/compliance/` | Compliance automation tooling | |
| `tools/drill/` | Break-glass drill runner | `break_glass_drill.sh` |
| `tools/rotate/` | SOPS key rotation + Vault secret rotation | `rotate_sops_keys.sh`, `rotate_vault_secrets.sh` |
| `tools/scanning/` | Enhanced secret scanning, DLP pattern matching, entropy analysis | `scan_repo.sh`, `entropy_check.sh` |
| `tools/secrets-doctor/` | Diagnostic CLI — deps, SOPS, Vault, git health checks | `doctor.sh` |
| `tools/signing/` | Artifact signing/verification (cosign, notation) | `sign_artifact.sh`, `verify_artifact.sh` |
| `tools/sirm/` | SIRM session management — bootstrap, status, report, seal | `sirm-bootstrap.sh`, `sirm-session.sh` |

---

## SDK Architecture

All three SDKs (Python, Go, TypeScript) implement a shared set of capabilities with language-idiomatic patterns.

### Common Capabilities

```
┌─────────────────────────────────────────────────────────┐
│                    SDK Surface                           │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Auth       │  │   KV v2     │  │  Dynamic    │    │
│  │ Token        │  │ Read        │  │  Creds      │    │
│  │ AppRole      │  │ Write       │  │ (DB, cloud) │    │
│  │ OIDC/JWT     │  │ Delete      │  │             │    │
│  └──────────────┘  └─────────────┘  └─────────────┘    │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   PKI        │  │   SSH CA    │  │  Transit    │    │
│  │ Issue cert   │  │ Sign key    │  │  Encrypt    │    │
│  │ CA chain     │  │             │  │  Decrypt    │    │
│  └──────────────┘  └─────────────┘  └─────────────┘    │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   SOPS       │  │  Config     │  │  Rotation   │    │
│  │ Decrypt      │  │  Validate   │  │  Policy     │    │
│  │ Encrypt      │  │  Scan       │  │  Age check  │    │
│  └──────────────┘  └─────────────┘  └─────────────┘    │
│                                                         │
│  ┌─────────────┐  ┌──────────────────────────────┐     │
│  │   Health     │  │  Audit Events                │     │
│  │ Connectivity │  │  Structured logging per op   │     │
│  │ Auth check   │  │                              │     │
│  └──────────────┘  └──────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

### Shared Type Inventory

Every SDK defines typed equivalents of these models:

| Model | Purpose |
|-------|---------|
| `SecretMetadata` | KV v2 version metadata (path, version, created time, destroyed flag) |
| `LeaseInfo` | Dynamic credential lease (ID, duration, renewable, data) |
| `CertInfo` | PKI certificate (cert, CA, chain, private key, serial, expiration) |
| `SSHCertInfo` | Signed SSH certificate (signed key, serial) |
| `TransitResult` | Transit encrypt/decrypt result (ciphertext or plaintext, key version) |
| `HealthCheck` | Single health probe result (name, status, detail, latency) |
| `HealthReport` | Aggregated health (checks array, timestamp, overall status) |
| `AuditEvent` | Structured audit log entry (type, timestamp, path, detail) |
| `SecretFinding` | Plaintext secret scan result |
| `AgeReport` | Secret age analysis |

### Shared Error Hierarchy

| Error | When |
|-------|------|
| `SecretsSDKError` (base) | Base for all SDK errors |
| `VaultAuthError` | Authentication failure (bad token, expired, wrong method) |
| `VaultConnectionError` | Vault unreachable |
| `VaultSecretNotFound` | KV path does not exist |
| `VaultLeaseError` | Lease renewal or revocation failure |
| `SopsDecryptError` | SOPS decryption failure |
| `SopsEncryptError` | SOPS encryption failure |
| `SopsNotInstalledError` | SOPS binary not found |
| `ConfigValidationError` | Repo structure or config validation failure |
| `RotationError` | Secret rotation policy violation |

For detailed SDK design patterns, see [SDK Design Guide](23-sdk-design-guide.md).

---

## Tool Architecture

All tools in `tools/` follow shared conventions:

| Convention | Detail |
|------------|--------|
| Entrypoint | Single shell script as the primary interface |
| Flags | `--dry-run` supported by all destructive operations |
| Exit codes | 0 = success, non-zero = failure (always) |
| Logging | ISO UTC timestamps, structured output to stdout/stderr |
| Dependencies | Checked at startup; fail early with clear message if missing |
| Secrets | Never hardcoded; sourced from environment variables or Vault |
| Makefile integration | Every tool has a corresponding `make` target |
| README | Every tool directory has a `README.md` |

### Tool Categories

```
tools/
├── audit/          → Credential age, identity inventory (read-only inspection)
├── ceremony/       → PKI key ceremonies (root + intermediate CA, HSM-backed)
├── compliance/     → Compliance automation and evidence collection
├── drill/          → Break-glass drill execution and validation
├── rotate/         → SOPS key rotation + Vault secret rotation
├── scanning/       → Enhanced secret scanning, DLP, entropy analysis
├── secrets-doctor/ → Diagnostic CLI (deps, SOPS, Vault, git health)
├── signing/        → Artifact signing and verification (cosign, notation)
└── sirm/           → SIRM session lifecycle (bootstrap, status, report, seal)
```

---

## Data Flow Diagrams

### Secret Read (KV v2)

```
Developer / Application
        │
        │ 1. Authenticate (OIDC / AppRole / Token)
        ▼
┌───────────────┐
│  Vault Server │
│               │ 2. Validate identity + policy
│  ┌──────────┐ │
│  │ Auth     │ │ 3. Check ACL: does identity have read on path?
│  │ Backend  │ │
│  └────┬─────┘ │
│       ▼       │
│  ┌──────────┐ │
│  │ KV v2    │ │ 4. Retrieve secret data + metadata
│  │ Engine   │ │
│  └────┬─────┘ │
└───────┼───────┘
        │
        ▼ 5. Return { data, metadata } — short-lived token, audit logged
Developer / Application
```

### Secret Rotation

```
Rotation trigger (schedule / policy / manual)
        │
        ▼
┌───────────────────┐
│  rotate_vault_    │  1. Read current secret metadata
│  secrets.sh       │  2. Check age against rotation policy
│                   │  3. Generate new credential (or request from engine)
│  (or SDK          │  4. Write new version to KV v2
│   checkSecretAge) │  5. Verify new version readable
└───────┬───────────┘  6. Audit log rotation event
        │
        ▼
┌───────────────────┐
│  rotate_sops_     │  1. Read .sops.yaml for key references
│  keys.sh          │  2. Re-encrypt all files with new data key
│                   │  3. Verify decrypt succeeds with new key
└───────────────────┘  4. Commit re-encrypted files
```

### Key Ceremony (Root CA)

```
Ceremony Operator(s) + Witness(es)
        │
        │ 1. Pre-flight: verify HSM, quorum, environment
        ▼
┌───────────────────────┐
│  root_ca_ceremony.sh  │  2. Generate root CA key (HSM-backed or software)
│                       │  3. Self-sign root certificate
│  --dry-run by default │  4. Export public cert (never private key)
│                       │  5. Record ceremony log with SHA-256 hashes
└───────────┬───────────┘  6. Witness attestation
            │
            ▼
┌───────────────────────────┐
│  intermediate_ca_         │  7. Generate intermediate key
│  ceremony.sh              │  8. Sign with root CA
│                           │  9. Configure Vault PKI mount
└───────────────────────────┘ 10. Record in evidence chain
```

### SIRM Session Lifecycle

```
Operator
  │
  │ 1. Set SIRM_CASE_ID, SIRM_CLASSIFICATION, SIRM_OPERATOR
  ▼
┌───────────────────────┐
│  sirm-bootstrap.sh    │  Phase 1: Operator authentication
│                       │  Phase 2: Environment validation
│  (make sirm-init)     │  Phase 3: Repository state capture
│                       │  Phase 4: Infrastructure health
│                       │  Phase 5: Context snapshot
└───────────┬───────────┘
            │ Session state: ACTIVE
            ▼
┌───────────────────────┐
│  Investigation work   │  Evidence collection (SHA-256 hashed)
│                       │  Timeline entries (ISO UTC)
│  sirm-session.sh      │  Findings classified: F/O/I/H
│  status / report      │  Chain of custody maintained
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  sirm-session.sh      │  Generate tamper-evident report
│  seal                 │  SHA-256 hash of entire session
│                       │  State: SEALED (irreversible)
│  (make sirm-seal)     │  Court-admissible artifact
└───────────────────────┘
```

---

## Extension Points

### Adding a New Secret Backend

To support a secret backend beyond Vault KV v2 (e.g., AWS Secrets Manager, Azure Key Vault, GCP Secret Manager):

1. **SDK layer**: Implement a new client class that conforms to the same interface as `VaultClient` — at minimum: auth, read, write, delete, health.
2. **Config**: Add backend selection to configuration (environment variable or config file).
3. **Tools**: Update `secrets-doctor` to health-check the new backend.
4. **CI templates**: Add OIDC/auth integration for the new backend.
5. **Tests**: Add integration tests in `tests/integration/`.
6. **Docs**: Document in `docs/` and update compliance mappings if control implementations change.

### Adding a New CI Platform

To add a CI platform beyond GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, and CircleCI:

1. **Templates**: Create `platform/<ci-platform>/` with pipeline configuration files.
2. **OIDC integration**: Implement Vault OIDC token exchange for the platform.
3. **Secret scanning**: Add a secret scan step using the platform's native capabilities or the repo's `scan_repo.sh`.
4. **OPA policies**: Add Rego policies in `tests/opa/` that validate the template's security posture.
5. **Guide**: Update `platform/ci-integration-guide.md`.
6. **Examples**: Add a deployment example using the new platform.

### Adding a New Compliance Framework

To map a new compliance framework (beyond NIST, ISO, OWASP, CSA, CIS, SOC2/PCI, CISA ZT):

1. **Mapping doc**: Create `docs/compliance/<framework>-mapping.md` following the existing format.
2. **Controls table**: Map framework controls to specific components, tools, and code paths in this repo.
3. **Automated checks**: Add validation scripts to `tests/compliance/` for any controls that can be verified programmatically.
4. **OPA policies**: If the framework introduces new policy requirements, add Rego policies.
5. **Evidence**: Define evidence collection patterns in `tools/compliance/`.
6. **README**: Update `docs/compliance/README.md` and the main `README.md` compliance table.

### Adding a New Tool

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-new-tool) for the full checklist.

### Adding a New SDK Language

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-new-sdk) and [SDK Design Guide](23-sdk-design-guide.md) for interface requirements and patterns.
