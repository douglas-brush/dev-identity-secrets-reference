# Changelog

## [0.6.0] - 2026-03-16
### Added
- **Runbook automation engine** (`tools/runbooks/`) — YAML-driven runbook executor with sequential step execution, validation, rollback, and structured logging; 5 built-in runbooks (secret-rotation, cert-renewal, vault-unseal, incident-response, onboard-service)
- **Secrets mesh framework** (`lib/python/secrets_sdk/mesh/`) — pluggable provider architecture (Vault, file, env) with caching, hot-reload, and failover; distributed secrets delivery pattern
- **Vault migration toolkit** (`tools/migrate/`) — `vault-export.sh`, `vault-import.sh`, `vault-diff.sh`, `vault-health-check.sh` for SOPS-encrypted Vault instance migrations
- **Cloud bridge examples** (`examples/cloud-bridge/`) — bidirectional sync scripts for AWS Secrets Manager, Azure Key Vault, GCP Secret Manager with unified `bridge-config.yaml`
- **Secret lifecycle metrics** (`tools/metrics/`) — `collect-metrics.sh` for cross-tool metrics collection, `risk-scorer.sh` for risk scoring, `generate-report.sh` for terminal and markdown reporting
- **Workshop training modules** (`docs/workshops/`) — 4 hands-on workshops: Vault Fundamentals, Secrets in CI/CD, Incident Response with SIRM, SDK Development
- **Architecture overview** (`docs/22-architecture-overview.md`) — high-level architecture overview document
- **SDK design guide** (`docs/23-sdk-design-guide.md`) — SDK development guidelines and patterns
- **Attack trees** (`docs/24-attack-trees.md`) — attack tree analysis with Mermaid diagram (`diagrams/04-attack-tree-secret-compromise.mmd`)
- **Incident playbooks** (`docs/25-incident-playbooks.md`) — expanded incident response playbooks with detailed procedures
- **Security hardening checklist** (`docs/26-security-hardening-checklist.md`) — comprehensive security hardening guide
- **Incident response flow diagram** (`diagrams/05-incident-response-flow.mmd`)
- **Grafana dashboards** (`dev/grafana/`) — Vault health dashboard with datasource and dashboard provisioning
- **Prometheus monitoring** (`dev/prometheus/`) — metrics collection config for dev environment
- **Dev seed script** (`dev/scripts/seed-demo-data.sh`) — demo data seeder for local dev
- **Vault Agent config** (`dev/vault/agent-config.hcl`) — agent sidecar config for dev environment
- **GitHub templates** — bug report, feature request, PR template, dependabot config
- **Contributing guide** (`CONTRIBUTING.md`)
- **OPA policy expansion** — `ci_security_policy.rego`, `sops_config_policy.rego`, `vault_policy.rego` with tests
- **CI workflows** — OPA tests (`opa-tests.yml`), shell tooling (`test-shell.yml`)
- **Vault policy expansion** — 14 HCL policies (added `admin-emergency`, `ci-issuer`, `db-dynamic`, `developer-read`, `rotation-operator`, `ssh-ca-operator`, `transit-app`) + Sentinel EGPs
- Makefile targets for runbooks, metrics, risk scoring, reporting, vault migration, mesh status

### Changed
- README.md complete rewrite — full directory tree, 29-tool inventory, 12 CI workflows, vault policy table, cloud bridge section, workshop listing, 500+ test badges
- `docs/13-future-enhancements.md` updated — secrets mesh, runbooks, migration, cloud bridge, metrics, workshops moved to completed
- Makefile expanded to 50+ targets with new sections for runbooks, metrics, vault migration, and mesh

## [0.5.0] - 2026-03-16
### Added
- **Go SDK** (`lib/go/`) — VaultClient with 14 methods, SOPS decrypt, config validation, Cobra CLI (doctor, vault-health, scan, decrypt), 84 tests passing
- **TypeScript SDK** (`lib/typescript/`) — VaultClient, SOPS, config, rotation modules, Commander CLI with 5 subcommands, strict TypeScript, 87 tests passing
- **Vault policy library** (`platform/vault/policies/`) — 8 HCL policies (ci-readonly, ci-deploy, developer, security-auditor, break-glass, rotation-agent, pki-admin, transit-only), 3 Sentinel EGPs (require-reason, time-bound-access, mfa-required)
- **Certificate monitoring** (`tools/audit/cert_inventory.sh`, `tools/audit/cert_monitor.sh`) — filesystem + Vault PKI + K8s cert scanning, baseline comparison, webhook/email alerts
- **Compliance automation** (`tools/compliance/`) — `generate_evidence.sh` for SHA-256 evidence packages, `control_matrix.sh` for automated PASS/FAIL/MANUAL control checks
- **Compliance examples** (`examples/compliance/`) — SOC 2 evidence collection and PCI DSS 4.0 validation scripts
- **Compliance automation guide** (`docs/21-compliance-automation.md`)
- **CI workflows** — cert monitoring (`.github/workflows/cert-monitor.yml`), Go tests (`test-go.yml`), TypeScript tests (`test-typescript.yml`), enhanced secret scan (`secret-scan-enhanced.yml`)
- **236 new BATS tests** across 8 test files for shell tooling validation
- **68 new Python SDK tests** for CLI, models, and exceptions (total: 265 Python tests)
- Total test suite: **500+ tests** across Python, Go, TypeScript, BATS, and OPA

### Fixed
- 37 shellcheck warnings resolved across 20+ shell scripts
- 7 Makefile broken references corrected
- 3 missing executable permissions fixed
- 1 broken doc cross-reference fixed
- mypy clean on Python SDK

### Changed
- README.md rewritten with full directory tree, SDK comparison table, tool inventory, CI template matrix
- `docs/13-future-enhancements.md` updated — Go and TypeScript SDKs moved from future to completed
- Makefile reorganized with new targets for compliance, cert monitoring, OPA, and all-tests aggregate

## [0.4.0] - 2026-03-15
### Added
- SIRM (Security Incident Response Management) session framework (`tools/sirm/`)
- SIRM architecture document (`docs/19-sirm-framework.md`) — session lifecycle state machine, bootstrap protocol, evidence management, timeline event model with F/O/I/H classification, compliance mapping
- SIRM session protocol (`docs/20-sirm-session-protocol.md`) — operational runbook with pre-session checklist, bootstrap sequence, evidence registration, session close/seal, break-glass and multi-operator protocols, court-readiness checklist
- SIRM session examples (`examples/sirm/`) — basic audit session and full incident response session
- Makefile targets: `sirm-init`, `sirm-status`, `sirm-report`, `sirm-seal`

### Changed
- README expanded with SIRM section, directory tree entries, and references
- `docs/13-future-enhancements.md` — SIRM session framework moved from future to completed

## [0.3.0] - 2026-03-15
### Added
- Artifact signing toolkit (`tools/signing/`) with cosign and notation support
- mTLS examples (`examples/mtls/`) — Vault PKI, Envoy, nginx, direct app patterns
- JIT privileged access patterns (`examples/jit-access/`)
- Key ceremony scripts (`tools/ceremony/`) for root and intermediate CA with HSM support
- Enhanced secret scanning and DLP integration (`tools/scanning/`, `examples/dlp/`)
- Local dev patterns (`platform/local-dev/`) — direnv, env templates, local Vault proxy
- Expanded integration tests (`tests/integration/`) — SOPS, PKI, SSH CA, Transit
- mTLS & Workload Identity Guide (`docs/16-mtls-workload-identity-guide.md`)
- JIT Access Patterns doc (`docs/17-jit-access-patterns.md`)
- Key Ceremony Guide (`docs/18-key-ceremony-guide.md`)
- Artifact signing examples (`examples/signing/`)
- Makefile targets: `sign`, `verify`, `ceremony-root`, `ceremony-intermediate`, `scan-enhanced`, `entropy-check`, `test-integration`, `dev-proxy`

### Changed
- README expanded with new directory tree entries, artifact signing / mTLS / ceremony sections, and updated references
- `docs/13-future-enhancements.md` rewritten — completed items marked done, new future items added (Go SDK, TypeScript SDK, Terraform provider, GUI dashboard)
- Diagram SVGs regenerated from updated Mermaid sources

### Fixed
- `.venv` and `.pytest_cache` removed from version tracking

## [0.2.0] - 2026-03-15
### Added
- Python SDK (`lib/python/secrets_sdk/`)
- Multi-language integration examples (Python, Node.js, Go, .NET, Shell)
- Docker Compose local dev environment
- CI pipeline templates (GitLab, Azure DevOps, Jenkins, CircleCI)
- secrets-doctor certificate health checks
- Break-glass drill runner
- Non-human identity inventory scanner
- Vault secret rotation checker
- SOPS bootstrap guide
- SIEM integration examples (Splunk, ELK)
- E2E validation harness
- Comprehensive compliance mappings (NIST, ISO, OWASP, CSA, CIS, SOC2, PCI, CISA ZT)

### Changed
- Refactored to platform-independent architecture (removed cloud/K8s lock-in)
- onboard_app.sh now supports --platform flag (k8s, ecs, lambda, none)
- All docs updated with platform-agnostic language

### Removed
- Terraform modules (aws-kms-oidc, azure-keyvault-oidc, gcp-kms-oidc, vault-setup)
- Kubernetes manifests (ESO, CSI, cert-manager, Kyverno, SPIFFE, network policies)
- Cloud-specific OIDC workflows
- devcontainer configuration

## [0.1.0] - 2026-03-14
### Added
- Initial reference architecture
- Vault server config, policies, and setup scripts
- GitHub Actions reusable workflows
- SOPS configuration and encryption examples
- OPA policy tests
- secrets-doctor diagnostic tool
- Developer bootstrap scripts
- Threat model and incident playbooks
