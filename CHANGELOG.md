# Changelog

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
