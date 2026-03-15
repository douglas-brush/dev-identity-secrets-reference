# Changelog

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
