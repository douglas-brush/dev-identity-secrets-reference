# Contributing to Dev Identity & Secrets Reference

Thank you for contributing. This project is a production-grade reference architecture for developer identity, PKI, and secrets management. Contributions must maintain that standard.

---

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Commit Conventions](#commit-conventions)
- [Pull Request Process](#pull-request-process)
- [Adding a New Tool](#adding-a-new-tool)
- [Adding a New SDK](#adding-a-new-sdk)
- [Adding a New CI Template](#adding-a-new-ci-template)
- [Code of Conduct](#code-of-conduct)

---

## Development Environment Setup

### Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Docker + Docker Compose | Local dev environment | [docker.com](https://docs.docker.com/get-docker/) |
| shellcheck | Shell script linting | `brew install shellcheck` or `apt install shellcheck` |
| Python 3.10+ | SDK development, compliance scripts | System or pyenv |
| Go 1.21+ | Go SDK development | [go.dev](https://go.dev/dl/) |
| Node.js 18+ | TypeScript SDK development | [nodejs.org](https://nodejs.org/) |
| OPA | Policy testing | `brew install opa` or [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| SOPS | Encrypted secrets | `brew install sops` or [github.com/getsops/sops](https://github.com/getsops/sops) |
| pre-commit | Git hook framework | `pip install pre-commit` |

### Quick Start

```bash
# Clone and install hooks
git clone https://github.com/BrushCyber/dev-identity-secrets-reference.git
cd dev-identity-secrets-reference
make setup

# Run diagnostics to verify your environment
make doctor

# Start the local dev environment (Vault + supporting services)
make dev-up
make dev-setup

# Run the interactive demo to verify everything works
make dev-demo
```

### Local Dev Environment

The `dev/` directory contains a Docker Compose stack with Vault and supporting services:

```bash
make dev-up       # Start Vault + Postgres
make dev-setup    # Initialize and configure Vault inside the container
make dev-demo     # Run the interactive demo
make dev-down     # Stop services
make dev-reset    # Destroy volumes and recreate from scratch
make dev-proxy    # Start local Vault dev proxy for SDK work
```

### SDK Development

```bash
# Python SDK
cd lib/python
pip install -e ".[dev]"
pytest tests/ -v
# Or from repo root:
make sdk-install && make sdk-test && make sdk-lint

# Go SDK
cd lib/go
go test ./...
go vet ./...

# TypeScript SDK
cd lib/typescript
npm install
npm test
npm run lint
```

---

## Code Standards

### Shell Scripts

- All scripts must pass `shellcheck` with zero warnings (SC1091 is globally excluded for sourced files).
- Use `set -euo pipefail` at the top of every script.
- Use `#!/usr/bin/env bash` as the shebang.
- Include ISO UTC timestamps in all log output.
- Exit non-zero on any error.
- Never hardcode credentials, tokens, or secrets.
- Use `argparse`-style flag parsing for scripts with more than one argument.

### Python

- **mypy strict mode** must pass (`[tool.mypy] strict = true` in `pyproject.toml`).
- Use type annotations on all function signatures.
- Use `pydantic` for data models.
- Use structured logging via the `logging` module.
- Lint with `ruff`.
- Format is not enforced by CI but `ruff format` is recommended.

### Go

- `go vet ./...` must pass with zero issues.
- `go test ./...` must pass.
- All exported types and functions must have doc comments.
- Use the functional options pattern for client configuration (see `lib/go/vault/client.go`).
- Error types should be concrete structs implementing the `error` interface.

### TypeScript

- **Strict mode** must be enabled (`"strict": true` in `tsconfig.json`).
- All exports must have explicit type annotations at module boundaries.
- Internal types may use inference.
- Use `jest` for testing.
- Lint with ESLint.

### YAML

- All YAML files must parse cleanly with `yaml.safe_load()`.
- Encrypted YAML files use the `.enc.yaml` / `.enc.yml` extension.
- Never commit decrypted YAML (`.dec.yaml`, `.dec.yml`, `.plain.yaml`).

### OPA / Rego

- Policies live in `tests/opa/`.
- All policies must have corresponding `_test.rego` files.
- Run with `opa test tests/opa/ -v`.

---

## Testing Requirements

All tests must pass before a PR can be merged. The full suite is:

```bash
make all    # Runs: validate (scan + lint) + test (OPA + compliance) + e2e
```

### Test Categories

| Command | What It Tests | Required |
|---------|--------------|----------|
| `make scan` | No plaintext secrets in repo, all secrets files encrypted | Yes |
| `make lint` | Shell scripts pass shellcheck, YAML parses cleanly | Yes |
| `make test` | OPA policy tests, compliance control checks | Yes |
| `make e2e` | End-to-end reference validation | Yes |
| `make sdk-test` | Python SDK unit tests | Yes, if SDK changed |
| `make test-integration` | Integration tests (SOPS, PKI, SSH CA, Transit) | Yes, if tools changed |
| `make scan-enhanced` | Enhanced secret scanning with DLP patterns | Recommended |
| `make entropy-check` | Entropy-based high-risk detection | Recommended |

### Writing Tests

- **OPA policies**: Add `_test.rego` file alongside your policy in `tests/opa/`.
- **Compliance checks**: Add validation to `tests/compliance/check_controls.sh`.
- **Integration tests**: Add test script to `tests/integration/` and register in `run_all.sh`.
- **SDK tests**: Add tests in the SDK's `tests/` directory using the language-appropriate framework.
- **E2E tests**: Extend `tests/e2e/validate_reference.sh` for new structural requirements.

---

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

### Format

```
<type>: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | When |
|------|------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `chore` | Maintenance, dependency updates, config changes |
| `docs` | Documentation only |
| `refactor` | Code restructure with no behavior change |
| `security` | Security improvement or vulnerability fix |
| `test` | Test additions or corrections |

### Examples

```
feat: add JIT access pattern for database credentials
fix: correct SOPS key rotation dry-run exit code
docs: add mTLS troubleshooting section
security: enforce minimum key length in PKI ceremony
test: add OPA policy tests for CI secret access
chore: update pre-commit hook versions
```

---

## Pull Request Process

1. **Branch**: Create a feature branch from `main`. Use descriptive names: `feat/jit-database-access`, `fix/sops-rotation-exit-code`.
2. **Implement**: Make your changes. Follow the code standards above.
3. **Test**: Run `make all` locally. All checks must pass.
4. **Commit**: Use conventional commit messages.
5. **Push**: Push your branch and open a PR using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).
6. **Review**: Address review feedback. Re-run `make all` after changes.
7. **Merge**: Squash-merge preferred for feature branches. Maintainers merge.

### PR Expectations

- PRs that touch shell scripts must pass `shellcheck`.
- PRs that touch SDK code must include or update tests.
- PRs that add new tools must include a README in the tool directory.
- PRs that change security-relevant behavior must document the change in the decision log (`docs/08-decision-log.md`).
- PRs must not introduce plaintext secrets, hardcoded tokens, or unencrypted credential files.

---

## Adding a New Tool

Tools live in `tools/<tool-name>/`. Follow this checklist:

- [ ] Create `tools/<tool-name>/` directory.
- [ ] Add the main script(s). Shell scripts must pass `shellcheck`.
- [ ] Add `tools/<tool-name>/README.md` with: purpose, usage, dependencies, examples.
- [ ] Add a Makefile target in the root `Makefile` under the appropriate section.
- [ ] Register the target in the `.PHONY` declaration at the top of `Makefile`.
- [ ] Add the target to `make help` output.
- [ ] Add tests in `tests/` (integration or unit as appropriate).
- [ ] Update `README.md` — add the tool to the "What's In This Repo" tree and the "Tools Included" section.
- [ ] If the tool has security implications, add an OPA policy in `tests/opa/`.
- [ ] Run `make all` to verify nothing breaks.

---

## Adding a New SDK

SDKs live in `lib/<language>/`. Follow this checklist:

- [ ] Create `lib/<language>/` with the standard project structure for that language.
- [ ] Implement the common interface patterns (see [SDK Design Guide](docs/23-sdk-design-guide.md)):
  - VaultClient with auth (token, AppRole, OIDC), KV read/write/delete, dynamic creds, PKI, SSH, Transit, health.
  - SOPS decrypt/encrypt.
  - Config validation (repo structure, SOPS config, Vault policy, plaintext scan).
  - Rotation policy.
  - Typed error hierarchy.
  - Typed models (SecretMetadata, LeaseInfo, CertInfo, SSHCertInfo, TransitResult, HealthReport, AuditEvent).
- [ ] Add `lib/<language>/README.md`.
- [ ] Add unit tests with mock strategies appropriate to the language.
- [ ] Add SDK build/test/lint targets to root `Makefile`.
- [ ] Add examples in `examples/<language>/`.
- [ ] Update `README.md` with SDK section and usage example.
- [ ] Run `make all` to verify nothing breaks.

---

## Adding a New CI Template

CI templates live in `platform/<ci-platform>/`. Follow this checklist:

- [ ] Create `platform/<ci-platform>/` directory.
- [ ] Add pipeline/workflow templates following the platform's conventions.
- [ ] Include OIDC-based Vault authentication (no static secrets in CI).
- [ ] Include secret scanning step.
- [ ] Add `platform/<ci-platform>/README.md` with: platform requirements, setup instructions, usage examples.
- [ ] Add OPA policy tests in `tests/opa/` validating the template meets security requirements.
- [ ] Update `platform/ci-integration-guide.md` with the new platform.
- [ ] Update `README.md` to list the new platform in the repo tree.
- [ ] Run `make all` to verify nothing breaks.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

In summary:
- Be respectful and professional.
- Focus on constructive technical discussion.
- No harassment, discrimination, or personal attacks.
- Report issues to the maintainers.

For the full text, see [contributor-covenant.org](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
