# E2E Validation Harness

Local validation for the Dev Identity & Secrets reference architecture. Runs entirely offline without requiring Vault, Kubernetes, or any other infrastructure.

## Quick Start

```bash
# Run all validations
./tests/e2e/validate_reference.sh

# Generate a report file
./tests/e2e/validate_reference.sh --report validation-report.txt

# Strict mode (warnings = failures)
./tests/e2e/validate_reference.sh --strict
```

## What It Validates

| Check | Tool Required | Fallback |
|-------|---------------|----------|
| YAML syntax | `python3` + PyYAML | `yq` |
| HCL syntax | `terraform` | `hclfmt` |
| Shell script lint | `shellcheck` | skipped |
| OPA policy compile | `opa` | skipped |
| OPA policy tests | `opa` | skipped |
| Kubernetes manifests | `kubeconform` | `kubeval`, then skipped |
| Doc cross-references | built-in | always runs |
| Placeholder detection | built-in | always runs |
| File permissions | built-in | always runs |
| Repo structure | built-in | always runs |

Checks gracefully skip when their required tool is not installed. The built-in checks (cross-references, placeholders, permissions, structure) always run with no external dependencies.

## Installing Optional Tools

```bash
# macOS (Homebrew)
brew install shellcheck opa kubeconform yq

# OPA (binary)
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64
chmod +x /usr/local/bin/opa

# kubeconform
go install github.com/yannh/kubeconform/cmd/kubeconform@latest
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (warnings are non-fatal unless `--strict`) |
| 1 | One or more checks failed |
| 2 | Usage error |

## CI Integration

Add to your CI pipeline:

```yaml
- name: Validate reference architecture
  run: ./tests/e2e/validate_reference.sh --strict --report validation-report.txt

- name: Upload validation report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: validation-report
    path: validation-report.txt
```
