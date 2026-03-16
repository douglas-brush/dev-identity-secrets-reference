## Description

<!-- What does this PR do? Why is it needed? Link to any relevant issues. -->

## Type of Change

- [ ] New feature (non-breaking change that adds functionality)
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] Security improvement (hardening, vulnerability fix, policy update)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional change)
- [ ] New tool (`tools/`)
- [ ] New or updated SDK (`lib/`)
- [ ] New or updated CI template (`platform/`)
- [ ] Compliance mapping update (`docs/compliance/`)
- [ ] Test improvement

## Testing Checklist

- [ ] `make all` passes locally (validate + test + e2e)
- [ ] `make scan` confirms no plaintext secrets introduced
- [ ] `make lint` passes (shellcheck + YAML validation)
- [ ] New/changed shell scripts pass `shellcheck` individually
- [ ] SDK tests pass (`make sdk-test` or language-specific test command)
- [ ] Integration tests pass if tools were modified (`make test-integration`)
- [ ] New tests added for new functionality

## Documentation Checklist

- [ ] `README.md` updated (if repo structure, tools, or usage changed)
- [ ] Tool README added/updated (`tools/<name>/README.md`)
- [ ] Decision log updated (`docs/08-decision-log.md`) for security-relevant changes
- [ ] Compliance mappings reviewed (if security controls changed)
- [ ] Inline code comments added where non-obvious

## Security Considerations

<!-- Describe any security implications. Delete this section if not applicable. -->

- [ ] No hardcoded credentials, tokens, or secrets
- [ ] No new plaintext secret files
- [ ] SOPS encryption used for any new secret configuration
- [ ] Least-privilege principles maintained
- [ ] Pre-commit hooks still function correctly
