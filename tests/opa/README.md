# OPA Policy Library

Policy-as-code validation for secrets management, Vault configuration, SOPS encryption, and CI/CD pipeline security.

## Policy Catalog

| Policy | Package | File | Description |
|--------|---------|------|-------------|
| Kubernetes Secrets | `kubernetes.secrets` | `secrets_policy.rego` | Blocks hardcoded Secrets, enforces dedicated SAs, validates cert-manager and ExternalSecret configs |
| CI/CD Basic | `ci.security` | `ci_policy.rego` | Requires OIDC permissions, blocks hardcoded secrets, enforces OIDC over static cloud creds |
| Vault HCL | `vault.policy` | `vault_policy.rego` | Validates Vault policy documents: no wildcards on sensitive paths, break-glass seal controls, no unauthorized sudo, transit key protection |
| SOPS Config | `sops.config` | `sops_config_policy.rego` | Validates .sops.yaml: requires creation_rules, blocks PGP, enforces path_regex separation, controls unencrypted_suffix |
| CI/CD Advanced | `ci.advanced_security` | `ci_security_policy.rego` | Extended CI checks: least-privilege permissions, cleanup/revoke steps, pull_request_target injection protection |

## Rule Details

### Vault HCL Policy (`vault_policy.rego`)

1. **No wildcard capabilities on sensitive paths** -- `sys/*` and `auth/*` paths must have explicit capabilities, never `*`
2. **Break-glass seal controls** -- Break-glass policies must explicitly deny `sys/seal` and `sys/unseal`
3. **Header comment required** -- All policies must document their purpose with a header comment
4. **No sudo except break-glass** -- `sudo` capability is restricted to break-glass policies only
5. **Transit key deletion blocked** -- `delete` capability on `transit/keys/*` paths is prohibited

### SOPS Config (`sops_config_policy.rego`)

1. **creation_rules required** -- Every `.sops.yaml` must define `creation_rules`
2. **No PGP** -- Must use age keys or cloud KMS (AWS KMS, GCP KMS, Azure Key Vault, HC Vault Transit)
3. **path_regex required** -- Environment separation requires path-based routing rules
4. **unencrypted_suffix controlled** -- `unencrypted_suffix` requires an explicit `allowed_unencrypted_keys` allowlist

### CI/CD Advanced Security (`ci_security_policy.rego`)

1. **No hardcoded secrets** -- Env vars matching secret patterns must use `${{ secrets.* }}`
2. **OIDC over static tokens** -- Static AWS creds, Azure client secrets, and Vault tokens are denied
3. **Least-privilege permissions** -- `contents: write` requires justification (release actions or git push)
4. **Cleanup/revoke required** -- Jobs using credentials must include a cleanup or revoke step
5. **pull_request_target protection** -- Checking out PR code in `pull_request_target` workflows is blocked

## Running Tests

### Prerequisites

Install OPA:

```bash
# macOS
brew install opa

# Linux
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa && sudo mv opa /usr/local/bin/
```

### Run All Tests

```bash
opa test tests/opa/ -v
```

### Run Specific Policy Tests

```bash
# Vault policies only
opa test tests/opa/vault_policy.rego tests/opa/vault_policy_test.rego -v

# SOPS config only
opa test tests/opa/sops_config_policy.rego tests/opa/sops_config_policy_test.rego -v

# CI security only
opa test tests/opa/ci_security_policy.rego tests/opa/ci_security_policy_test.rego -v
```

### Evaluate a Policy Against Input

```bash
# Check a Vault policy document
opa eval -i policy.json -d tests/opa/vault_policy.rego 'data.vault.policy.violations'

# Check a .sops.yaml
opa eval -i .sops.yaml.json -d tests/opa/sops_config_policy.rego 'data.sops.config.violations'

# Check a GitHub Actions workflow
opa eval -i workflow.json -d tests/opa/ci_security_policy.rego 'data.ci.advanced_security.violations'
```

## CI Integration

The `.github/workflows/opa-tests.yml` workflow runs all OPA tests on every push and pull request. It:

1. Installs OPA
2. Runs `opa test tests/opa/ -v` with verbose output
3. Runs `opa check tests/opa/` for syntax validation
4. Fails the build if any test fails

### Adding to Existing CI

Add this step to any workflow:

```yaml
- name: Run OPA policy tests
  run: |
    curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
    chmod +x /usr/local/bin/opa
    opa test tests/opa/ -v
```

## Input Schema Conventions

### Vault Policy Input

```json
{
  "name": "policy-name",
  "header_comment": "Description of what this policy does",
  "rules": [
    {
      "path": "secret/data/myapp/*",
      "capabilities": ["read", "create", "update"]
    }
  ]
}
```

### SOPS Config Input

Matches `.sops.yaml` structure:

```json
{
  "creation_rules": [
    {
      "path_regex": "environments/prod/.*\\.enc\\.yaml$",
      "age": "age1...",
      "key_groups": []
    }
  ]
}
```

### CI Workflow Input

Matches GitHub Actions workflow YAML (converted to JSON):

```json
{
  "on": { "push": { "branches": ["main"] } },
  "permissions": { "contents": "read", "id-token": "write" },
  "jobs": {
    "deploy": {
      "runs-on": "ubuntu-latest",
      "steps": [{ "run": "deploy.sh" }]
    }
  }
}
```

## Adding New Policies

1. Create `tests/opa/<name>_policy.rego` with package, header comment, rules, and `violations` aggregate
2. Create `tests/opa/<name>_policy_test.rego` with both deny and allow test cases
3. Add the policy to the catalog table above
4. Run `opa test tests/opa/ -v` to verify
