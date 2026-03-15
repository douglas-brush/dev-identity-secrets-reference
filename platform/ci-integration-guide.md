# CI/CD Platform Integration Guide

This guide covers integrating HashiCorp Vault with CI/CD pipelines using OIDC federation. The goal: **zero static secrets in CI/CD configuration**.

Every CI/CD platform covered here supports OIDC token issuance. Vault validates these tokens against the platform's JWKS endpoint, eliminating stored credentials entirely.

## Platform OIDC Support Matrix

| Platform | OIDC Token Source | Token Env Variable / Mechanism | OIDC Discovery URL | Audience Convention | Bound Claims Available |
|---|---|---|---|---|---|
| **GitHub Actions** | Native (`id-token: write` permission) | `ACTIONS_ID_TOKEN_REQUEST_TOKEN` + API call (or `hashicorp/vault-action`) | `https://token.actions.githubusercontent.com` | Vault URL or custom | `repository`, `ref`, `sha`, `workflow`, `actor`, `environment` |
| **GitLab CI** | Native (`id_tokens` keyword) | Custom variable name (e.g., `VAULT_ID_TOKEN`) | `https://gitlab.com` (or self-hosted URL) | Custom (typically Vault URL) | `namespace_path`, `project_path`, `ref`, `ref_type`, `pipeline_source`, `environment` |
| **Azure DevOps** | Azure AD workload identity federation | `idToken` via `AzureCLI@2` with `addSpnToEnvironment` | `https://login.microsoftonline.com/{tenant}/v2.0` | App ID URI (`api://...`) | `oid` (service principal), `tid` (tenant), `sub` |
| **Jenkins** | Jenkins OIDC Provider plugin | `OIDC_TOKEN_FILE` or `JENKINS_OIDC_TOKEN` | `https://jenkins.example.com/oidc` | Custom | Job name, build number, branch (plugin-dependent) |
| **CircleCI** | Native (context with OIDC) | `CIRCLE_OIDC_TOKEN_V2` | `https://oidc.circleci.com/org/{ORG_ID}` | Org ID | `oidc.circleci.com/project-id`, `oidc.circleci.com/context-ids`, `sub` |
| **Bitbucket Pipelines** | Native (OIDC) | `BITBUCKET_STEP_OIDC_TOKEN` | `https://api.bitbucket.org/2.0/workspaces/{workspace}/pipelines-config/identity/oidc` | `ari:cloud:bitbucket::workspace/{uuid}` | `repositoryUuid`, `branchName`, `stepUuid`, `pipelineUuid` |

## Vault JWT Auth Configuration Per Platform

### GitHub Actions

```bash
# Enable JWT auth backend
vault auth enable -path=jwt/github jwt

# Configure OIDC discovery
vault write auth/jwt/github/config \
  oidc_discovery_url="https://token.actions.githubusercontent.com" \
  bound_issuer="https://token.actions.githubusercontent.com"

# Create role with bound claims
vault write auth/jwt/github/role/github-ci \
  role_type="jwt" \
  bound_audiences="https://vault.example.com" \
  bound_claims_type="glob" \
  bound_claims='{"repository":"myorg/myrepo","ref":"refs/heads/main"}' \
  user_claim="repository" \
  policies="ci-issuer" \
  token_ttl="600" \
  token_max_ttl="900"
```

### GitLab CI

```bash
vault auth enable -path=jwt/gitlab jwt

# For GitLab.com — self-hosted instances use their own URL
vault write auth/jwt/gitlab/config \
  oidc_discovery_url="https://gitlab.com" \
  bound_issuer="https://gitlab.com"

vault write auth/jwt/gitlab/role/gitlab-ci \
  role_type="jwt" \
  bound_audiences="https://vault.example.com" \
  bound_claims_type="glob" \
  bound_claims='{"namespace_path":"mygroup/*","ref":"refs/heads/main"}' \
  user_claim="sub" \
  policies="ci-issuer" \
  token_ttl="600" \
  token_max_ttl="900"
```

### Azure DevOps

```bash
vault auth enable -path=jwt/azure jwt

# Azure AD OIDC discovery
vault write auth/jwt/azure/config \
  oidc_discovery_url="https://login.microsoftonline.com/TENANT_ID/v2.0" \
  bound_issuer="https://sts.windows.net/TENANT_ID/"

vault write auth/jwt/azure/role/azure-devops-ci \
  role_type="jwt" \
  bound_audiences="api://AZURE_APP_ID" \
  bound_claims='{"oid":"SERVICE_PRINCIPAL_OBJECT_ID"}' \
  user_claim="oid" \
  policies="ci-issuer" \
  token_ttl="600" \
  token_max_ttl="900"
```

### Jenkins

```bash
vault auth enable -path=jwt/jenkins jwt

# Jenkins OIDC Provider plugin exposes JWKS
vault write auth/jwt/jenkins/config \
  jwks_url="https://jenkins.example.com/oidc/jwks" \
  bound_issuer="https://jenkins.example.com"

vault write auth/jwt/jenkins/role/jenkins-ci \
  role_type="jwt" \
  bound_audiences="https://vault.example.com" \
  bound_claims='{"jenkins_full_name":"myorg/myjob/*"}' \
  user_claim="sub" \
  policies="ci-issuer" \
  token_ttl="600" \
  token_max_ttl="900"
```

### CircleCI

```bash
vault auth enable -path=jwt/circleci jwt

vault write auth/jwt/circleci/config \
  oidc_discovery_url="https://oidc.circleci.com/org/ORG_ID" \
  bound_issuer="https://oidc.circleci.com/org/ORG_ID"

vault write auth/jwt/circleci/role/circleci-ci \
  role_type="jwt" \
  bound_audiences="ORG_ID" \
  bound_claims='{"oidc.circleci.com/project-id":"PROJECT_ID"}' \
  user_claim="sub" \
  policies="ci-issuer" \
  token_ttl="600" \
  token_max_ttl="900"
```

### Bitbucket Pipelines

```bash
vault auth enable -path=jwt/bitbucket jwt

vault write auth/jwt/bitbucket/config \
  oidc_discovery_url="https://api.bitbucket.org/2.0/workspaces/WORKSPACE/pipelines-config/identity/oidc" \
  bound_issuer="https://api.bitbucket.org/2.0/workspaces/WORKSPACE/pipelines-config/identity/oidc"

vault write auth/jwt/bitbucket/role/bitbucket-ci \
  role_type="jwt" \
  bound_audiences="ari:cloud:bitbucket::workspace/WORKSPACE_UUID" \
  bound_claims='{"repositoryUuid":"REPO_UUID"}' \
  user_claim="sub" \
  policies="ci-issuer" \
  token_ttl="600" \
  token_max_ttl="900"
```

## Common Patterns

### 1. Per-Stage Authentication

Each pipeline stage authenticates independently with its own short-lived Vault token. Never share tokens across stages.

```
Build Stage   -> OIDC auth -> Vault token (TTL: 10m) -> fetch build secrets -> revoke
Test Stage    -> OIDC auth -> Vault token (TTL: 10m) -> dynamic DB creds    -> revoke
Deploy Stage  -> OIDC auth -> Vault token (TTL: 10m) -> SOPS decrypt        -> revoke
```

**Why:** If a stage is compromised, the blast radius is limited to that stage's token scope. A build-stage token cannot access deploy secrets.

### 2. Least-Privilege Vault Roles

Create separate Vault roles per stage with minimal policies:

| Stage | Policy | Permissions |
|-------|--------|-------------|
| Build | `ci-build` | Read `kv/data/ci/build-config`, read container registry creds |
| Test | `ci-test` | Read `database/creds/test-*`, read test config |
| Deploy | `ci-deploy` | Read `kv/data/{env}/*`, Transit decrypt (for SOPS), read kubeconfig |
| Scan | (none) | No Vault access needed |

### 3. Dynamic Credentials for Tests

Use Vault's database secrets engine to generate unique credentials per test run:

```bash
# Configure once in Vault
vault write database/config/testdb \
  plugin_name="postgresql-database-plugin" \
  connection_url="postgresql://{{username}}:{{password}}@db.example.com:5432/testdb" \
  allowed_roles="test-readonly"

vault write database/roles/test-readonly \
  db_name="testdb" \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}';" \
  default_ttl="15m" \
  max_ttl="30m"
```

Each test run gets unique credentials that auto-expire. No credential reuse across builds.

### 4. SOPS with Vault Transit

Use Vault's Transit secrets engine as the SOPS encryption backend. This centralizes key management in Vault and eliminates cloud KMS dependencies.

```bash
# Enable Transit engine
vault secrets enable transit

# Create encryption key for SOPS
vault write -f transit/keys/sops-ci

# .sops.yaml configuration
cat > .sops.yaml << 'EOF'
creation_rules:
  - path_regex: secrets/.*\.yaml$
    hc_vault_transit_uri: "https://vault.example.com/v1/transit/keys/sops-ci"
EOF
```

SOPS uses the VAULT_TOKEN from OIDC auth to perform encrypt/decrypt operations via Transit.

### 5. Token Revocation

Always revoke Vault tokens when a stage completes, whether it succeeds or fails:

```
after_script:    # GitLab
post { always }  # Jenkins
when: always     # CircleCI
condition: always()  # Azure DevOps
if: always()     # GitHub Actions
```

## Anti-Patterns

### 1. Storing Vault Tokens as CI Variables

**Problem:** A static Vault token stored in CI/CD variables (GitLab CI Variables, Azure DevOps Variable Groups, Jenkins Credentials) defeats the purpose of Vault. The token is long-lived, shared across all builds, and visible to project maintainers.

**Fix:** Use OIDC federation. The CI platform issues a short-lived JWT per job, which Vault exchanges for a scoped token. No stored secrets.

### 2. Sharing Tokens Across Stages

**Problem:** Passing a Vault token from an auth stage to downstream stages (via artifacts, env vars, or CI caches) creates a single point of compromise and extends the token's effective lifetime.

**Fix:** Each stage authenticates independently via OIDC. Vault tokens live only for the duration of one stage.

### 3. Wildcard Bound Claims

**Problem:** A Vault role with `bound_claims='{"repository":"myorg/*"}'` allows any repository in the org to authenticate. A compromised or malicious repo gets full access.

**Fix:** Bind to the specific project/repo and branch:
```json
{
  "repository": "myorg/myrepo",
  "ref": "refs/heads/main"
}
```

### 4. Long Token TTLs

**Problem:** Setting `token_ttl="86400"` (24 hours) means a leaked token is valid for a full day.

**Fix:** Set TTLs to match the maximum expected stage duration plus a small buffer. 10-15 minutes covers most CI stages. Vault will not issue tokens longer than `token_max_ttl`.

### 5. Decrypted Secrets in Artifacts

**Problem:** Uploading decrypted SOPS files as CI artifacts stores plaintext secrets on the CI server's storage, accessible to anyone with artifact download permissions.

**Fix:** Decrypt to a tmpfs or ephemeral directory, use the secrets immediately, and delete them in an `always` cleanup step. If you must pass secrets between stages, use Vault directly in each stage.

### 6. AppRole with Static Secret IDs

**Problem:** AppRole `secret_id` stored in Jenkins credentials and never rotated is functionally equivalent to a static password.

**Fix:** Use OIDC instead. If OIDC is not available, implement secret_id rotation:
- Generate a new `secret_id` before each pipeline run
- Set `secret_id_ttl` to match the pipeline timeout
- Use `secret_id_num_uses=1` so each secret_id works exactly once

### 7. Logging Secret Values

**Problem:** `echo $DB_PASSWORD` or `vault kv get kv/data/myapp/config` without `-field` prints secrets to CI logs.

**Fix:** Use `-field` to extract specific values. Pipe secrets directly into files or environment variables. Use the platform's secret masking:
- GitHub Actions: `::add-mask::$VALUE`
- GitLab CI: Variables marked "masked" in settings
- Azure DevOps: `##vso[task.setvariable variable=X;issecret=true]`
- Jenkins: `withCredentials` block or `set +x`
- CircleCI: Secrets set via `BASH_ENV` in contexts

## Migration Guide: Static Secrets to OIDC

### Phase 1: Inventory (Week 1)

1. Audit all CI/CD variables, credentials, and secret stores across platforms
2. Classify each secret: Vault tokens, API keys, database passwords, certificates
3. Map which pipelines use which secrets and in which stages

### Phase 2: Vault Infrastructure (Week 2)

1. Deploy or configure Vault with JWT auth backends — one per CI platform
2. Configure OIDC discovery for each platform
3. Create Vault policies following least-privilege (see Common Patterns above)
4. Create Vault roles with tight bound_claims per project and branch

### Phase 3: Parallel Run (Weeks 3-4)

1. Add OIDC auth to pipelines alongside existing static secrets
2. Run both paths; verify OIDC-fetched secrets match static ones
3. Add monitoring: track Vault auth success/failure rates per platform
4. Validate token TTLs and revocation patterns

### Phase 4: Cutover (Week 5)

1. Remove static secrets from CI/CD variables one pipeline at a time
2. Start with non-production environments
3. Monitor for auth failures — common causes:
   - Bound claims mismatch (branch name, project path format)
   - Audience mismatch (URL trailing slash, case sensitivity)
   - Clock skew between CI runner and Vault (>60s causes JWT validation failures)
4. Production cutover after 48h clean run on staging

### Phase 5: Hardening (Week 6)

1. Enable Vault audit logging for all JWT auth paths
2. Set up alerts for: auth failures, token creation spikes, policy violations
3. Rotate any remaining AppRole secret_ids to short TTLs
4. Document the new auth flow for each pipeline in the repo's CI docs
5. Remove the old static secret variables from all CI/CD platforms

## Platform-Specific Files in This Repository

| Platform | Auth Template | Full Pipeline Example |
|---|---|---|
| GitHub Actions | `platform/github-actions/reusable/oidc-vault-auth.yml` | `platform/github-actions/workflows/deploy-with-secrets.yml` |
| GitLab CI | `platform/gitlab-ci/vault-oidc-auth.yml` | `platform/gitlab-ci/pipeline-example.yml` |
| Azure DevOps | `platform/azure-pipelines/vault-oidc-auth.yml` | `platform/azure-pipelines/pipeline-example.yml` |
| Jenkins | `platform/jenkins/Jenkinsfile-vault` | `platform/jenkins/vault-shared-library.groovy` |
| CircleCI | `platform/circleci/config.yml` | `platform/circleci/config.yml` (commands + workflow) |

## Vault JWT Auth Debugging

When OIDC auth fails, check these in order:

1. **Discovery URL reachable from Vault?** `curl -s https://gitlab.com/.well-known/openid-configuration | jq .`
2. **Issuer matches?** The `iss` claim in the JWT must exactly match `bound_issuer` in Vault config (trailing slashes matter).
3. **Audience matches?** The `aud` claim must be in `bound_audiences`. Decode the JWT at `jwt.io` to verify.
4. **Claims match?** `vault read auth/jwt/MOUNT/role/ROLE` shows `bound_claims`. Compare against the JWT's actual claims.
5. **Clock skew?** JWTs have `iat` and `exp` timestamps. If the CI runner's clock is >60s off from Vault's clock, validation fails. Check with `date -u` on both systems.
6. **Token expired?** CI OIDC tokens are short-lived (typically 5-10 minutes). If the auth step takes too long, the token may expire before Vault validates it.
