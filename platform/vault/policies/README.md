# Vault Policy Library

Reference policies for identity-based secrets management. Each policy follows least-privilege principles with explicit deny blocks for dangerous operations.

## Policy Inventory

| Policy | File | Identity | Purpose |
|--------|------|----------|---------|
| CI Read-Only | `ci-readonly.hcl` | CI runner (build/test jobs) | Read app secrets from KV. No writes, no listing root mounts. |
| CI Deploy | `ci-deploy.hcl` | CI deploy jobs (main branch) | Read KV, generate DB creds, issue TLS certs, Transit encrypt. |
| Developer | `developer.hcl` | Human developer (OIDC) | Read/write personal KV namespace, read shared KV, dev DB creds, dev certs. |
| Security Auditor | `security-auditor.hcl` | Security/compliance team | Read audit config, list mounts, read metadata (not values), sys/health. |
| Break-Glass | `break-glass.hcl` | On-call/incident commander | Broad read access. Explicit deny on seal, policy deletion. Requires control group. |
| Rotation Agent | `rotation-agent.hcl` | Rotation automation (SA) | Read/write KV for rotation, Transit key rotate/rewrap, DB role rotation. |
| PKI Admin | `pki-admin.hcl` | Platform/security engineer | Full PKI intermediate CA management, CRL, roles, tidy. No transit/KV access. |
| Transit Only | `transit-only.hcl` | Application service account | Encrypt/decrypt/rewrap/sign/verify on named keys. No key deletion or creation. |

### Pre-existing Policies (Sprint 3)

| Policy | File | Purpose |
|--------|------|---------|
| Admin Emergency | `admin-emergency.hcl` | Legacy break-glass (superseded by `break-glass.hcl`) |
| Developer Read | `developer-read.hcl` | Minimal dev read (superseded by `developer.hcl`) |
| CI Issuer | `ci-issuer.hcl` | Tightly scoped CI for a single app |
| DB Dynamic | `db-dynamic.hcl` | Single-app dynamic DB credential policy |
| Transit App | `transit-app.hcl` | Single-app transit encrypt/decrypt/sign/verify |
| Rotation Operator | `rotation-operator.hcl` | Original rotation policy (superseded by `rotation-agent.hcl`) |
| SSH CA Operator | `ssh-ca-operator.hcl` | SSH certificate signing |

## Design Principles

1. **Explicit deny blocks** -- Every policy includes deny rules for operations outside its scope. Vault defaults to implicit deny, but explicit denies document intent and survive policy composition when tokens have multiple policies.

2. **Identity templating** -- Policies like `developer.hcl` use `{{identity.entity.name}}` to scope paths per-user without creating per-user policies.

3. **Environment boundaries** -- CI read-only cannot reach production. Developers cannot reach production. Only deploy and break-glass policies cross environment boundaries.

4. **Separation of duties** -- PKI admins cannot access transit. Transit users cannot access KV. Auditors can read metadata but never secret values.

5. **Capabilities comments** -- Each path block documents which capabilities are granted and why.

## Deployment

```bash
# Apply all policies
for f in platform/vault/policies/*.hcl; do
  name=$(basename "$f" .hcl)
  vault policy write "$name" "$f"
done

# Assign to auth roles
vault write auth/jwt/role/ci-readonly \
  bound_claims='{"repository":"org/repo"}' \
  token_policies="ci-readonly" \
  token_ttl=15m token_max_ttl=30m

vault write auth/oidc/role/developer \
  bound_audiences="vault" \
  token_policies="developer" \
  token_ttl=8h token_max_ttl=12h
```

## Policy Composition

Vault merges capabilities when a token has multiple policies. The most permissive grant wins **except** for `deny`, which always wins. This is why explicit deny blocks matter -- they prevent privilege escalation through policy composition.

Example: A developer token with both `developer` and `ci-readonly` policies still cannot access `sys/mounts` because both policies deny it.

## Related

- [`../sentinel/`](../sentinel/) -- Sentinel Endpoint Governing Policies (EGP)
- [`../../../examples/jit-access/vault-jit-policy.hcl`](../../../examples/jit-access/vault-jit-policy.hcl) -- Control group and JIT access patterns
- [`../examples/`](../examples/) -- Engine configuration examples
