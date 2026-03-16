# Vault Sentinel Policies (EGP)

Endpoint Governing Policies (EGP) for Vault Enterprise. These Sentinel policies enforce governance rules that cannot be expressed in standard ACL policies -- time-based restrictions, mandatory metadata, MFA requirements, and request validation.

## Policy Inventory

| Policy | File | Enforcement | Purpose |
|--------|------|-------------|---------|
| Require Reason | `require-reason.sentinel` | `hard-mandatory` | Require `X-Vault-Reason` header on privileged path access |
| Time-Bound Access | `time-bound-access.sentinel` | `soft-mandatory` | Restrict privileged operations to business hours (M-F 06:00-22:00) |
| MFA Required | `mfa-required.sentinel` | `hard-mandatory` | Require MFA identity group membership for admin operations |

## Prerequisites

- **Vault Enterprise** with Sentinel support (or Vault 1.16+ Community with EGP)
- Sentinel policies are evaluated **after** ACL policies pass
- `hard-mandatory` -- request is denied, no override possible
- `soft-mandatory` -- request is denied, but root tokens can override

## Deployment

```bash
# Deploy require-reason EGP on privileged paths
vault write sys/policies/egp/require-reason \
  policy="$(cat require-reason.sentinel)" \
  paths="kv/data/prod/*,database/creds/prod-*,sys/policies/*" \
  enforcement_level="hard-mandatory"

# Deploy time-bound-access EGP on production paths
vault write sys/policies/egp/time-bound-access \
  policy="$(cat time-bound-access.sentinel)" \
  paths="kv/data/prod/*,database/creds/prod-*" \
  enforcement_level="soft-mandatory"

# Deploy mfa-required EGP on admin operations
vault write sys/policies/egp/mfa-required \
  policy="$(cat mfa-required.sentinel)" \
  paths="sys/policies/*,sys/auth/*,sys/mounts/*,sys/audit/*" \
  enforcement_level="hard-mandatory"
```

## How Sentinel EGP Works

1. Client makes a Vault API request
2. Vault evaluates ACL policies (standard `.hcl` policies)
3. If ACL allows, Vault evaluates Sentinel EGP policies matching the request path
4. All applicable EGP policies must pass for the request to succeed
5. Failed policies return an error with the policy name and failure reason

## Testing

Sentinel policies can be tested locally with the `sentinel` CLI:

```bash
# Install sentinel CLI (requires Vault Enterprise license)
# Test a policy with mock data
sentinel test require-reason.sentinel

# Test with specific mock data
sentinel test -run "test_missing_reason" require-reason.sentinel
```

## Related

- [`../policies/`](../policies/) -- ACL policies that work alongside Sentinel
- [`../policies/break-glass.hcl`](../policies/break-glass.hcl) -- Break-glass policy designed to work with time-bound Sentinel
- [Vault Sentinel Documentation](https://developer.hashicorp.com/vault/docs/enterprise/sentinel)
