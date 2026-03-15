# Controls and Guardrails

## Control objectives

### C1. Secrets never enter Git in plaintext
Controls:
- SOPS enforced by policy and review
- merge blocking
- local pre-commit guardrails
- repo scanning

### C2. CI never relies on long-lived deployment credentials
Controls:
- OIDC federation
- per-repo / per-branch trust conditions
- short TTL access
- environment-specific roles

### C3. Workloads get only the secrets they need
Controls:
- least-privileged policies
- one service account per workload
- separate stores/roles per environment
- avoid wildcard access patterns

### C4. Certificates are not manually issued ad hoc
Controls:
- approved issuer patterns
- CA/intermediate separation by purpose
- policy-restricted issuance
- lifecycle monitoring

### C5. SSH access is not based on personal key ownership
Controls:
- SSH CA or broker
- control-plane alternatives
- revocable short-lived access
- periodic stale-access review

### C6. Break-glass is real, not theoretical
Controls:
- dual-control custody
- logged access
- explicit scope
- quarterly drills

## Guardrail rules

### Rule 1
Never store any of the following in plaintext under version control:
- private keys
- API tokens
- cloud access keys
- database passwords
- OAuth client secrets
- service account credentials
- PFX / P12 archives

### Rule 2
Every environment gets separate:
- namespaces
- KMS / key references
- secret paths
- Vault roles
- CA policy where applicable

### Rule 3
Every automation identity must have:
- a clear owner
- a defined purpose
- a TTL or renewal model
- a rotation or revocation path

### Rule 4
Every human admin path must be:
- attributable
- time-bounded where practical
- reviewable
- recoverable without one specific person’s laptop

## Decision criteria for runtime secret delivery

| Pattern | Use When | Avoid When |
|---|---|---|
| External secrets sync | app expects platform-native secrets or env vars | you want to avoid durable secret objects |
| Volume-mount driver | mounted files are acceptable and sensitivity is higher | app can only read env vars and cannot adapt |
| Secrets agent sidecar | templating, renewal, and lease handling matter | app team cannot support sidecar or file template model |
| Certificate lifecycle driver | workload identity certificates are needed | workload has no TLS/cert need |
