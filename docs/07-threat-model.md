# Threat Model

## Assumptions

- developer endpoints can be lost or compromised
- source control systems are high-value targets
- CI runners are attractive token theft targets
- Kubernetes namespaces are not equivalent to strong isolation by themselves
- insider misuse is possible
- legacy apps will force some static secret exceptions

## Threats

### T1. Plaintext secret committed to Git
Impact:
- immediate secret exposure to every clone, cache, fork, and backup

Mitigations:
- SOPS
- pre-commit guardrails
- merge blocking
- repo scanning and rotation runbook

### T2. CI workflow token misuse
Impact:
- cloud compromise, secret exfiltration, unauthorized deployment

Mitigations:
- OIDC federation
- repository and branch claim restrictions
- short TTL credentials
- environment-scoped roles

### T3. Developer laptop compromise
Impact:
- session theft, local secret theft, unauthorized admin access

Mitigations:
- managed devices
- phishing-resistant auth
- no durable local secrets by default
- short-lived credential issuance
- prompt revocation path

### T4. Kubernetes secret sprawl
Impact:
- wider blast radius than intended, difficult auditing

Mitigations:
- use CSI when appropriate
- keep one service account per app
- separate stores and roles by namespace/environment
- avoid blanket cluster-wide access

### T5. Static SSH key dependency
Impact:
- lockout, hidden access persistence, poor attribution

Mitigations:
- SSH CA / broker
- control-plane alternatives
- central revocation
- break-glass procedure

### T6. Collapsed trust domains in PKI
Impact:
- one compromise signs everything

Mitigations:
- multiple intermediates
- policy boundaries
- separate inspection trust from identity trust
- short-lived certs where automation exists

### T7. Break-glass never validated
Impact:
- recovery fails during real incident

Mitigations:
- drills
- evidence capture
- rotation after test
- two-person control
