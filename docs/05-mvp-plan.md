# MVP Plan

## MVP objective

Deliver a first working security control plane for development and platform operations that proves the architecture with real workflows.

## MVP scope

### Required in MVP
1. **Developer authentication**
   - centralized sign-in
   - privileged group gating
   - documented local bootstrap flow

2. **Repository encryption**
   - SOPS configuration in place
   - one encrypted config path per environment
   - merge blocking for plaintext secrets

3. **CI federation**
   - GitHub OIDC or equivalent for one cloud and/or Vault
   - zero long-lived deployment credentials stored in repo settings

4. **Runtime secret delivery**
   - one Kubernetes app using External Secrets or CSI
   - one VM or service using Vault Agent or equivalent runtime retrieval

5. **Dynamic credentials**
   - one database role using dynamic credentials
   - enforced TTL and attributable access

6. **Certificates**
   - one certificate issuance path for workloads
   - one administrative or machine certificate path for dev-related operations

7. **Administrative access**
   - short-lived SSH access model or cloud-control-plane admin access
   - no single-operator key dependency

### Explicitly deferred
- broad service mesh rollout
- full artifact signing program
- full privileged access management automation
- migration of every legacy application in wave one

## Suggested MVP sequence

### Sprint 0 — design and selection
- pick the central broker model
- choose key authority per environment
- define trust domains
- define naming conventions, namespaces, and role model

### Sprint 1 — repository and CI rails
- implement `.sops.yaml`
- implement guardrail scripts and merge checks
- implement GitHub OIDC trust to target cloud and/or Vault
- test end-to-end on a non-production repo

### Sprint 2 — runtime secret pilot
- choose one Kubernetes app
- choose one secret delivery method
- issue least-privileged policy
- validate rotation and revocation behavior

### Sprint 3 — dynamic credentials and certificates
- enable dynamic DB credentials
- issue workload certificates through cert-manager or equivalent
- validate lease behavior and app restart behavior

### Sprint 4 — admin access modernization
- implement SSH CA or control-plane access
- document and test break-glass
- remove unmanaged legacy admin keys where possible

## MVP exit criteria

- secrets in Git are encrypted
- CI runs without long-lived cloud or Vault secrets
- a live app receives secrets centrally
- at least one dynamic credential path exists
- at least one certificate issuance path exists
- admin access is centralized and attributable
- break-glass is documented and tested
