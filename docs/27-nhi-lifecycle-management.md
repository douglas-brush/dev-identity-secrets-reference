# Non-Human Identity (NHI) Lifecycle Management

## Purpose

Non-human identities are the dominant identity class in every modern environment and the least governed. This document establishes a lifecycle management framework for NHIs across this architecture — covering inventory, provisioning, rotation, monitoring, deprovisioning, and audit — with explicit mappings to the OWASP Non-Human Identity Top 10 (2025).

---

## 1. What Are Non-Human Identities?

A non-human identity (NHI) is any credential, token, certificate, or role that authenticates a machine, service, or automation process rather than a human operator. NHIs include:

| NHI Type | Examples | Typical Lifetime | This Architecture's Pattern |
|----------|----------|------------------|-----------------------------|
| Service accounts | Kubernetes ServiceAccounts, cloud IAM service accounts, database service users | Indefinite (if not managed) | One per workload, scoped by namespace (`docs/06-controls-and-guardrails.md` C3) |
| API keys | SaaS integrations, third-party service connectors, webhook signing keys | Months to years | Vault KV v2 with TTL-enforced rotation (`tools/rotate/rotate_vault_secrets.sh`) |
| OAuth client credentials | Machine-to-machine OAuth2 flows, service-to-service API auth | Varies by provider | Short-lived token exchange; client secrets stored in Vault |
| Machine certificates | mTLS workload certificates, TLS server certificates | Hours to days (dynamic) | Vault PKI engine with automated renewal (`docs/16-mtls-workload-identity-guide.md`) |
| Bot tokens | CI bots, ChatOps integrations, automation service tokens | Often indefinite | Scoped to specific repos/channels; inventoried in `tools/audit/identity_inventory.sh` |
| CI/CD service principals | GitHub Actions OIDC, GitLab CI tokens, Jenkins service connections | Per-pipeline (ephemeral) | OIDC federation — no stored credentials (`platform/ci-integration-guide.md`) |
| Kubernetes service accounts | Pod identity, projected token volumes | Bound to pod lifecycle | Token projection with audience binding and TTL |
| Cloud IAM roles | AWS IAM roles, Azure Managed Identities, GCP service accounts | Indefinite (role persists; credentials are ephemeral via STS) | Vault dynamic credentials or cloud-native workload identity |
| Database users | Application connection credentials, replication users, monitoring agents | Dynamic (minutes) or static | Vault database secrets engine for dynamic, KV v2 for legacy static |
| SSH keys | Machine-to-machine SSH, deployment keys, Git deploy keys | Often indefinite (the problem) | SSH CA with short-lived signed certificates (`docs/02-reference-architecture.md`) |
| SPIFFE SVIDs | Workload identity documents in SPIFFE-enabled meshes | Minutes | SPIRE agent auto-rotation; no stored key material |

### The scale problem

NHIs outnumber human identities by 10-50x in typical enterprise environments. A mid-size engineering org with 200 developers commonly has 2,000-10,000 NHIs across cloud accounts, Kubernetes clusters, SaaS integrations, and CI/CD pipelines. Most organizations cannot answer basic questions: how many NHIs exist, who owns them, when they were last used, or what permissions they hold.

This gap is not a theoretical concern. Compromised NHIs are the initial access vector in the majority of cloud breaches. The attack surface is large because NHIs are provisioned quickly, rarely inventoried, almost never deprovisioned, and frequently overprivileged.

---

## 2. OWASP NHI Top 10 (2025) — Risk Mapping

The OWASP Non-Human Identities Top 10 (released 2025) codifies the ten most critical risks to machine/service credentials. The table below maps each risk to this architecture's controls, referencing specific documents and tools.

### NHI1: Improper Offboarding

**Risk:** Orphaned credentials persist after the owning team, service, or project is decommissioned. These become unmonitored, unrotated attack surface.

**This architecture's mitigations:**
- `tools/audit/identity_inventory.sh` enumerates all NHIs across Vault and Kubernetes with ownership metadata
- `tools/audit/credential_age_report.sh` flags credentials exceeding the 90-day rotation policy, surfacing likely orphans
- Guardrail Rule 3 (`docs/06-controls-and-guardrails.md`): every automation identity must have a clear owner, defined purpose, TTL, and revocation path
- Vault lease expiration automatically cleans up dynamic credentials that are not renewed — orphaned workloads lose access when leases expire
- Quarterly access review process (Section 4: Audit phase below) catches NHIs whose owners have left

**Residual risk:** Static credentials stored outside Vault (SaaS API keys, third-party integrations) require manual offboarding discipline. The inventory tool reduces but does not eliminate this gap.

### NHI2: Secret Leakage

**Risk:** Credentials exposed in source code, CI logs, configuration files, error messages, or container images.

**This architecture's mitigations:**
- Control C1 (`docs/06-controls-and-guardrails.md`): secrets never enter Git in plaintext — enforced by SOPS, pre-commit hooks, merge blocking, and repo scanning
- `tools/secrets-doctor/doctor.sh` runs comprehensive diagnostic checks including Git history scanning for leaked secrets
- `tools/scanning/` provides repo-level secret detection
- Threat T1 (`docs/07-threat-model.md`): plaintext secret in Git is the first enumerated threat with four layered mitigations
- Vault audit logging captures every secret read — leaked credentials can be traced to the accessor and rotated
- CI pipelines use OIDC federation, so there are no stored secrets to leak from CI configuration

**Residual risk:** Developer workstation memory, debug logs, and clipboard history remain vectors. Short credential TTLs limit the window of exposure.

### NHI3: Vulnerable Third-Party NHI

**Risk:** Third-party integrations (SaaS vendors, partner APIs, supply chain tools) are granted NHI access that is overprivileged, unmonitored, or uses compromised libraries.

**This architecture's mitigations:**
- Vault acts as a choke point: third-party integrations that need credentials receive them through Vault with scoped policies and TTLs
- OPA policies (`tests/opa/`) enforce that third-party access paths cannot exceed defined permission boundaries
- `tools/secrets-doctor/checks/` validates that third-party auth configurations meet baseline security requirements
- The reference architecture (`docs/02-reference-architecture.md`) positions Vault as the central broker — third parties do not receive direct cloud IAM credentials

**Residual risk:** SaaS-to-SaaS OAuth grants that bypass Vault are a blind spot. These require periodic review at the IdP level.

### NHI4: Insecure Authentication

**Risk:** NHIs use weak authentication mechanisms — static API keys, shared passwords, unauthenticated internal services, or credentials transmitted in cleartext.

**This architecture's mitigations:**
- OIDC federation for all CI/CD eliminates static credentials entirely (`platform/ci-integration-guide.md`)
- mTLS for service-to-service communication provides mutual cryptographic authentication (`docs/16-mtls-workload-identity-guide.md`)
- Vault requires authenticated sessions for all secret access — no anonymous read paths
- SSH CA replaces static SSH keys with short-lived signed certificates (`docs/02-reference-architecture.md`)
- Kubernetes service account token projection replaces legacy long-lived tokens with audience-bound, time-limited JWTs
- Security hardening checklist items V-11 through V-16 (`docs/26-security-hardening-checklist.md`) verify that all auth methods are properly bound

**Residual risk:** Legacy applications that cannot support modern auth methods may require static credentials as an exception, documented in the decision log (`docs/08-decision-log.md`).

### NHI5: Overprivileged NHI

**Risk:** Service accounts and machine credentials accumulate permissions beyond what they need, expanding blast radius on compromise.

**This architecture's mitigations:**
- Control C3: workloads get only the secrets they need — one service account per workload, separate stores/roles per environment, no wildcard access
- Vault policies enforce least privilege at the path level — each role has explicit `capabilities` on specific paths
- Sentinel policies (if Enterprise) provide additional governance guardrails (`platform/vault/sentinel/`)
- JIT access patterns (`docs/17-jit-access-patterns.md`) ensure that elevated privileges are time-bounded and audited, not standing
- `tools/audit/credential_age_report.sh` combined with Vault audit logs can identify credentials with permissions that are granted but never exercised

**Residual risk:** Cloud IAM policies managed outside Vault may drift. Cloud-native tools (AWS Access Advisor, Azure sign-in logs) should supplement Vault-side controls.

### NHI6: Insecure Cloud Deployment Configuration

**Risk:** Cloud IAM roles, instance profiles, and service account bindings are misconfigured — overly permissive trust policies, missing condition keys, or cross-account trust without proper constraints.

**This architecture's mitigations:**
- Vault dynamic credentials for AWS/Azure/GCP generate scoped, short-lived cloud credentials rather than relying on static IAM configuration
- OIDC federation configurations enforce `bound_claims` restricting repository, branch, and environment (`platform/ci-integration-guide.md`)
- Guardrail Rule 2: every environment gets separate namespaces, KMS references, secret paths, and Vault roles — no cross-environment bleed
- OPA policies can validate cloud IAM configurations against organizational standards
- The architecture overview (`docs/22-architecture-overview.md`) enforces identity plane separation from the runtime delivery plane

**Residual risk:** Terraform/IaC misconfigurations that create overly permissive cloud IAM outside this architecture's control. Integrate cloud security posture management (CSPM) tooling.

### NHI7: Long-Lived Credentials

**Risk:** Credentials that never expire or rotate create persistent attack surface. A compromised long-lived credential provides indefinite access.

**This architecture's mitigations:**
- Vault dynamic secrets engines are the primary credential pattern — database credentials, cloud access keys, and certificates are issued with TTLs measured in minutes to hours
- `tools/rotate/rotate_vault_secrets.sh` handles rotation of credentials that must remain in Vault KV
- `tools/rotate/rotate_sops_keys.sh` rotates the encryption keys protecting Git-stored secrets
- `tools/audit/credential_age_report.sh` enforces a 90-day maximum age policy and flags violations
- Control C2: CI never relies on long-lived deployment credentials
- SSH CA issues certificates with TTLs, not permanent keys
- Vault PKI issues short-lived workload certificates with automated renewal
- Security hardening item V-08: token TTLs capped at 24h for services, 8h for humans

**Residual risk:** Some third-party SaaS APIs only support static API keys. These are tracked in Vault KV with enforced rotation schedules and flagged by the credential age report.

### NHI8: Environment Isolation Failure

**Risk:** NHIs from one environment (dev, staging) can access resources in another (production), or a single compromised credential crosses environment boundaries.

**This architecture's mitigations:**
- Guardrail Rule 2: every environment gets separate namespaces, KMS/key references, secret paths, Vault roles, and CA policy
- Vault policies scope access by environment path (`secret/data/prod/*` vs `secret/data/dev/*`)
- Kubernetes namespace isolation with per-namespace service accounts
- OIDC bound claims include environment constraints — a staging CI pipeline cannot authenticate to a production Vault role
- SOPS uses per-environment encryption keys — a dev SOPS key cannot decrypt production values

**Residual risk:** Shared infrastructure components (monitoring, logging) that span environments may have cross-environment NHIs by design. These should be explicitly documented and minimally privileged.

### NHI9: NHI Reuse

**Risk:** Multiple services share a single service account, API key, or credential. Compromise of one service exposes all. Attribution is impossible.

**This architecture's mitigations:**
- Control C3: one service account per workload — explicitly prohibits shared credentials
- Vault roles are created per-service, not per-team or per-environment
- Kubernetes ServiceAccounts are created per-deployment, not shared across pods
- Dynamic credentials from Vault are unique per lease — two services requesting database access get different username/password pairs
- `tools/audit/identity_inventory.sh` can detect shared service accounts by comparing NHI-to-workload mappings

**Residual risk:** Legacy applications that share database connection pools with a single credential. Migration path: Vault database dynamic credentials with per-service roles.

### NHI10: Human Use of NHI

**Risk:** Humans authenticate using service accounts to bypass MFA, audit logging, or access controls. This defeats identity governance and makes attribution impossible.

**This architecture's mitigations:**
- The identity plane (`docs/02-reference-architecture.md`) separates human auth (IdP + OIDC + MFA) from machine auth (AppRole, Kubernetes, cloud IAM)
- Vault auth methods are configured so that human-facing methods (OIDC) and machine-facing methods (AppRole, Kubernetes, JWT) bind to different policy sets
- Guardrail Rule 4: every human admin path must be attributable, time-bounded, reviewable
- Vault audit logs capture the auth method and accessor for every operation — human use of machine auth methods produces anomalous audit patterns detectable by SIEM correlation
- JIT access (`docs/17-jit-access-patterns.md`) provides legitimate elevated access without needing to borrow a service account

**Residual risk:** SSH keys shared between humans and automation. The SSH CA pattern eliminates this by issuing per-identity certificates with embedded principals.

---

## 3. NHI Inventory Template

Use this template to maintain a living inventory of all non-human identities. The inventory should be stored in a controlled location (internal wiki, CMDB, or version-controlled YAML) and reviewed quarterly.

### Inventory Table

| ID | Type | Owner | Created | Last Used | Max TTL | Environment | Permissions | Review Date | Status |
|----|------|-------|---------|-----------|---------|-------------|-------------|-------------|--------|
| NHI-001 | Vault AppRole | platform-team@org | 2025-01-15 | 2025-03-10 | 24h (dynamic) | prod | `secret/data/prod/api-gateway/*` read | 2025-04-01 | Active |
| NHI-002 | K8s ServiceAccount | payments-team@org | 2025-02-01 | 2025-03-14 | Bound to pod | prod | `payments` namespace, Vault `payments-prod` role | 2025-04-01 | Active |
| NHI-003 | GitHub OIDC | ci-team@org | 2025-01-20 | 2025-03-15 | 15m per pipeline | ci | `ci-issuer` Vault policy, `myorg/myrepo` bound | 2025-04-01 | Active |
| NHI-004 | AWS IAM Role | infra-team@org | 2024-11-01 | 2025-03-12 | 1h (STS) | prod | `arn:aws:iam::role/vault-dynamic-*` assume | 2025-04-01 | Active |
| NHI-005 | Database User | data-team@org | 2025-03-01 | 2025-03-15 | 30m (dynamic) | staging | `SELECT, INSERT` on `orders.*` | 2025-06-01 | Active |
| NHI-006 | SSH Deploy Key | legacy-team@org | 2023-06-15 | 2024-12-01 | None (static) | prod | `git clone` on `myorg/legacy-app` | 2025-01-15 | REVIEW — unused 3+ months, candidate for decommission |
| NHI-007 | SaaS API Key | integrations@org | 2024-03-01 | 2025-03-14 | 90d rotation | prod | Vendor X webhook delivery | 2025-06-01 | Active — rotation due 2025-05-30 |

### Inventory Fields

| Field | Description | Required |
|-------|-------------|----------|
| ID | Unique identifier (NHI-NNN) | Yes |
| Type | Credential class: Vault AppRole, K8s SA, OIDC, IAM Role, API Key, SSH Key, Certificate, Database User, Bot Token | Yes |
| Owner | Team or individual responsible for this NHI — email or team alias | Yes |
| Created | Date the NHI was provisioned (ISO 8601) | Yes |
| Last Used | Most recent authentication or credential issuance event | Yes |
| Max TTL | Maximum credential lifetime per use (or "static" if no TTL) | Yes |
| Environment | dev / staging / prod / ci / shared | Yes |
| Permissions | Summary of access granted — Vault policy paths, IAM actions, database grants | Yes |
| Review Date | Next scheduled review (quarterly minimum) | Yes |
| Status | Active / Under Review / Decommission Pending / Decommissioned | Yes |

### Automated Inventory Generation

The `tools/audit/identity_inventory.sh` script produces a machine-readable inventory by enumerating:

- Vault auth accessors and role bindings
- Kubernetes ServiceAccounts across namespaces
- Vault lease metadata (active dynamic credentials)
- Certificate serial numbers from Vault PKI

Run quarterly or integrate into CI:

```bash
# Generate JSON inventory
tools/audit/identity_inventory.sh --json > logs/nhi-inventory-$(date +%Y%m%d).json

# Generate with namespace filter
tools/audit/identity_inventory.sh --namespace prod --verbose
```

---

## 4. Lifecycle Phases

### Phase 1: Provisioning

Every NHI must be provisioned through a controlled process with least-privilege scope, an identified owner, and a defined TTL.

**Provisioning checklist:**

| Step | Action | Tooling |
|------|--------|---------|
| 1 | Define the workload's identity requirements: what does it need to access, in which environment, for how long? | Architecture review |
| 2 | Select the NHI type: prefer dynamic (Vault, OIDC, projected token) over static (API key, SSH key) | Decision tree in `diagrams/04-decision-tree.md` |
| 3 | Create the Vault role, cloud IAM binding, or Kubernetes ServiceAccount with minimum required permissions | Vault CLI / Terraform / kubectl |
| 4 | Assign an owner (team alias, not individual) and document in NHI inventory | `tools/audit/identity_inventory.sh` |
| 5 | Configure TTL/rotation: dynamic credentials get engine-level TTL; static credentials get `max_lease_ttl` and scheduled rotation | `tools/rotate/` |
| 6 | Validate with `secrets-doctor`: confirm the new NHI passes all hygiene checks | `tools/secrets-doctor/doctor.sh audit` |
| 7 | Add to monitoring: ensure Vault audit logs capture the new auth method/role | SIEM integration |

**Approval workflow:** For production NHIs, use Vault Control Groups (Enterprise) or PR-based review of Vault policy/Terraform changes. The goal is an auditable record of who approved what access and why.

**Anti-patterns to block:**
- Creating a "shared" service account for multiple services (violates C3, enables NHI9)
- Granting `admin` or wildcard permissions "to get it working" (enables NHI5)
- Provisioning without an owner field (enables NHI1 — orphaning on first team change)

### Phase 2: Rotation

Rotation ensures that compromised or leaked credentials have a bounded window of exposure. The target state is dynamic credentials that never need manual rotation.

| Credential Type | Rotation Mechanism | Target TTL | Tooling |
|-----------------|-------------------|------------|---------|
| Database credentials | Vault database secrets engine (dynamic) | 30 minutes | Vault dynamic secret request per connection |
| Cloud IAM credentials | Vault AWS/Azure/GCP secrets engine (STS) | 1 hour | Vault dynamic secret request per session |
| Workload certificates | Vault PKI engine with auto-renewal | 24-72 hours | Vault Agent / cert-manager |
| SSH certificates | Vault SSH CA | 5-30 minutes per session | `vault write ssh/sign/role` |
| Vault KV static secrets | Scheduled rotation script | 90 days maximum | `tools/rotate/rotate_vault_secrets.sh` |
| SOPS encryption keys | Key rotation with re-encryption | Annual or on compromise | `tools/rotate/rotate_sops_keys.sh` |
| Kubernetes SA tokens | Projected volume with TTL | 1 hour (configurable) | `serviceAccountToken` volume projection |
| SaaS API keys | Manual rotation with Vault KV update | 90 days (enforced by `credential_age_report.sh`) | Manual + alert |

**Rotation failure handling:**
1. `tools/audit/credential_age_report.sh --max-age 90` flags any credential exceeding the rotation policy
2. `tools/metrics/collect-metrics.sh` aggregates rotation compliance into the unified metrics dashboard
3. Failed Vault lease renewals generate audit log entries that should trigger SIEM alerts
4. The incident playbook for secret exposure (`docs/incident-playbooks/secret-exposure-response.md`) covers emergency rotation

### Phase 3: Monitoring

Continuous monitoring of NHI usage detects compromise, drift, and hygiene degradation.

**What to monitor:**

| Signal | Detection Method | Alert Threshold | Tooling |
|--------|-----------------|-----------------|---------|
| Unused NHI | No authentication events in 90 days | 90 days | `tools/audit/credential_age_report.sh`, cloud provider access logs |
| Anomalous access pattern | NHI accessing paths outside its normal baseline | Any deviation from established pattern | Vault audit log + SIEM correlation |
| Authentication failures | Repeated auth failures for a service identity | >5 failures in 10 minutes | Vault audit log `error` type entries |
| Credential age violation | Static credential exceeds maximum age policy | >90 days | `tools/audit/credential_age_report.sh` |
| Lease explosion | Unexpected spike in active Vault leases | >2x baseline | `vault operator usage` + monitoring |
| Cross-environment access | NHI authenticating from unexpected environment | Any occurrence | Vault audit log source IP correlation |
| Certificate expiry | Workload cert approaching expiry without renewal | <24h before expiry | `tools/audit/cert_monitor.sh` |
| Permission escalation | NHI policy change granting broader access | Any policy modification | Vault audit log `sys/policy` writes |

**Vault audit log integration:**

Vault audit logs are the single richest source of NHI activity data. Every secret read, credential issuance, authentication event, and policy evaluation is logged. Forward these to your SIEM and build correlation rules for:

- Service accounts authenticating from unexpected source IPs
- Credentials used outside their normal time windows
- Auth methods being used by unexpected accessor types (NHI10 detection)
- Lease creation spikes that may indicate credential harvesting

### Phase 4: Deprovisioning

Deprovisioning is where most organizations fail. The architecture provides multiple automatic and manual deprovisioning mechanisms.

**Automatic deprovisioning (built into the architecture):**

| Mechanism | What It Decommissions | Trigger |
|-----------|----------------------|---------|
| Vault lease expiry | Dynamic database creds, cloud STS tokens, certificates | TTL expiration without renewal |
| Kubernetes pod termination | Projected service account tokens | Pod deletion (token is not valid outside pod lifecycle) |
| OIDC token expiry | CI/CD pipeline credentials | Pipeline completion (token TTL, typically 10-15 minutes) |
| Vault token revocation | All leases associated with a Vault token | Token TTL expiry or explicit revocation |

**Manual deprovisioning (requires process discipline):**

| Trigger | Actions | Tooling |
|---------|---------|---------|
| Service decommission | Remove Vault role, delete Kubernetes SA, revoke outstanding leases, remove from NHI inventory | Vault CLI, kubectl, inventory update |
| Team offboarding | Transfer NHI ownership or decommission NHIs owned by departing team members | `tools/audit/identity_inventory.sh` to identify owned NHIs |
| Security incident | Emergency revocation of compromised NHI, rotate all credentials it could access | `docs/incident-playbooks/secret-exposure-response.md`, `docs/incident-playbooks/break-glass-procedure.md` |
| Quarterly review finding | Decommission NHIs flagged as unused, orphaned, or overprivileged | Review process (Section 4: Audit) |

**Orphan detection:**

Run the following to identify candidates for decommissioning:

```bash
# Credentials older than 90 days with no recent use
tools/audit/credential_age_report.sh --max-age 90 --format csv | grep -i "violation"

# Full identity inventory with last-used timestamps
tools/audit/identity_inventory.sh --json | jq '.identities[] | select(.last_used == null or .age_days > 180)'
```

### Phase 5: Audit

Quarterly NHI audits validate that the inventory is accurate, permissions are still appropriate, and lifecycle controls are functioning.

**Quarterly audit checklist:**

| # | Check | Evidence Source | Pass Criteria |
|---|-------|-----------------|---------------|
| A-01 | NHI inventory is complete and current | `tools/audit/identity_inventory.sh` output vs. manual inventory | No undocumented NHIs |
| A-02 | All NHIs have assigned owners | NHI inventory `Owner` field | 100% ownership coverage |
| A-03 | No credentials exceed maximum age policy | `tools/audit/credential_age_report.sh` | Zero violations |
| A-04 | Unused NHIs are flagged for decommission | Last-used timestamps from Vault audit logs and cloud access logs | All NHIs unused >90 days are in review status |
| A-05 | No overprivileged NHIs | Vault policy review, cloud IAM access advisor | All permissions justified by current workload needs |
| A-06 | Environment isolation is intact | Vault policy paths, OIDC bound claims, namespace bindings | Zero cross-environment access paths |
| A-07 | Dynamic credentials dominate over static | Metrics from `tools/metrics/collect-metrics.sh` | >80% of credential issuances are dynamic |
| A-08 | No human use of service accounts | Vault audit log auth method analysis | Zero OIDC/human auth methods on machine-designated roles |
| A-09 | Rotation schedules are being met | `credential_age_report.sh` historical trends | Rotation compliance >95% |
| A-10 | Break-glass NHIs are tested and current | Drill logs from `tools/drill/` | Last drill within 90 days |

**Compliance evidence generation:**

```bash
# Generate comprehensive evidence package
tools/compliance/generate_evidence.sh

# Collect metrics with trend comparison
tools/metrics/collect-metrics.sh --baseline logs/metrics/previous-quarter.json --output logs/metrics/current-quarter.json
```

The compliance automation framework (`docs/21-compliance-automation.md`) integrates NHI audit evidence into broader compliance reporting for SOC 2, PCI DSS, and NIST 800-53 requirements.

---

## 5. Implementation Patterns

### Pattern 1: Vault Dynamic Credentials (Primary)

Vault dynamic secrets engines are the default NHI pattern for this architecture. The credential does not exist until requested, is unique per consumer, has a hard TTL, and is automatically revoked on expiry.

**Supported engines:**

| Engine | Use Case | TTL Range | Rotation |
|--------|----------|-----------|----------|
| `database` | Application database access | 5m - 24h | New credential per lease |
| `aws` | AWS API access via STS | 15m - 12h | New STS token per lease |
| `azure` | Azure API access | 15m - 24h | New service principal or MSI token per lease |
| `gcp` | GCP API access | 15m - 24h | New OAuth token or service account key per lease |
| `pki` | X.509 workload certificates | 1h - 72h | New certificate per request |
| `ssh` | SSH signed certificates | 5m - 8h | New certificate per session |
| `consul` | Consul ACL tokens | 15m - 24h | New token per lease |
| `rabbitmq` | RabbitMQ credentials | 5m - 24h | New user per lease |

**Why this is superior to static credentials:** No credential exists to steal when the workload is idle. Credential compromise is time-bounded. Every credential issuance is a distinct audit event. Credential sharing is impossible (each lease is unique). Revocation is automatic.

### Pattern 2: OIDC Federation for CI/CD

OIDC federation eliminates NHIs from CI/CD entirely. The CI platform issues a signed JWT asserting the pipeline's identity (repository, branch, environment). Vault validates this JWT against the platform's JWKS endpoint and issues scoped, short-lived credentials.

**Supported platforms:** GitHub Actions, GitLab CI, Azure DevOps, Jenkins, CircleCI, Bitbucket Pipelines (full configuration in `platform/ci-integration-guide.md`).

**What this eliminates:**
- Static `VAULT_TOKEN` in CI secrets
- Cloud access keys stored in CI configuration
- Service account JSON keys checked into repos or uploaded to CI
- Long-lived deploy tokens

**Bound claims for defense in depth:**

```
bound_claims = {
  "repository" = "myorg/myrepo"       # Only this repo
  "ref"        = "refs/heads/main"     # Only main branch
  "environment"= "production"          # Only production deploys
}
token_ttl     = "600"                  # 10 minutes maximum
token_max_ttl = "900"                  # Hard ceiling at 15 minutes
```

### Pattern 3: SSH CA for Machine-to-Machine

The Vault SSH secrets engine acts as a certificate authority, issuing short-lived signed certificates instead of distributing static SSH keys.

**Advantages over static SSH keys:**
- Certificates expire automatically (no orphaned access)
- Each certificate embeds the requesting identity (full attribution)
- Revocation is not needed for short-lived certs — they expire before a CRL check matters
- No `authorized_keys` file management across fleets
- Key material never leaves the issuing system

**Implementation:** See `docs/02-reference-architecture.md` (SSH CA pattern) and the JIT access patterns for SSH in `docs/17-jit-access-patterns.md`.

### Pattern 4: SPIFFE/SPIRE for Workload Identity

SPIFFE (Secure Production Identity Framework for Everyone) provides automatic, attestation-based workload identity. SPIRE (the SPIFFE Runtime Environment) issues SVIDs (SPIFFE Verifiable Identity Documents) to workloads based on platform attestation — no stored secrets, no manual provisioning.

**How it works:**
1. SPIRE Agent runs on each node and attests workloads based on kernel-level identity (PID, cgroup, namespace, container image hash)
2. SPIRE Server issues an X.509 SVID or JWT SVID to the attested workload
3. The SVID has a short TTL (minutes) and is automatically rotated by the SPIRE Agent
4. Services use SVIDs for mTLS or JWT-based authentication to each other

**When to use SPIFFE/SPIRE vs. Vault PKI:**
- SPIFFE/SPIRE when you need automatic, zero-touch workload identity across heterogeneous platforms
- Vault PKI when you need certificate issuance integrated with Vault's policy engine and audit logging
- Both can coexist: SPIRE for east-west service mesh identity, Vault PKI for north-south and compliance-sensitive certificate issuance

### Pattern 5: Kubernetes Service Account Token Projection

Kubernetes projected service account tokens replace the legacy non-expiring SA tokens with audience-bound, time-limited JWTs.

**Configuration:**
```yaml
volumes:
  - name: vault-token
    projected:
      sources:
        - serviceAccountToken:
            path: vault-token
            expirationSeconds: 3600    # 1 hour TTL
            audience: vault            # Bound to Vault audience
```

**Why this matters for NHI lifecycle:**
- Token is valid only for the specified audience (Vault, not arbitrary services)
- Token expires and is automatically re-projected by kubelet
- Token is bound to the pod — cannot be extracted and used elsewhere after pod termination
- Vault Kubernetes auth validates the projected token against the cluster's TokenReview API

---

## 6. NHI Hygiene Automation

### Repository Tools

| Tool | Purpose | Frequency | Command |
|------|---------|-----------|---------|
| `tools/audit/credential_age_report.sh` | Flag credentials exceeding rotation policy | Weekly or CI-integrated | `credential_age_report.sh --max-age 90 --format json` |
| `tools/audit/identity_inventory.sh` | Enumerate all NHIs across Vault and Kubernetes | Quarterly (minimum) | `identity_inventory.sh --json --verbose` |
| `tools/audit/cert_inventory.sh` | Inventory all certificates from Vault PKI | Monthly | `cert_inventory.sh` |
| `tools/audit/cert_monitor.sh` | Alert on certificates approaching expiry | Daily (cron or CI) | `cert_monitor.sh` |
| `tools/secrets-doctor/doctor.sh` | Comprehensive secrets infrastructure health check | Per-session or CI-gated | `doctor.sh all --json` |
| `tools/rotate/rotate_vault_secrets.sh` | Rotate static secrets stored in Vault KV | Per rotation schedule | `rotate_vault_secrets.sh` |
| `tools/rotate/rotate_sops_keys.sh` | Rotate SOPS encryption keys and re-encrypt | Annually or on compromise | `rotate_sops_keys.sh` |
| `tools/metrics/collect-metrics.sh` | Aggregate all metrics into unified dashboard | Weekly | `collect-metrics.sh --output logs/metrics/weekly.json` |
| `tools/metrics/risk-scorer.sh` | Score overall NHI risk posture | Quarterly | `risk-scorer.sh` |
| `tools/compliance/generate_evidence.sh` | Generate compliance evidence package | Quarterly or audit-triggered | `generate_evidence.sh` |

### Vault Lease Monitoring

Active Vault leases represent live NHI credentials. Monitoring lease counts and lifetimes provides early warning of:

- Lease explosion (possible credential harvesting or runaway automation)
- Lease accumulation (renewals without revocation — possible orphaned consumers)
- Lease TTL violations (leases being renewed beyond expected lifetimes)

**Key Vault queries:**

```bash
# Count active leases by prefix
vault list -format=json sys/leases/lookup/database/creds/ | jq length

# Inspect a specific lease
vault write sys/leases/lookup lease_id="database/creds/myapp/LEASE_ID"

# Revoke all leases for a decommissioned service
vault lease revoke -prefix database/creds/decommissioned-service/
```

### Cloud IAM Unused Credential Reports

Cloud providers offer native tools for identifying unused NHIs. These supplement the Vault-centric tooling:

| Cloud | Tool | What It Reports | Access Method |
|-------|------|-----------------|---------------|
| AWS | IAM Access Advisor | Last-accessed timestamps for each IAM policy/service | `aws iam get-service-last-accessed-details` |
| AWS | IAM Credential Report | Age, last-used, rotation status for all IAM users | `aws iam generate-credential-report` |
| Azure | Entra ID Sign-in Logs | Last sign-in for service principals and managed identities | Azure Portal > Entra ID > Sign-in Logs (Service Principal) |
| Azure | Access Reviews | Automated periodic review of access grants | Azure Portal > Identity Governance > Access Reviews |
| GCP | IAM Policy Analyzer | Permissions granted vs. permissions used | `gcloud asset analyze-iam-policy` |
| GCP | Service Account Insights | Unused service accounts and keys | `gcloud recommender insights list --insight-type=google.iam.serviceAccount.Insight` |

Integrate cloud-native reports with the quarterly audit (Section 4, Phase 5) to catch NHIs that exist outside the Vault perimeter.

---

## 7. Metrics and KPIs

Track these metrics to measure NHI lifecycle management maturity and identify regression.

### Core Metrics

| Metric | Target | Measurement Method | Alert Threshold |
|--------|--------|--------------------|-----------------|
| % of NHIs with known owners | 100% | `identity_inventory.sh` — count NHIs with non-empty owner field / total NHIs | <95% |
| Mean credential age (static creds) | <45 days | `credential_age_report.sh` — average age across all static credentials | >60 days |
| % using dynamic/short-lived credentials | >80% | Vault lease creation count vs. static credential read count from audit logs | <70% |
| Time to deprovision after owner offboarding | <48 hours | HR offboarding trigger → NHI decommission timestamp (manual tracking until automated) | >7 days |
| Orphaned credential count | 0 | NHIs with no owner or no use in >90 days from `identity_inventory.sh` | >0 (any orphan triggers review) |
| Credential age policy violations | 0 | `credential_age_report.sh --max-age 90` violation count | >0 |
| Mean time to rotate after compromise | <4 hours | Incident response logs — detection to rotation completion | >24 hours |
| Cross-environment NHI count | Documented exceptions only | Vault policy audit — NHIs with policies spanning multiple environment paths | Any undocumented |
| Shared NHI count (reused across services) | 0 | `identity_inventory.sh` — NHIs mapped to >1 workload | >0 |
| Human use of NHI incidents | 0 | Vault audit log analysis — human auth methods on machine-designated roles | >0 |

### Maturity Model

| Level | Description | Key Indicators |
|-------|-------------|----------------|
| **1 — Ad Hoc** | NHIs are created on demand with no inventory, no rotation, no ownership tracking | No inventory exists; credentials are years old; shared service accounts are common |
| **2 — Documented** | NHI inventory exists; rotation policies are defined; owners are assigned | Inventory covers >80% of NHIs; rotation policy exists but compliance is <50% |
| **3 — Managed** | Dynamic credentials are the default; automated rotation is in place; quarterly audits occur | >70% dynamic credentials; rotation compliance >90%; quarterly audit evidence exists |
| **4 — Measured** | Metrics are tracked continuously; anomaly detection is operational; deprovisioning is partially automated | All core metrics tracked; mean credential age <45 days; orphan count trending to zero |
| **5 — Optimized** | NHI lifecycle is fully automated; SPIFFE/workload identity eliminates most stored credentials; human intervention is exception-only | >95% dynamic/ephemeral credentials; deprovisioning is automated; zero orphans; zero shared NHIs |

### Reporting Cadence

| Report | Frequency | Audience | Generator |
|--------|-----------|----------|-----------|
| NHI hygiene dashboard | Weekly | Engineering leads, security team | `tools/metrics/collect-metrics.sh` |
| Credential age compliance | Weekly | Service owners (for their NHIs) | `tools/audit/credential_age_report.sh` |
| Full NHI inventory | Quarterly | Security team, compliance, management | `tools/audit/identity_inventory.sh` |
| NHI risk score | Quarterly | CISO, risk committee | `tools/metrics/risk-scorer.sh` |
| Compliance evidence package | Quarterly or on-demand | Auditors, compliance team | `tools/compliance/generate_evidence.sh` |

---

## Cross-References

| Topic | Document |
|-------|----------|
| Reference architecture (identity, crypto, runtime planes) | `docs/02-reference-architecture.md` |
| Controls and guardrails (C1-C6, Rules 1-4) | `docs/06-controls-and-guardrails.md` |
| Threat model | `docs/07-threat-model.md` |
| mTLS and workload identity | `docs/16-mtls-workload-identity-guide.md` |
| JIT access patterns | `docs/17-jit-access-patterns.md` |
| Compliance automation | `docs/21-compliance-automation.md` |
| Architecture overview | `docs/22-architecture-overview.md` |
| Security hardening checklist | `docs/26-security-hardening-checklist.md` |
| CI/CD OIDC integration | `platform/ci-integration-guide.md` |
| Secret exposure incident playbook | `docs/incident-playbooks/secret-exposure-response.md` |
| Break-glass procedure | `docs/incident-playbooks/break-glass-procedure.md` |
