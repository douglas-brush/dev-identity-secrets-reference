# Deep Dive: Development Environment Architecture

## Why dev environments need stricter centralization

Development is where security architecture usually fails first because convenience pressure is highest. That is exactly why centralized key and credential management matters more in dev than many teams admit.

The dev environment model must assume:
- engineers will need fast access
- preview and test workloads will spin up and down constantly
- tokens will be requested often
- secrets will be copied unless the workflow prevents it
- local laptops, remote dev environments, CI runners, and shared clusters all represent different risk levels

The correct response is not to ban access. The correct response is to **centralize issuance, shorten lifetime, and standardize delivery**.

---

## 1. Local developer workstation pattern

### Objectives
- no long-lived local API keys
- no permanent database passwords
- no unmanaged private SSH keys as the only admin path
- no plaintext repo secrets on disk beyond temporary, scoped use

### Recommended flow
1. Developer signs in through IdP with phishing-resistant MFA.
2. Device posture and group membership determine whether the user can request privileged access.
3. A bootstrap script or broker obtains:
   - a short-lived Vault token or equivalent
   - short-lived cloud access if needed
   - optional short-lived SSH certificate
4. Local development pulls secrets on demand from the central broker.
5. If configuration must live in Git, only SOPS-encrypted files are stored.
6. Secrets are written either:
   - to ephemeral environment variables
   - to temporary files outside the repository
   - to mounted memory-backed locations where possible

### Local workstation anti-patterns
- `.env` files committed or copied across projects
- personal cloud access keys with no expiration
- permanent admin tokens in shell history
- local private keys that nobody else can recover from or revoke centrally

---

## 2. Devcontainer / Codespace / remote development pattern

Remote dev environments amplify credential risk because developers often assume the environment is temporary and therefore safe. It is not.

### Control objectives
- the container image contains no secrets
- the repo contains no plaintext secrets
- the runtime obtains credentials after the developer identity is established
- credentials are scoped to environment and project
- credentials expire automatically

### Recommended flow
1. Developer authenticates to the remote dev environment using organizational SSO.
2. The devcontainer bootstrap process requests scoped credentials from the central broker.
3. The container receives:
   - app config from SOPS-decrypted material if needed
   - dynamic DB credentials from Vault or equivalent
   - short-lived certificates where mTLS is required
4. When the container is destroyed, credentials expire without manual cleanup.

### Why this matters
Remote dev is where teams accidentally recreate server-to-server trust as if it were personal access. That is a mistake. Treat remote dev as a runtime platform, not as a trusted personal laptop.

---

## 3. CI/CD runner pattern

### Objectives
- eliminate stored cloud credentials from CI
- eliminate static secret-manager tokens from CI
- make repo and branch context part of trust
- restrict each workflow to the minimum claims and permissions required

### Recommended flow
1. CI workload receives an OIDC token from the source control platform.
2. Cloud IAM or Vault validates trust based on repository, branch, environment, and workflow claims.
3. CI obtains only the credentials required for that job.
4. Credentials expire on short TTL and are not stored as repository secrets.

### Non-negotiable rule
**Do not solve CI authentication by storing “just one more secret” in the repository or CI platform.** That approach becomes permanent.

---

## 4. Container orchestration cluster pattern

Container orchestration platforms are where centralized secret and certificate delivery becomes operationally important. The patterns below are platform-agnostic — implement them using whatever orchestrator and tooling your platform provides.

### Use three patterns deliberately

#### A. External secrets sync
Use when:
- the application expects native platform secrets
- you need native secret references for env vars or existing packaging
- operator convenience is more important than avoiding secret objects entirely

Strength:
- easy fit for many applications

Tradeoff:
- secret material exists in platform-native secret objects

#### B. Volume-mount secret driver
Use when:
- secrets should be mounted directly into the workload filesystem
- file-based secret delivery is acceptable
- you want to reduce secret object sprawl

Strength:
- fewer durable secret objects
- works well for high-sensitivity mounted secrets

Tradeoff:
- applications must read from files or sync-to-secret must be configured intentionally

#### C. Certificate lifecycle manager
Use when:
- each workload should get its own key pair and certificate
- mTLS is required
- you want certificate lifecycle tied to workload lifecycle

Strength:
- ephemeral workload identity
- avoids shared key/cert reuse

Tradeoff:
- needs clear CA and issuer design

### Additional orchestration notes
- Use dedicated service accounts per app.
- Bind each service account to the least-privileged secret role.
- Separate dev, stage, and prod namespaces or trust boundaries and stores.
- Avoid cluster-wide or global secret stores unless there is a compelling platform reason.

---

## 5. VM and bare compute pattern

Not all workloads run in container orchestrators. Some workloads and admin paths still live on VMs.

### Recommended pattern
- bootstrap the VM using cloud-native identity or a trusted initial bootstrap token
- use Vault Agent or equivalent to retrieve short-lived secrets and render templates locally
- prefer short-lived SSH certificates or cloud control plane access for human admins
- rotate credentials based on lease expiration, not human memory

### VM anti-patterns
- gold images with embedded secrets
- static local service passwords
- shared SSH private keys in password managers without issuance control

---

## 6. Database and service access pattern

### Principle
Applications should not own durable database credentials if the platform can issue dynamic ones.

### Recommended pattern
- database roles are created centrally
- workloads request credentials at runtime
- leases expire automatically
- access is attributable to the requesting workload or role

### Where static secrets remain unavoidable
Some legacy products still require static credentials. When that happens:
- store them centrally
- rotate them on a schedule
- do not embed them in source code
- do not duplicate them across environments

---

## 7. PKI inside dev environments

Development environments still need PKI discipline.

### Certificate populations
- developer device certs
- VPN / Wi-Fi / EAP-TLS device certs
- service mTLS certs
- admin access certs
- internal test environment ingress certs
- TLS inspection certs if used, isolated from identity trust

### Pattern
- use a root and multiple intermediates
- constrain issuance by environment and purpose
- keep inspection CA separate from user or workload auth CAs
- issue short-lived certs when automation exists

### Microsoft-heavy option
If Intune is part of the endpoint and VPN path, you can keep Microsoft Cloud PKI as the device certificate distribution plane while anchoring it to your own private CA in BYOCA mode.

---

## 8. Central key management model

### What central key management should include
- master encryption keys per environment
- HSM-backed or managed KMS where possible
- explicit ownership and rotation processes
- policy-based access using context where supported
- separate key material for:
  - repository encryption
  - runtime secrets
  - certificate authority
  - signing / transit use cases
  - break-glass

### What central key management should not become
- one giant key used everywhere
- a human-operated ceremony for routine dev actions
- a vague “shared vault” that nobody can model or audit

---

## 9. Credential taxonomy for dev

Treat credentials as categories with separate handling rules.

| Credential Type | Primary Source | Lifetime | Delivery Pattern | Notes |
|---|---|---:|---|---|
| Human admin session | IdP / PIM | Minutes to hours | Browser / CLI SSO | Must be attributable |
| CI cloud auth | OIDC federation | Minutes | Token exchange | No stored cloud keys |
| Database creds | Vault dynamic secrets | Minutes to hours | API / mount / agent | Prefer generated credentials |
| App API secret | Secret manager / Vault KV | Rotated by policy | sync / mount / agent | Only when dynamic is impossible |
| Workload mTLS cert | PKI / cert lifecycle mgr | Hours to days | cert manager / mount | Tie to workload identity |
| SSH admin access | SSH CA / broker | Minutes to hours | Signed cert or broker | Avoid static user keys |
| Repo secret encryption | SOPS + KMS | Persistent master key | Git encrypted file | Environment-specific recipients |

---

## 10. MVP for dev environments

### MVP must deliver
- developers authenticate centrally
- CI uses OIDC, not stored cloud secrets
- at least one application gets runtime secrets from a central broker
- at least one workload gets short-lived DB credentials
- at least one container workload gets a certificate through a certificate lifecycle manager or equivalent
- SSH admin access is no longer based on one person’s static key

### What MVP does not require
- full zero trust service mesh
- every app migrated at once
- every secret made dynamic on day one

Build the central rails first. Then move apps over them.
