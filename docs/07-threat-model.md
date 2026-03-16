# Threat Model

This document identifies the primary threats to developer identity and secrets infrastructure, maps each to real-world breach precedent, and defines detection and mitigation strategies tied to this architecture's control objectives (C1--C6).

STRIDE is used as the classification framework. Likelihood and impact are rated on a four-level scale (Critical / High / Medium / Low) based on attacker capability, exposure surface, and observed frequency in the wild.

---

## Attack Surface Summary

| Plane | Threats | Primary Controls |
|-------|---------|-----------------|
| **Identity** | T3, T5, T6, T8 | C4, C5, C6 |
| **Secrets** | T1, T2, T4, T9, T10, T11 | C1, C2, C3 |
| **Runtime** | T2, T4, T7, T8, T10, T11 | C2, C3, C6 |

---

## Risk Heat Map

Likelihood (horizontal) vs. Impact (vertical). Cell contents are threat IDs.

|  | **Almost Certain** | **Likely** | **Possible** | **Unlikely** |
|---|---|---|---|---|
| **Critical impact** | T1 | T2, T10 | T8 | T6 |
| **High impact** | T9, T11 | T3, T4 | T5 | -- |
| **Medium impact** | -- | -- | T7 | -- |
| **Low impact** | -- | -- | -- | -- |

---

## Assumptions

- Developer endpoints can be lost or compromised.
- Source control systems are high-value targets.
- CI runners are attractive token-theft targets.
- Kubernetes namespaces are not equivalent to strong isolation by themselves.
- Insider misuse is possible and must be modeled explicitly.
- Legacy applications will force some static secret exceptions.
- Non-human identities outnumber human identities by 10:1 or more.
- AI coding assistants are now part of the developer toolchain and have access to repository context.
- Supply chain dependencies execute code at install time with full environment access.

---

## Threats

---

### T1. Plaintext secret committed to Git

**STRIDE Category:** Information Disclosure

**Likelihood:** Almost Certain -- GitGuardian's 2024 State of Secrets Sprawl report detected 12.8 million new secrets in public GitHub repositories in a single year. Every organization with more than a handful of developers will experience this.

**Impact:** Critical -- A committed secret is immediately replicated to every clone, fork, mirror, CI cache, and backup. Git history preserves the secret even after deletion from HEAD. Automated scanners harvest exposed credentials within minutes of push.

> **Case Study: Uber (2022)** -- Attackers purchased stolen credentials on the dark web and used social engineering to bypass MFA. Once inside, they found hardcoded AWS credentials in a PowerShell script within an internal GitHub repository. Those credentials provided admin access to Uber's AWS account, Duo, OneLogin, and internal dashboards. The blast radius was organization-wide because a single plaintext secret in source control became the pivot point from initial access to full infrastructure compromise.

> **Case Study: Toyota (2022)** -- A Toyota subsidiary accidentally published an access key to a public GitHub repository. The key remained exposed for approximately five years before discovery, granting potential access to customer data for over 296,000 individuals. The incident demonstrated that even a single leaked credential can persist undetected for years when no scanning or rotation controls exist.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C1 | SOPS encryption for all secret values in version control |
| C1 | Pre-commit hooks (gitleaks, detect-secrets) blocking pushes containing high-entropy strings or known secret patterns |
| C1 | CI-level scanning as backstop when local hooks are bypassed via `--no-verify` |
| C1 | Merge/PR blocking on secret detection findings |
| C3 | Rotation runbook triggered on any confirmed exposure |

**Detection:**

- Pre-commit hook alerts on the developer workstation.
- CI pipeline secret scanning (gitleaks, truffleHog) on every push and PR.
- GitHub Advanced Security / GitGuardian alerts on public and private repositories.
- Vault audit log anomalies: credential used from unexpected IP or identity.
- Cloud provider GuardDuty / Defender alerts on credential use from outside expected CIDR ranges.

**Residual Risk:** Medium -- Pre-commit hooks can be bypassed with `--no-verify`. CI scanning catches this, but there is a window between push and CI execution where the secret exists in the remote. Encrypted history (SOPS) limits the blast radius for secrets that were always encrypted, but secrets committed before SOPS adoption require history rewriting or rotation.

---

### T2. CI workflow token misuse

**STRIDE Category:** Elevation of Privilege, Spoofing

**Likelihood:** Likely -- CI/CD pipelines are the highest-value non-human identity in most organizations. Supply chain attacks specifically targeting CI environments increased significantly from 2021 to 2023.

**Impact:** Critical -- A compromised CI token can deploy arbitrary code to production, exfiltrate secrets from the CI environment, pivot to cloud accounts, and tamper with build artifacts. The trust granted to CI pipelines often exceeds what any individual developer holds.

> **Case Study: Codecov (2021)** -- Attackers modified Codecov's bash uploader script by exploiting a Docker image build process flaw. The compromised script exfiltrated environment variables -- including CI tokens, API keys, and cloud credentials -- from an estimated 29,000 customers' CI environments. Affected organizations included Twitch, HashiCorp, and Confluent. The attack persisted for two months before detection because CI environment variables were treated as implicitly trusted.

> **Case Study: CircleCI (2023)** -- An engineer's laptop was compromised via malware, which captured an active SSO session token. The attacker used this to access CircleCI's internal systems and exfiltrate customer environment variables and secrets stored in CircleCI. The incident forced a company-wide rotation of all customer secrets. Root cause: a long-lived session token on an endpoint, combined with CI secrets stored at rest without additional encryption layers.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C2 | OIDC federation -- CI authenticates to cloud providers via short-lived tokens, no stored credentials |
| C2 | Repository and branch claim restrictions on OIDC subject claims |
| C2 | Short TTL credentials (minutes, not hours) for CI-to-cloud authentication |
| C2 | Environment-scoped roles preventing dev CI from touching prod resources |
| C3 | Per-workflow least-privilege: each job gets only the permissions it needs |

**Detection:**

- OIDC token claim validation failures in Vault or cloud provider logs.
- CI job execution from unexpected branches or repositories.
- Anomalous deployment patterns: deployments outside business hours, from non-release branches, or to environments not matching the workflow.
- Cloud trail / audit logs showing CI role assumption from unexpected source IPs.
- Sudden spike in secret reads from Vault correlated with CI pipeline execution.

**Residual Risk:** Low -- OIDC federation with tightly scoped subject claims eliminates the stored-credential attack vector. Residual risk is in the OIDC provider itself being compromised (GitHub, GitLab) or in overly broad claim patterns that allow cross-repository token reuse.

---

### T3. Developer laptop compromise

**STRIDE Category:** Spoofing, Information Disclosure, Elevation of Privilege

**Likelihood:** Likely -- Endpoint compromise via phishing, malware, or physical theft is a persistent reality. Developer machines are high-value targets because they often hold session tokens, SSH keys, cloud CLI credentials, and IDE context.

**Impact:** High -- A compromised developer laptop provides the attacker with the developer's identity: active SSO sessions, cached credentials, local git configuration, IDE secrets, and potentially access to secrets management systems if sessions are long-lived.

> **Case Study: LastPass (2022-2023)** -- Attackers initially breached LastPass via a compromised developer laptop in August 2022. Four months later, they targeted a DevOps engineer's personal home computer, exploiting a vulnerable third-party media software package to install a keylogger. This captured the engineer's master password, providing access to the corporate LastPass vault. From there, the attackers accessed AWS S3 buckets containing encrypted customer vault backups and encryption keys. The final breach -- customer vault data -- was a direct consequence of a single endpoint compromise escalating through session persistence and privileged access to secrets infrastructure.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C5 | No durable local secrets by default -- SSH via CA/broker, cloud access via OIDC |
| C1 | No plaintext secrets on disk -- SOPS for repos, Vault for runtime |
| C6 | Break-glass revocation path for compromised identities |
| -- | Managed devices with EDR, disk encryption, and remote wipe capability |
| -- | Phishing-resistant authentication (FIDO2/WebAuthn) eliminating session theft via phished passwords |
| -- | Short-lived credential issuance (Vault TTLs, cloud STS tokens) limiting the window of usability for stolen tokens |

**Detection:**

- EDR alerts: malware, keylogger installation, suspicious process execution.
- IdP impossible-travel alerts: authentication from geographically inconsistent locations.
- Vault audit logs: credential access from a device ID or IP not matching the developer's known patterns.
- Git push from a developer identity outside their normal working hours or from an unrecognized IP.
- Cloud provider alerts: CLI credential use from a new region or network.

**Residual Risk:** Medium -- Even with short-lived credentials, an attacker with real-time access to an active session can operate within the credential's TTL. Phishing-resistant MFA significantly raises the bar but does not eliminate real-time session hijacking via malware on the endpoint itself.

---

### T4. Kubernetes secret sprawl

**STRIDE Category:** Information Disclosure, Tampering

**Likelihood:** Likely -- Kubernetes Secrets are base64-encoded (not encrypted) by default and accessible to any pod with the right RBAC binding. Overpermissive RBAC is one of the most common Kubernetes misconfigurations.

**Impact:** High -- Excessive secret distribution increases the blast radius of any single namespace compromise. Secrets accessible across namespaces or to overly broad service accounts allow lateral movement from one compromised workload to the infrastructure layer.

> **Case Study: Microsoft SAS Token Exposure (2023)** -- Microsoft AI researchers accidentally exposed 38 terabytes of internal data by publishing an overly permissive Azure SAS (Shared Access Signature) token in a public GitHub repository. The token, intended to share a narrow training data bucket, was scoped too broadly and granted read/write access to an entire storage account containing internal messages, secrets, and private keys. The misconfiguration went undetected for over two years. While not a Kubernetes-specific incident, it directly illustrates the pattern: a credential with broader scope than intended, persisted without lifecycle controls, in an environment where no one was auditing actual vs. intended access.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C3 | One service account per workload -- no shared identities across applications |
| C3 | Namespace-scoped RBAC -- no cluster-wide secret read permissions |
| C3 | Separate Vault paths and policies per namespace and environment |
| C3 | CSI Secret Store driver for direct mount from Vault, avoiding Kubernetes Secret objects entirely where possible |
| C3 | Avoid wildcard (`*`) verbs on secrets resources in any RBAC binding |

**Detection:**

- RBAC audit: periodic enumeration of all subjects with `get`/`list`/`watch` on secrets resources, flagging any with cross-namespace or cluster-scope access.
- Kubernetes audit logs: watch for secret reads from unexpected service accounts or namespaces.
- OPA/Gatekeeper policies denying creation of overly broad RoleBindings or ClusterRoleBindings referencing secrets.
- Vault audit logs: dynamic credential requests from unexpected Kubernetes service accounts.
- Drift detection: comparing deployed RBAC against policy-as-code definitions.

**Residual Risk:** Medium -- CSI driver adoption eliminates Kubernetes Secret objects for sensitive credentials, but legacy workloads may still require native secrets. RBAC drift over time is the primary residual concern and requires continuous audit.

---

### T5. Static SSH key dependency

**STRIDE Category:** Spoofing, Repudiation

**Likelihood:** Possible -- Many organizations still rely on long-lived SSH keys distributed to individual developers or embedded in automation. The keys rarely rotate and revocation depends on manual authorized_keys management.

**Impact:** High -- Static SSH keys provide persistent access that survives password resets, MFA changes, and IdP deprovisioning. They create attribution gaps (key reuse across systems makes forensic tracing difficult) and hidden persistence (an attacker who obtains a key retains access until the key is explicitly removed from every target).

> **Case Study Pattern: SSH Key Reuse in Cloud Breaches** -- Multiple cloud breach investigations have identified a recurring pattern: SSH private keys stored unencrypted on developer laptops or in CI environments, reused across multiple hosts and environments, with no expiration or rotation. In several incidents, a single compromised SSH key provided access to production bastion hosts, internal jump boxes, and version control systems simultaneously. The lack of centralized revocation meant that incident responders had to enumerate every authorized_keys file across the infrastructure to fully contain the compromise. This pattern was observed in multiple DFIR engagements where the initial access vector was a stolen SSH key, and containment took days because the key's scope of access was unknown.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C5 | SSH CA issuing short-lived certificates (hours, not months) tied to IdP identity |
| C5 | SSH broker (Teleport, Boundary) providing audited, recorded sessions |
| C5 | Control-plane alternatives: kubectl exec, SSM Session Manager, reducing need for direct SSH |
| C5 | Central revocation via CA CRL or broker session termination |
| C6 | Break-glass SSH keys stored in sealed custody, tested quarterly |

**Detection:**

- SSH CA logs: certificate issuance to unexpected principals or with unusual validity periods.
- Bastion / broker session logs: connections from unexpected source IPs or at unusual times.
- Host-level auth logs: successful authentication using a raw key (not a CA-signed certificate) when the policy requires certificates.
- Periodic scan: authorized_keys files across infrastructure, flagging any entries not managed by the CA or configuration management.

**Residual Risk:** Low -- SSH CA with short-lived certificates eliminates the persistent-key problem. Residual risk is in break-glass keys (which must exist but are tightly controlled) and in legacy systems that cannot support CA-based authentication.

---

### T6. Collapsed trust domains in PKI

**STRIDE Category:** Spoofing, Tampering

**Likelihood:** Unlikely -- Full CA compromise is rare, but the consequences are catastrophic. Partial trust collapse (overly broad intermediate, wildcard certificate misuse) is more common.

**Impact:** Critical -- A compromised CA or intermediate can issue valid certificates for any identity within its scope. If a single CA or intermediate serves multiple trust domains (e.g., internal mTLS and external TLS from the same intermediate), one compromise allows impersonation across all domains.

> **Case Study: DigiNotar (2011)** -- The Dutch certificate authority DigiNotar was fully compromised by attackers who issued over 500 fraudulent certificates, including for google.com. The breach was not detected by DigiNotar's own monitoring; it was discovered when Iranian users reported certificate warnings in Chrome's certificate pinning implementation. DigiNotar had a flat trust architecture with insufficient separation between CAs serving different purposes. The compromise led to DigiNotar's complete removal from all browser trust stores and the company's bankruptcy. The incident demonstrated that PKI trust collapse is a business-extinction event.

> **Case Study: Let's Encrypt TLS-ALPN-01 Revocation (2022)** -- A validation method flaw in the TLS-ALPN-01 challenge required Let's Encrypt to revoke approximately 2.6 million certificates on short notice. While not a compromise, the event demonstrated the operational impact of trust boundary events at scale. Organizations that depended entirely on a single CA with no automation for rapid re-issuance experienced outages.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C4 | Multiple intermediate CAs separated by trust domain (internal mTLS, external TLS, code signing) |
| C4 | Policy constraints on each intermediate limiting the names and key usages it can issue for |
| C4 | Separate inspection trust (TLS termination at load balancer) from identity trust (mTLS between services) |
| C4 | Short-lived certificates (cert-manager with hours/days validity) reducing the window of usability for any fraudulently issued certificate |
| C4 | Automated certificate lifecycle eliminating human error in issuance |

**Detection:**

- Certificate Transparency (CT) log monitoring for unexpected certificates issued under your domains.
- Intermediate CA audit logs: certificate issuance for names or key usages outside expected scope.
- mTLS handshake failures: sudden increase may indicate certificate revocation or CA trust issues.
- cert-manager metrics: certificate renewal failures, unexpected issuer changes.
- Periodic audit: compare active certificates against expected inventory.

**Residual Risk:** Low -- Separated intermediates with policy constraints limit the blast radius of any single CA compromise. The primary residual risk is in the root CA itself, which is mitigated by offline storage, key ceremony controls (see `docs/18-key-ceremony-guide.md`), and Shamir secret sharing.

---

### T7. Break-glass never validated

**STRIDE Category:** Denial of Service (operational)

**Likelihood:** Possible -- Break-glass procedures are written once and rarely exercised. Without drills, procedures rot: credentials expire, contact lists go stale, documented steps no longer match current infrastructure, and operators have never practiced the workflow under pressure.

**Impact:** Medium -- A break-glass procedure that fails during a real incident extends mean time to recovery, potentially turning a containable incident into a prolonged outage or expanding the blast radius. The impact is amplified when the incident that triggers break-glass is itself time-sensitive (e.g., CA compromise requiring mass certificate re-issuance).

> **Case Study Pattern: IR Readiness Failures** -- Post-incident reviews repeatedly identify a common failure mode: organizations that had documented break-glass procedures but never tested them. In multiple DFIR engagements, incident responders found that sealed break-glass credentials had expired, documented procedures referenced decommissioned systems, the designated break-glass operators had left the organization, and MFA enrollment for break-glass accounts had lapsed. The result in each case was hours of additional downtime while responders improvised access recovery during an active incident. The Maersk NotPetya recovery (2017) is the canonical example: the only surviving Active Directory domain controller was in a Ghana office that happened to be offline during the attack. Recovery depended on this accident, not on a tested break-glass procedure.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C6 | Quarterly break-glass drills with documented results |
| C6 | Dual-control custody: two authorized individuals required to unseal |
| C6 | Evidence capture: every break-glass use (drill or real) produces an audit trail |
| C6 | Credential rotation after every drill or real use |
| C6 | Explicit scope definition: break-glass grants minimum necessary access, not admin-everything |

**Detection:**

- Drill schedule adherence: alert if quarterly drill is overdue.
- Break-glass credential health checks: automated validation that sealed credentials are not expired.
- Access log review: any break-glass credential use outside a declared drill or incident.
- Post-drill report: gap analysis comparing documented procedure against actual execution.

**Residual Risk:** Low -- Regular drills with credential rotation and evidence capture keep procedures current. Residual risk is in scenarios not covered by the drill (novel failure modes) and in the human factor of operators performing under genuine incident stress.

---

### T8. Non-human identity (NHI) lifecycle failure

**STRIDE Category:** Spoofing, Elevation of Privilege

**Likelihood:** Possible -- Non-human identities (service accounts, API keys, machine credentials, OAuth client secrets) routinely outnumber human identities by an order of magnitude. They are created for projects, integrations, and automation and frequently outlive their original purpose. Lifecycle management (rotation, deprovisioning, ownership tracking) is rarely as mature as human identity management.

**Impact:** Critical -- A compromised or orphaned NHI with broad permissions provides persistent, unmonitored access. Because NHIs do not trigger MFA prompts or behave like human users, their misuse is harder to detect through behavioral analytics.

> **Case Study: Microsoft Storm-0558 (2023)** -- The threat actor Storm-0558 obtained a Microsoft account (MSA) consumer signing key and used it to forge authentication tokens for approximately 25 organizations, including US government agencies. The key had been valid since 2016 and should have been retired years earlier. A series of failures compounded: the key was not rotated on schedule, a crash dump containing key material was moved to a debugging environment without proper scrubbing, and the validation logic did not properly distinguish between consumer and enterprise token issuers. The incident was a textbook NHI lifecycle failure: a machine credential that outlived its intended lifecycle, with insufficient monitoring of its use, enabling cross-tenant impersonation at scale.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C3 | Every NHI must have a defined owner, purpose, TTL, and rotation path (Guardrail Rule 3) |
| C2 | Prefer OIDC federation and short-lived tokens over static API keys |
| C3 | Per-workload service accounts with least-privilege policies |
| C3 | Automated credential expiration: Vault leases with max TTL, cloud IAM key age policies |
| -- | NHI inventory: maintain a registry of all service accounts and machine credentials with last-used timestamps |

**Detection:**

- NHI inventory audit: periodic enumeration of all service accounts, API keys, and machine credentials. Flag any without a defined owner or with last-used dates older than 90 days.
- Vault lease monitoring: credentials that are renewed beyond their expected lifecycle.
- Cloud IAM reports: service account keys older than the rotation policy threshold.
- Anomalous NHI behavior: API calls from a service account outside its expected time window, source network, or API scope.
- Orphan detection: cross-reference NHI owners against HR/IdP deprovisioning events.

**Residual Risk:** Medium -- Vault TTLs and OIDC federation reduce the static credential surface, but legacy integrations and third-party services often require long-lived API keys. The NHI inventory discipline is the critical compensating control, and its effectiveness depends on consistent enforcement.

---

### T9. AI coding assistant secret leakage

**STRIDE Category:** Information Disclosure

**Likelihood:** Almost Certain -- AI coding assistants (Copilot, Cursor, Claude Code, Cody) now operate with repository context including configuration files, environment variables, and in some cases, secrets stores. The GitGuardian 2024 report documented 12.8 million new secrets exposed in public GitHub repositories, with AI-assisted development contributing to the acceleration.

**Impact:** High -- Secrets can leak through multiple AI-specific vectors: autocomplete suggesting hardcoded credentials based on training data patterns, context windows including secret-containing files, prompt injection attacks extracting context from the assistant, and developers accepting AI-generated code containing example credentials that were never replaced before commit.

> **Case Study Pattern: AI-Accelerated Secret Exposure** -- GitGuardian's 2024 State of Secrets Sprawl report found that the rate of secret exposure in public repositories increased substantially year-over-year, correlating with the widespread adoption of AI coding assistants. The mechanism is straightforward: AI models trained on public code have internalized patterns that include hardcoded credentials. When developers use these tools, the assistants suggest code that follows the same patterns -- including credential placeholders that look like real secrets, or actual secrets that appeared in training data. Developers working quickly accept suggestions without reviewing for embedded credentials.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C1 | Pre-commit scanning catches AI-suggested secrets before they reach the remote |
| C1 | CI-level scanning as backstop |
| C1 | `.gitignore` and IDE exclusion rules preventing secret-containing files from being indexed by AI tools |
| -- | AI tool configuration: exclude `.env`, `*secret*`, `*credential*`, `*key*` patterns from context windows |
| -- | Developer training: review AI-generated code for credential patterns before accepting |
| C3 | Environment-based secret injection: secrets never exist in files that AI tools can read |

**Detection:**

- Pre-commit hook blocks with AI-pattern markers (e.g., placeholder credentials matching common AI-suggested patterns).
- CI scanning with rules tuned for AI-generated credential patterns.
- Repository audit: increasing rate of secret detection findings correlated with AI tool adoption.
- AI tool audit logs (where available): context window contents, file access patterns.

**Residual Risk:** High -- This is an emerging and rapidly evolving threat. Pre-commit and CI scanning are effective catch-nets, but the fundamental issue is that AI tools need code context to be useful, and that context may include or be adjacent to sensitive material. The residual risk decreases as organizations move secrets entirely out of files (into Vault, environment injection, CSI mounts) so that there is nothing for AI tools to index.

---

### T10. Supply chain secret injection

**STRIDE Category:** Tampering, Information Disclosure

**Likelihood:** Likely -- Malicious packages targeting secrets in CI and developer environments are a proven, repeating attack pattern. The npm, PyPI, and RubyGems ecosystems have all experienced incidents where packages exfiltrated environment variables during installation.

**Impact:** Critical -- A malicious dependency executing during `npm install`, `pip install`, or CI build can read all environment variables (including injected secrets), access the filesystem (including `.env` files, cloud credential caches, and SSH keys), and exfiltrate them to attacker infrastructure. The attack surface is enormous: a single `postinstall` script in a transitive dependency can compromise the entire CI secret set.

> **Case Study: ua-parser-js (2021)** -- The widely-used npm package ua-parser-js (8 million weekly downloads) was compromised when an attacker gained access to the maintainer's npm account and published malicious versions. The compromised package installed a cryptominer and a credential-stealing trojan that harvested passwords and cookies from the infected system. The attack was effective because `npm install` executes lifecycle scripts with the full permissions of the running user.

> **Case Study: event-stream (2018)** -- An attacker gained maintainer access to the popular npm package event-stream by social engineering the original maintainer. They added a targeted payload that activated only when the package was used as a dependency of the Copay Bitcoin wallet application. The malicious code exfiltrated wallet credentials. This demonstrated that supply chain attacks can be precisely targeted and lie dormant until a specific victim condition is met.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C2 | OIDC federation ensures CI secrets are short-lived and scoped; even if exfiltrated, they expire quickly |
| C3 | Least-privilege secret injection: CI jobs receive only the secrets they need, not a global set |
| -- | Lockfile enforcement: `npm ci` / `pip install --require-hashes` ensuring reproducible, verified installs |
| -- | Dependency review: automated PR checks for new dependencies, typosquatting detection, maintainer change alerts |
| -- | Network egress controls in CI: restrict outbound connections to known registries and deployment targets |
| C1 | No secrets in `.env` files within the build context; inject via Vault agent or OIDC at runtime |

**Detection:**

- CI network monitoring: unexpected outbound connections during build phases (especially during `install` or `postinstall` steps).
- Dependency diff on PRs: flag new dependencies, version changes, and especially new install scripts.
- Package provenance verification: npm provenance attestations, sigstore signatures.
- Behavioral monitoring: CI jobs that suddenly read environment variables or filesystem paths they have not historically accessed.
- Canary tokens: plant unique canary credentials in CI environments that trigger alerts if used.

**Residual Risk:** Medium -- Lockfile enforcement and short-lived OIDC credentials significantly reduce the impact. Network egress controls in CI are the highest-value residual control but are complex to implement comprehensively. The fundamental risk remains: package managers execute arbitrary code at install time.

---

### T11. Secrets in logs and observability data

**STRIDE Category:** Information Disclosure

**Likelihood:** Almost Certain -- Application logs, APM traces, error reporting services, and structured logging systems routinely capture request/response bodies, environment variables, and configuration dumps. Secrets end up in logs through debug logging left enabled, error handlers dumping full context, structured logging capturing HTTP headers (including Authorization), and APM tools recording request payloads.

**Impact:** High -- Secrets in logs are typically stored in systems with broader access than the secrets themselves (Elasticsearch, Splunk, Datadog, CloudWatch). Log retention often exceeds credential TTLs, meaning a rotated credential may still be valid in a log system. Log data is frequently replicated across regions, backed up, and shared with third-party observability vendors.

> **Case Study Pattern: Credential Leakage via Structured Logging** -- This is one of the most common findings in security assessments. Organizations adopt structured logging (JSON logs with request context) and inadvertently capture Authorization headers, API keys in query parameters, database connection strings in error traces, and OAuth tokens in request/response bodies. The leaked credentials persist in log aggregation systems that are accessible to operations teams, SREs, and often third-party vendors. In multiple incident investigations, the log aggregation system was the actual source of credential theft -- not the application or secrets manager.

**Mitigations:**

| Control | Implementation |
|---------|---------------|
| C3 | Short-lived credentials: even if logged, they expire before an attacker can extract and use them |
| C1 | Secret value filtering in log pipelines: redact patterns matching known credential formats |
| -- | Structured logging policies: explicitly exclude `Authorization` headers, `Cookie` values, and request bodies from log capture |
| -- | Log sink access controls: restrict who can query raw logs, especially in production |
| -- | APM configuration: disable full request/response capture in production; use sampling |
| -- | Error handler review: ensure stack traces and error context dumps do not include environment variables or configuration objects |

**Detection:**

- Log content scanning: periodic regex-based scanning of log sinks for secret patterns (API keys, JWTs, connection strings).
- Canary tokens: plant recognizable but harmless canary values in application configuration; alert if they appear in log sinks.
- Log access audit: monitor who queries production logs and flag bulk exports or unusual query patterns.
- APM configuration audit: verify that request/response body capture is disabled or filtered in production.

**Residual Risk:** Medium -- Log filtering reduces exposure but is inherently a deny-list approach (you can only filter patterns you know about). Short-lived credentials are the strongest mitigation because they make leaked credentials useless by the time they are discovered in logs. The residual risk is in credentials with longer TTLs (database passwords, third-party API keys) that are captured before rotation.

---

## Threat Summary

| ID | Threat | STRIDE | Likelihood | Impact | Primary Controls | Residual Risk |
|----|--------|--------|-----------|--------|-----------------|---------------|
| T1 | Plaintext secret in Git | Information Disclosure | Almost Certain | Critical | C1 | Medium |
| T2 | CI workflow token misuse | Elevation of Privilege, Spoofing | Likely | Critical | C2, C3 | Low |
| T3 | Developer laptop compromise | Spoofing, Info Disclosure, EoP | Likely | High | C1, C5, C6 | Medium |
| T4 | Kubernetes secret sprawl | Information Disclosure, Tampering | Likely | High | C3 | Medium |
| T5 | Static SSH key dependency | Spoofing, Repudiation | Possible | High | C5, C6 | Low |
| T6 | Collapsed trust domains in PKI | Spoofing, Tampering | Unlikely | Critical | C4 | Low |
| T7 | Break-glass never validated | Denial of Service | Possible | Medium | C6 | Low |
| T8 | NHI lifecycle failure | Spoofing, Elevation of Privilege | Possible | Critical | C2, C3 | Medium |
| T9 | AI coding assistant secret leakage | Information Disclosure | Almost Certain | High | C1, C3 | High |
| T10 | Supply chain secret injection | Tampering, Info Disclosure | Likely | Critical | C1, C2, C3 | Medium |
| T11 | Secrets in logs/observability | Information Disclosure | Almost Certain | High | C1, C3 | Medium |
