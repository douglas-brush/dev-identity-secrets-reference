# Incident Response Playbooks

This document provides detailed, step-by-step incident response playbooks for the five highest-priority secret and identity incidents. Each playbook integrates with the SIRM framework (`docs/19-sirm-framework.md`) for evidence collection and chain of custody, and references existing tools and runbooks in this repository.

For the foundational playbooks, see also:
- `docs/incident-playbooks/secret-exposure-response.md`
- `docs/incident-playbooks/break-glass-procedure.md`
- `docs/09-runbooks.md`

IR workflow diagram: `diagrams/05-incident-response-flow.mmd`

---

## Common RACI Definitions

| Role | Abbrev | Typical Assignment |
|------|--------|--------------------|
| Security Lead | SL | CISO / Head of Security |
| Platform Lead | PL | Infrastructure / Platform Engineering Lead |
| Incident Commander | IC | Rotating on-call or designated per incident |
| Application Owner | AO | Service owner for affected system |
| Identity Admin | IA | IAM / Vault / IdP administrator |
| Legal/Compliance | LC | Legal counsel or compliance officer |
| Communications | CO | Internal/external communications lead |

---

## Playbook 1: Leaked Secret in Git History

### Trigger Conditions

- Secret scanning tool (gitleaks, GitHub Advanced Security, GitGuardian) fires alert
- Peer review or automated check identifies credential in commit diff
- Cloud provider alerts on exposed access key (AWS GuardDuty, Azure Defender)
- External researcher reports credential exposure
- `tools/scanning/enhanced-scan` detects high-entropy string matching credential pattern

### Severity Classification

| Condition | Severity |
|-----------|----------|
| Production credential, public repo | P0 -- Critical |
| Production credential, private repo | P0 -- Critical |
| Non-production credential, public repo | P1 -- High |
| Non-production credential, private repo | P2 -- Medium |
| Test/dummy credential pattern match | P3 -- Low (verify and close) |

### RACI

| Step | IC | SL | PL | AO | IA | LC |
|------|----|----|----|----|----|----|
| Triage and classify | R | I | C | C | I | - |
| Immediate revocation | A | I | R | C | R | - |
| Blast radius assessment | A | C | R | R | C | I |
| Git history remediation | A | I | R | C | - | - |
| New credential issuance | A | I | C | R | R | - |
| Guardrail gap fix | C | A | R | C | - | - |
| Post-incident review | C | A | R | R | C | I |

*R = Responsible, A = Accountable, C = Consulted, I = Informed*

### Step-by-Step Procedure

#### Phase 1: Detection and Triage (0-15 minutes)

1. **Open SIRM session**
   ```bash
   sirm bootstrap --case "SECRET-LEAK-$(date +%Y%m%d-%H%M)" --type secret-exposure
   ```

2. **Classify the secret** -- determine type, scope, and environment using the classification table in `docs/incident-playbooks/secret-exposure-response.md` (Step 1.1).

3. **Register detection evidence**
   ```bash
   sirm add-evidence --source "scanner-alert" --file /tmp/alert-output.json \
     --description "Initial scanner alert triggering this incident"
   ```

4. **Determine exposure window** -- identify the commit that introduced the secret and calculate time since push.
   ```bash
   git log --all --oneline --diff-filter=A -- <file-with-secret>
   ```

#### Phase 2: Immediate Containment (15-30 minutes)

5. **Revoke the exposed credential immediately.** Do not wait for blast radius assessment. Follow the revocation commands per secret type in `docs/incident-playbooks/secret-exposure-response.md` (Step 1.2).

6. **Log the revocation in SIRM timeline**
   ```bash
   sirm add-timeline --type action --classification F \
     --summary "Credential revoked" \
     --detail "Secret type: [type], Secret ID: [identifier], Revoked via: [method]"
   ```

7. **If the repo is public**, determine if the secret has been indexed by search engines or code search services. Check GitHub code search, Google dorking with the repo name.

#### Phase 3: Blast Radius Assessment (30-90 minutes)

8. **Assess exposure surface** using the checklist in `docs/incident-playbooks/secret-exposure-response.md` (Step 2.1): Git history, forks, CI logs, container images, artifact storage, caches, backups, mirrors.

9. **Check for unauthorized use** of the credential via cloud audit logs, Vault audit logs, and application access logs.

10. **Run identity inventory** to find related credentials
    ```bash
    sirm run identity-inventory
    ```

11. **Register all assessment evidence in SIRM**
    ```bash
    sirm add-evidence --source "audit-log-query" --file /tmp/cloudtrail-results.json \
      --description "CloudTrail query for exposed credential usage"
    ```

#### Phase 4: Remediation (1-4 hours)

12. **Remove from Git history** using BFG Repo-Cleaner or git-filter-repo (see `docs/incident-playbooks/secret-exposure-response.md`, Step 3.1).

13. **Issue new credentials** and update all consumers.

14. **Fix the guardrail gap** -- determine why existing controls (pre-commit hooks, CI scanning, SOPS encryption) did not prevent the exposure. Update scanner patterns, SOPS creation rules, or pre-commit configuration.
    ```bash
    # Verify the fix catches the pattern
    tools/scanning/enhanced-scan --path <repo-root>
    ```

15. **Run secrets-doctor to verify overall health**
    ```bash
    sirm run secrets-doctor
    ```

#### Phase 5: Post-Incident (24-48 hours)

16. **Close SIRM session with findings**
    ```bash
    sirm add-finding --classification F --confidence dominant \
      --title "Production credential exposed in Git commit" \
      --detail "[Full description with timeline and scope]"
    sirm close
    ```

17. **Conduct post-incident review** using the template in `docs/incident-playbooks/secret-exposure-response.md` (Phase 4).

18. **Seal SIRM session**
    ```bash
    sirm seal
    ```

### Evidence Collection Checklist

- [ ] Scanner alert output (JSON/text)
- [ ] Git log showing commit that introduced the secret
- [ ] Cloud audit log queries for credential usage
- [ ] Vault audit log queries (if Vault credential)
- [ ] Screenshot or export of CI build logs if secret appeared there
- [ ] Revocation confirmation (API response or console screenshot)
- [ ] New credential issuance confirmation
- [ ] Scanner results showing gap is fixed
- [ ] Secrets-doctor health report post-remediation

---

## Playbook 2: Compromised CI Pipeline

### Trigger Conditions

- Unauthorized workflow run detected (unknown actor, unexpected branch)
- CI runner exhibiting anomalous behavior (outbound connections, unexpected processes)
- OIDC token minted for unexpected audience or subject claim
- Build artifact tampering detected (digest mismatch, unsigned image)
- Supply chain alert from dependency scanner

### Severity Classification

| Condition | Severity |
|-----------|----------|
| Production deployment from compromised pipeline | P0 -- Critical |
| Production secrets accessible from compromised runner | P0 -- Critical |
| Non-production pipeline only, no prod access | P1 -- High |
| Suspicious but unconfirmed compromise | P2 -- Medium |

### RACI

| Step | IC | SL | PL | AO | IA | LC |
|------|----|----|----|----|----|----|
| Isolate CI environment | R | I | R | I | - | - |
| Audit all CI-accessible secrets | A | C | R | C | R | - |
| Rotate all CI-accessible secrets | A | I | R | R | R | - |
| Verify deployment integrity | A | C | R | R | - | - |
| Rebuild CI trust chain | C | A | R | C | R | - |
| Post-incident review | C | A | R | R | C | I |

### Step-by-Step Procedure

#### Phase 1: Isolation (0-30 minutes)

1. **Open SIRM session**
   ```bash
   sirm bootstrap --case "CI-COMPROMISE-$(date +%Y%m%d-%H%M)" --type ci-incident
   ```

2. **Disable the compromised pipeline immediately.** Disable the workflow, pause the CI project, or revoke the runner registration token.
   ```bash
   # GitHub Actions: disable workflow
   gh workflow disable <workflow-name> --repo <org/repo>

   # Revoke runner registration token
   gh api -X POST repos/<org/repo>/actions/runners/registration-token
   ```

3. **Revoke all OIDC trust relationships** from the compromised repository/pipeline.
   ```bash
   # Vault: disable JWT auth role for the compromised repo
   vault write auth/jwt/role/<repo-role> bound_claims='{"repository":"DISABLED"}'
   ```

4. **Quarantine self-hosted runners.** If using self-hosted runners, stop and quarantine them. Do not destroy -- preserve for forensic analysis.

#### Phase 2: Audit (30 minutes - 2 hours)

5. **Enumerate all secrets the pipeline could access.** Include:
   - CI platform secrets (GitHub Actions secrets, GitLab CI variables)
   - OIDC-accessible Vault paths
   - Cloud IAM roles assumable via OIDC federation
   - Container registry push credentials
   - Deployment credentials (kubectl configs, Helm release secrets)

6. **Audit CI platform logs** for the full attack window.
   ```bash
   # GitHub: list recent workflow runs
   gh run list --repo <org/repo> --limit 50 --json databaseId,conclusion,headBranch,createdAt
   ```

7. **Check for unauthorized deployments** -- verify all production deployments since the suspected compromise date.
   ```bash
   # Check container image digests against expected values
   # Check ArgoCD/Flux sync history
   # Check Helm release history
   ```

8. **Register all audit evidence in SIRM**

#### Phase 3: Rotate All CI-Accessible Secrets (2-4 hours)

9. **Rotate every secret the compromised pipeline could access.** Treat every accessible secret as potentially compromised.

   | Secret Category | Rotation Method |
   |----------------|-----------------|
   | CI platform secrets | Regenerate in CI settings |
   | Vault AppRole credentials | `vault write -force auth/approle/role/<role>/secret-id` |
   | Cloud IAM keys | Rotate via cloud console/CLI |
   | Container registry tokens | Regenerate push tokens |
   | SOPS age keys (if CI had decrypt access) | Generate new key, re-encrypt with `tools/rotate/rotate_sops_keys.sh` |
   | SSH deploy keys | `ssh-keygen -t ed25519`, replace in repo settings |
   | Database credentials | Rotate via Vault dynamic secrets or manual rotation |

10. **Verify no unauthorized images were pushed to the container registry.**
    ```bash
    # List recent image pushes and verify signatures
    cosign verify <registry>/<image>:<tag>
    ```

#### Phase 4: Rebuild Trust (4-8 hours)

11. **Rebuild CI runners** from clean base images. Do not reuse quarantined runners.

12. **Re-establish OIDC trust** with tightened subject claims.
    ```bash
    vault write auth/jwt/role/<repo-role> \
      bound_claims='{"repository":"<org/repo>","ref":"refs/heads/main"}' \
      token_policies="<scoped-policy>" \
      token_ttl=300
    ```

13. **Enable enhanced monitoring** on the CI platform for the next 30 days.

14. **Run full scanning suite**
    ```bash
    sirm run enhanced-scan
    sirm run secrets-doctor
    ```

#### Phase 5: Post-Incident (24-48 hours)

15. **Close and seal SIRM session** with findings covering scope, timeline, affected secrets, and remediation actions.

16. **Conduct post-incident review.** Focus on: How did the attacker gain pipeline access? What controls should have prevented it? How can detection time be reduced?

### Evidence Collection Checklist

- [ ] CI platform audit logs (workflow runs, secret access, admin changes)
- [ ] OIDC token claims from suspicious authentications
- [ ] Vault audit logs for CI-sourced requests
- [ ] Cloud audit logs for CI-assumed roles
- [ ] Container registry push logs
- [ ] Runner system logs and process lists (if self-hosted)
- [ ] Deployment history (ArgoCD, Flux, Helm)
- [ ] Image signature verification results
- [ ] Full list of rotated credentials with before/after dates

---

## Playbook 3: Vault Token Theft

### Trigger Conditions

- Vault audit log shows token used from unexpected IP or identity
- Vault token accessor found in application logs or external system
- Anomalous Vault API pattern (bulk reads, policy enumeration, path traversal)
- Developer reports Vault token exposed (clipboard, screen share, log)
- `secrets-doctor` reports token with unexpected TTL or policy

### Severity Classification

| Condition | Severity |
|-----------|----------|
| Root token or admin-policy token compromised | P0 -- Critical |
| Production secret-read token compromised | P0 -- Critical |
| Non-production scoped token compromised | P1 -- High |
| Token expired before discovery | P2 -- Medium (still investigate) |

### RACI

| Step | IC | SL | PL | AO | IA | LC |
|------|----|----|----|----|----|----|
| Revoke stolen token | R | I | C | I | R | - |
| Audit token usage | A | C | R | C | R | - |
| Assess data access | A | C | R | R | C | I |
| Re-authenticate workloads | A | I | R | R | R | - |
| Vault policy review | C | A | R | - | R | - |
| Post-incident review | C | A | R | R | C | I |

### Step-by-Step Procedure

#### Phase 1: Immediate Revocation (0-15 minutes)

1. **Open SIRM session**
   ```bash
   sirm bootstrap --case "VAULT-TOKEN-$(date +%Y%m%d-%H%M)" --type vault-incident
   ```

2. **Revoke the stolen token immediately.**
   ```bash
   # Revoke by token value (if known)
   vault token revoke <stolen-token>

   # Revoke by accessor (safer -- does not require the token value)
   vault token revoke -accessor <accessor>

   # If the token created child tokens, revoke the entire tree
   vault token revoke -accessor <accessor>  # Revokes children automatically
   ```

3. **Revoke all leases created by the stolen token.**
   ```bash
   # List leases by prefix if the token's path is known
   vault lease revoke -prefix <secret-engine-path>/
   ```

4. **If root token is compromised**, generate a new root token via Shamir ceremony and revoke the old one. Follow `docs/incident-playbooks/break-glass-procedure.md`.

#### Phase 2: Audit Token Usage (15-60 minutes)

5. **Query Vault audit log** for all operations performed by the stolen token.
   ```bash
   # Search by token accessor in audit log
   grep "<accessor>" /var/log/vault/audit.log | jq '.request.path, .request.operation'
   ```

6. **Determine what the token could access** by examining its policies.
   ```bash
   vault token lookup -accessor <accessor>
   # Note: policies, ttl, creation_time, creation_path
   ```

7. **Identify all secrets that were read** during the compromise window. Cross-reference with the token's policy capabilities.

8. **Register audit evidence in SIRM**
   ```bash
   sirm add-evidence --source "vault-audit-log" --file /tmp/vault-audit-extract.json \
     --description "Vault audit log entries for compromised token accessor"
   ```

#### Phase 3: Re-authentication (1-4 hours)

9. **Rotate all secrets the token could read.** If the token had read access to production database credentials, rotate those credentials.

10. **Re-authenticate all workloads** that used the same authentication path.
    ```bash
    # If AppRole: generate new secret-id
    vault write -force auth/approle/role/<role>/secret-id

    # If Kubernetes auth: pods will re-auth on restart
    kubectl rollout restart deployment/<app> -n <namespace>

    # If OIDC/JWT: revoke and re-issue
    ```

11. **Review and tighten Vault policies** for the affected auth method.
    ```bash
    # Audit the policy
    vault policy read <policy-name>

    # Check for overly broad paths (wildcards, list capabilities on sensitive paths)
    ```

12. **Run Vault health diagnostics**
    ```bash
    sirm run secrets-doctor
    ```

#### Phase 4: Post-Incident (24-48 hours)

13. **Close and seal SIRM session.**

14. **Conduct post-incident review.** Focus on: How was the token exposed? Were token TTLs appropriate? Should response wrapping have been used? Are Vault audit log alerts configured?

### Evidence Collection Checklist

- [ ] Vault audit log extract for the token accessor (full compromise window)
- [ ] Token lookup output (policies, TTL, creation path)
- [ ] List of secrets the token could access (policy analysis)
- [ ] List of secrets confirmed read during compromise window
- [ ] Revocation confirmation
- [ ] Lease revocation confirmation
- [ ] Workload re-authentication confirmation
- [ ] Policy diff (before/after tightening)
- [ ] Secrets-doctor report post-remediation

---

## Playbook 4: Certificate Authority Compromise

### Trigger Conditions

- Private CA key material suspected or confirmed exposed
- Intermediate CA signing unauthorized certificates
- Certificate transparency log shows unexpected issuance
- Vault PKI secrets engine compromised or issuing without authorization
- Key ceremony audit reveals discrepancy in key material chain

### Severity Classification

| Condition | Severity |
|-----------|----------|
| Root CA private key compromised | P0 -- Critical (catastrophic) |
| Intermediate CA key compromised | P0 -- Critical |
| Leaf certificate private key compromised | P1 -- High |
| Suspected but unconfirmed CA compromise | P1 -- High (treat as confirmed until cleared) |

### RACI

| Step | IC | SL | PL | AO | IA | LC | CO |
|------|----|----|----|----|----|----|-----|
| Revoke compromised CA cert | R | A | R | I | R | I | - |
| Publish CRL / OCSP update | A | I | R | I | R | - | - |
| Notify relying parties | A | C | R | R | - | C | R |
| Re-issue all affected certs | A | I | R | R | R | - | - |
| Rebuild CA hierarchy | C | A | R | - | R | C | - |
| Post-incident review | C | A | R | R | C | C | I |

### Step-by-Step Procedure

#### Phase 1: Immediate CRL Publication (0-30 minutes)

1. **Open SIRM session**
   ```bash
   sirm bootstrap --case "CA-COMPROMISE-$(date +%Y%m%d-%H%M)" --type pki-incident
   ```

2. **Revoke the compromised CA certificate** and publish an updated CRL.
   ```bash
   # Vault PKI: revoke the intermediate
   vault write pki_int/revoke serial_number=<serial>

   # Force CRL rotation
   vault read pki_int/crl/rotate

   # If external CA: use CA-specific revocation procedure
   ```

3. **Update OCSP responder** if OCSP is in use. Verify the responder returns "revoked" for the compromised certificate.
   ```bash
   openssl ocsp -issuer ca.pem -cert compromised.pem -url <ocsp-url> -resp_text
   ```

4. **If root CA is compromised**, the entire PKI hierarchy must be rebuilt. This is the most severe scenario. All certificates issued under this root are untrustworthy.

#### Phase 2: Notify Relying Parties (30-60 minutes)

5. **Identify all systems trusting the compromised CA.** This includes:
   - Services using mTLS with certificates from this CA (see `docs/16-mtls-workload-identity-guide.md`)
   - Load balancers and reverse proxies with the CA in their trust store
   - Client applications with the CA pinned or in their trust bundle
   - Partner/vendor systems that validate certificates from this CA

6. **Notify all relying parties** with:
   - Which CA certificate is compromised (serial, subject, issuer)
   - Updated CRL distribution point
   - Timeline for certificate re-issuance
   - Interim mitigation (additional validation, IP allowlisting)

7. **Register notification evidence in SIRM**

#### Phase 3: Certificate Re-Issuance (1-8 hours)

8. **Stand up replacement CA** if the intermediate or root is compromised.
   ```bash
   # Vault: create new intermediate CA
   vault secrets enable -path=pki_int_v2 pki
   vault write pki_int_v2/intermediate/generate/internal \
     common_name="Organization Intermediate CA v2" \
     ttl=26280h

   # Sign with root (if root is not compromised)
   vault write pki/root/sign-intermediate \
     csr=@intermediate_v2.csr \
     ttl=26280h
   ```

9. **Re-issue all leaf certificates** from the new CA.
   ```bash
   # For each workload using cert-manager or Vault PKI:
   # Update issuer reference to new intermediate
   # Trigger certificate renewal

   # cert-manager: update ClusterIssuer/Issuer resource
   # Vault Agent: update PKI path in template
   ```

10. **Distribute new CA certificate** to all trust stores.

11. **Verify mTLS connectivity** for all affected services.
    ```bash
    openssl s_client -connect <service>:443 -CAfile new-ca-bundle.pem
    ```

#### Phase 4: Rebuild and Verify (8-48 hours)

12. **If root CA was compromised**, conduct a full key ceremony to generate a new root. Follow `docs/18-key-ceremony-guide.md`.

13. **Update all trust bundles** across the infrastructure.

14. **Run certificate health check**
    ```bash
    sirm run secrets-doctor
    ```

15. **Verify CRL/OCSP enforcement** -- confirm that relying parties are actually checking revocation status, not just trusting certificates without validation.

#### Phase 5: Post-Incident (48-72 hours)

16. **Close and seal SIRM session.**

17. **Conduct post-incident review.** Focus on: How was the CA key exposed? Was the key material properly protected (HSM, ceremony, access controls)? Are CRL/OCSP checking enforced across all relying parties? Should certificate lifetimes be shortened?

### Evidence Collection Checklist

- [ ] Compromised certificate details (serial, subject, issuer, public key hash)
- [ ] CRL publication confirmation (before/after)
- [ ] OCSP responder verification output
- [ ] List of all relying parties identified
- [ ] Notification records (who was notified, when, by whom)
- [ ] New CA certificate generation evidence (key ceremony records if applicable)
- [ ] Certificate re-issuance records for each affected service
- [ ] mTLS connectivity verification results
- [ ] Trust bundle distribution confirmation
- [ ] Vault PKI configuration diff (before/after)

---

## Playbook 5: Break-Glass Activation

### Trigger Conditions

- IdP completely unavailable and critical system access needed
- Vault sealed and cannot be unsealed through normal procedures
- Cloud IAM outage blocking all operational access
- Security incident requiring immediate credential revocation beyond normal access
- Certificate authority unreachable and emergency cert issuance needed

See also: `docs/incident-playbooks/break-glass-procedure.md` for the full procedure.

### Severity Classification

All break-glass activations are **P0 -- Critical** by definition. Break-glass is a last resort.

### RACI

| Step | IC | SL | PL | Key Holder 1 | Key Holder 2 | LC |
|------|----|----|----|----|----|----|
| Authorize activation | A | R | C | R | R | I |
| Retrieve materials | - | C | R | R | R | - |
| Establish access | A | I | R | R | R | - |
| Perform operations | A | C | R | - | - | - |
| Rotate all materials | A | I | R | R | R | - |
| Post-incident review | C | A | R | C | C | I |

### Step-by-Step Procedure

#### Phase 1: Authorization (0-10 minutes)

1. **Two authorized personnel must be present.** Verify identity to each other. No single person can authorize break-glass.

2. **Open SIRM session**
   ```bash
   sirm bootstrap --case "BREAK-GLASS-$(date +%Y%m%d-%H%M)" --type break-glass
   ```

3. **Document the emergency declaration** per the template in `docs/incident-playbooks/break-glass-procedure.md` (Step 1). Record:
   - Who is declaring
   - Who is witnessing
   - Why normal access is unavailable
   - What systems need emergency access
   - Expected duration
   - Reference incident ticket

4. **Scope limits** -- before retrieving materials, explicitly define and document the maximum scope of actions permitted:
   - Which systems may be accessed
   - What operations are authorized
   - What operations are explicitly forbidden
   - Maximum time window for emergency access

5. **Register authorization in SIRM**
   ```bash
   sirm add-timeline --type action --classification F \
     --summary "Break-glass authorized" \
     --detail "Declared by: [name], Witnessed by: [name], Scope: [systems], Reason: [why]"
   ```

#### Phase 2: Material Retrieval (10-25 minutes)

6. **Both authorized personnel retrieve their portions** of break-glass materials from physical storage. Follow the retrieval process in `docs/incident-playbooks/break-glass-procedure.md` (Step 2).

7. **Verify material integrity** -- hash check digital materials, seal check physical envelopes.

8. **Log retrieval in SIRM**

#### Phase 3: Emergency Operations (25 minutes - duration)

9. **Establish access** per the appropriate scenario in `docs/incident-playbooks/break-glass-procedure.md` (Step 3):
   - Scenario A: Vault unsealing (3-of-5 Shamir keys)
   - Scenario B: Cloud root access
   - Scenario C: SOPS emergency decryption
   - Scenario D: SSH emergency access

10. **Execute only the minimum operations necessary.** Every action must be documented in real time.
    ```bash
    sirm add-timeline --type action --classification F \
      --summary "[Action description]" \
      --detail "[Specific command or operation performed, by whom, result]"
    ```

11. **Two-person verification** for any destructive operation (revocation, deletion, configuration change).

#### Phase 4: Secure and Rotate (immediately after operations complete)

12. **Terminate all emergency sessions.**

13. **Securely destroy all temporary copies of break-glass materials.**
    ```bash
    shred -u /tmp/break-glass.age /tmp/emergency-ssh-key /tmp/critical.dec.yaml
    ```

14. **Rotate all break-glass materials** per the rotation procedures in `docs/incident-playbooks/break-glass-procedure.md` (Step 5):
    - Generate new Vault root token and revoke
    - Rotate age break-glass key and re-encrypt all SOPS files
    - Rotate cloud root credentials
    - Generate new SSH emergency key

15. **Return materials to secure storage** and verify seals.

16. **Run secrets-doctor to verify system health**
    ```bash
    sirm run secrets-doctor
    ```

#### Phase 5: Post-Incident Review (within 24 hours)

17. **Complete the break-glass incident report** per `docs/incident-playbooks/break-glass-procedure.md` (Step 6).

18. **Close and seal SIRM session.**
    ```bash
    sirm add-finding --classification F --confidence dominant \
      --title "Break-glass activation: [reason]" \
      --detail "[Full summary of why, what was done, materials used, rotation status]"
    sirm close
    sirm seal
    ```

19. **Review the root cause of the outage** that required break-glass. Was it a design flaw? An external dependency? A configuration error?

20. **Update break-glass procedures** based on any issues encountered during execution.

### Evidence Collection Checklist

- [ ] Emergency declaration document (who, when, why, scope)
- [ ] Material retrieval log (who retrieved what, when, integrity verification)
- [ ] Every operation performed (timestamped, operator-attributed)
- [ ] Two-person verification records for destructive operations
- [ ] Material rotation confirmation (new hashes, new storage locations)
- [ ] System health verification post-operations (secrets-doctor output)
- [ ] Root cause analysis of the outage requiring break-glass
- [ ] Updated procedure document (if changes needed)
- [ ] SIRM sealed session artifact

### Scope Limits Reference

Break-glass access is explicitly limited:

| Permitted | Not Permitted |
|-----------|--------------|
| Unseal Vault | Modify Vault policies permanently |
| Read/revoke production secrets for the incident | Bulk export of all secrets |
| Emergency credential rotation | Create new long-lived admin accounts |
| Emergency certificate issuance | Modify CA trust hierarchy permanently |
| Infrastructure access for incident containment | Deploy new application code |

Any action outside the declared scope requires re-authorization with a new declaration.

---

## Cross-Playbook SIRM Integration Summary

Every playbook follows the same SIRM lifecycle:

```
1. sirm bootstrap    -- Open session with case ID and type
2. sirm add-evidence -- Register each artifact as collected
3. sirm add-timeline -- Log every action with timestamp and classification
4. sirm run <tool>   -- Capture tool output as registered evidence
5. sirm add-finding  -- Record classified findings
6. sirm close        -- Generate report
7. sirm seal         -- Create tamper-evident archive
```

Sealed sessions satisfy SOC 2 CC7.2-7.4, NIST CSF RS.AN/RS.RP, NIST 800-53 IR-4/IR-5/AU-10, and ISO 27001 A.5.24-A.5.28 evidence requirements. See `docs/19-sirm-framework.md` for the full compliance mapping.

## Related Documents

- Secret exposure response: `docs/incident-playbooks/secret-exposure-response.md`
- Break-glass procedure: `docs/incident-playbooks/break-glass-procedure.md`
- Runbooks: `docs/09-runbooks.md`
- Threat model: `docs/07-threat-model.md`
- Attack trees: `docs/24-attack-trees.md`
- Security hardening checklist: `docs/26-security-hardening-checklist.md`
- SIRM framework: `docs/19-sirm-framework.md`
- SIRM session protocol: `docs/20-sirm-session-protocol.md`
- Key ceremony guide: `docs/18-key-ceremony-guide.md`
- IR workflow diagram: `diagrams/05-incident-response-flow.mmd`
