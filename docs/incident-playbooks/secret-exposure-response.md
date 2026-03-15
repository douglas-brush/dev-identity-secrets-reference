# Incident Playbook: Secret Exposure Response

## Severity: CRITICAL — Execute immediately upon discovery.

## Trigger Conditions

This playbook is activated when any of the following occur:
- Secret detected in a Git commit (by scanner, peer review, or manual discovery)
- Credential found in CI/CD logs, container images, or build artifacts
- Secret reported via issue template or security channel
- Secret scanning tool (gitleaks, GitHub Advanced Security, GitGuardian) fires alert
- Cloud provider alerts on exposed access key

## Response Timeline

| Window | Action |
|--------|--------|
| 0-15 min | Triage + immediate revocation |
| 15-60 min | Blast radius assessment + containment |
| 1-4 hours | Remediation + guardrail gap fix |
| 24 hours | Post-incident review |
| 1 week | Lessons learned + control improvements |

## Phase 1: Triage and Immediate Revocation (0-15 minutes)

### Step 1.1: Classify the secret

| Secret Type | Revocation Method | Priority |
|------------|-------------------|----------|
| AWS Access Key (AKIA*) | AWS IAM → Deactivate key → Delete key | P0 |
| Azure Client Secret | Entra ID → App Registration → Remove credential | P0 |
| GCP Service Account Key | IAM → Disable key → Delete key | P0 |
| GitHub PAT/Token | GitHub Settings → Revoke token | P0 |
| Vault Token | `vault token revoke <token>` | P0 |
| Database Password | Change password immediately in DB | P0 |
| SSH Private Key | Remove from authorized_keys, issue new CA cert | P1 |
| API Key (third-party) | Contact vendor, rotate via dashboard | P1 |
| SOPS Age Key | Generate new age key, re-encrypt all files | P1 |
| TLS Private Key | Revoke certificate, reissue | P1 |
| OAuth Client Secret | Rotate via IdP, update all consumers | P1 |

### Step 1.2: Revoke immediately

```bash
# AWS
aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name <user>
aws iam delete-access-key --access-key-id AKIA... --user-name <user>

# Vault
vault token revoke <exposed_token>
vault token revoke -accessor <accessor>
vault lease revoke -prefix <path>

# GitHub
gh api -X DELETE /user/keys/<key_id>

# Kubernetes
kubectl delete secret <secret-name> -n <namespace>
```

### Step 1.3: Document the exposure

```
EXPOSURE RECORD
═══════════════
Discovered:    [ISO UTC timestamp]
Discovered by: [person/scanner]
Secret type:   [classification]
Secret ID:     [identifier — NOT the value]
Location:      [repo/file/commit/log/artifact]
Revoked:       [YES/NO + timestamp]
Revoked by:    [person]
```

## Phase 2: Blast Radius Assessment (15-60 minutes)

### Step 2.1: Determine exposure surface

Check each vector:

- [ ] **Git history**: Is the secret in any commit? How many commits back?
- [ ] **Forks**: Has the repo been forked since the commit?
- [ ] **CI/CD logs**: Is the secret printed in any build logs?
- [ ] **Container images**: Is the secret baked into any image layer?
- [ ] **Artifact storage**: Is the secret in any published packages or artifacts?
- [ ] **Caches**: Is the secret in any CDN, proxy, or build cache?
- [ ] **Backup systems**: Could the secret be in any backup snapshots?
- [ ] **Third-party mirrors**: Is the repo mirrored anywhere?

### Step 2.2: Check for unauthorized use

```bash
# Check cloud audit logs for the exposed credential
# AWS CloudTrail
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...

# Vault audit
grep "exposed_token_accessor" /var/log/vault/audit.log

# Azure Sign-in logs
az monitor activity-log list --caller <service-principal-id>
```

### Step 2.3: Assess impact

| Question | Answer |
|----------|--------|
| What systems could this credential access? | |
| What data could be read/modified/deleted? | |
| Was the credential used by an unauthorized party? | |
| What is the maximum data exposure window? | |
| Are there compliance notification requirements? | |

## Phase 3: Remediation (1-4 hours)

### Step 3.1: Remove from Git history (if applicable)

```bash
# Option A: BFG Repo-Cleaner (preferred for large repos)
bfg --replace-text passwords.txt repo.git
cd repo.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force

# Option B: git-filter-repo
git filter-repo --invert-paths --path <file-with-secret>
```

### Step 3.2: Issue new credentials

Follow the appropriate rotation procedure:
- Dynamic credentials: Vault will auto-issue new ones
- Static credentials: Generate new, update all consumers
- Certificates: Reissue from CA, deploy to all endpoints

### Step 3.3: Fix the guardrail gap

Determine why existing controls didn't prevent this:

| Check | Status |
|-------|--------|
| Were pre-commit hooks installed? | |
| Was gitleaks configured? | |
| Was the secret pattern in the scanner's regex? | |
| Was CI secret scanning active? | |
| Was SOPS encryption required for this file? | |
| Did the PR review process catch it? | |

Fix the gap:
- Add missing regex pattern to scanner
- Add file to SOPS creation rules
- Update pre-commit hooks
- Enable additional CI scanning

### Step 3.4: Verify remediation

```bash
# Verify the old credential no longer works
# (test from a safe location)

# Verify the new credential works
# Run application health checks

# Verify the guardrail catches this pattern now
echo "test-secret-value" > /tmp/test-secret.txt
./bootstrap/scripts/check_no_plaintext_secrets.sh
```

## Phase 4: Post-Incident Review (24 hours)

### Required attendees
- Incident responder
- Repository owner
- Security lead
- Platform team representative

### Review template

```
POST-INCIDENT REVIEW
════════════════════
Incident ID:       [INC-YYYY-NNN]
Date:              [ISO date]
Duration:          [discovery to remediation]
Severity:          [P0/P1/P2]

TIMELINE
────────
[timestamp] Secret committed by [person/CI]
[timestamp] Secret discovered by [scanner/person]
[timestamp] Secret revoked
[timestamp] Blast radius assessed
[timestamp] New credential issued
[timestamp] Guardrail gap fixed
[timestamp] Remediation verified

ROOT CAUSE
──────────
[Why the secret was committed in the first place]

CONTRIBUTING FACTORS
────────────────────
[What controls failed or were missing]

UNAUTHORIZED ACCESS
───────────────────
[Evidence of unauthorized use, or confirmation of none]

ACTIONS TAKEN
─────────────
[List of all remediation actions]

PREVENTIVE MEASURES
───────────────────
[New controls added to prevent recurrence]

LESSONS LEARNED
───────────────
[What the team learned]
```

## Phase 5: Control Improvements (1 week)

- [ ] Update threat model if new attack vector identified
- [ ] Update scanner patterns for new secret types
- [ ] Update onboarding documentation
- [ ] Conduct team training if human error was root cause
- [ ] Update compliance evidence with incident response documentation
- [ ] Schedule follow-up review in 30 days
