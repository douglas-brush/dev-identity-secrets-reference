# Workshop 03: Incident Response with SIRM

**Duration:** 2 hours
**Level:** Intermediate to Advanced
**Audience:** Security engineers, incident responders, forensic analysts, security operations

---

## Objectives

By the end of this workshop, participants will be able to:

1. Bootstrap a SIRM session with proper chain of custody from the first keystroke
2. Register evidence artifacts with SHA-256 integrity verification
3. Build forensic timelines with F/O/I/H confidence classification
4. Generate session reports and seal sessions for immutable archival
5. Execute a break-glass emergency access drill

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Completed Workshop 01 or equivalent Vault familiarity | -- |
| Docker 24.0+ and Docker Compose 2.20+ | `docker --version` |
| `jq` 1.6+ | `jq --version` |
| `sha256sum` or `shasum` | `sha256sum --version` or `shasum --version` |
| Vault CLI | `vault version` |
| Basic incident response concepts | -- |

On macOS, `sha256sum` is available via `brew install coreutils`, or use `shasum -a 256` as a substitute.

### Environment Setup

```bash
cd dev-identity-secrets-reference

# Start the dev environment
make dev-up && make dev-setup

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token

# Verify SIRM tools are available
ls tools/sirm/*.sh
```

---

## Scenario

Throughout this workshop, we will respond to a simulated incident:

> **Scenario:** A pre-commit scan has detected what appears to be a valid API key committed to a feature branch 3 days ago. The key has been pushed to the remote repository. The key provides access to a third-party payment processing API. The commit was made by a developer on the payments team.

This scenario is realistic and exercises all SIRM capabilities without requiring external systems.

---

## Lab 1: SIRM Session Bootstrap (25 minutes)

### Concept

Every SIRM session begins with a bootstrap protocol that captures the complete operational context: who is operating, what tools are available, what state the environment is in. This snapshot becomes the foundation of the forensic record.

### 1.1 Pre-Session Checklist

Before bootstrapping, verify the session prerequisites:

```bash
# Check 1: Operator identity
echo "Operator: $(whoami)@$(hostname)"

# Check 2: System clock (must be within 5s of NTP)
date -u "+%Y-%m-%dT%H:%M:%SZ"

# Check 3: Required tools
for tool in vault jq git openssl; do
  command -v "$tool" >/dev/null 2>&1 \
    && echo "  [OK] $tool: $(command -v $tool)" \
    || echo "  [MISSING] $tool"
done

# Check 4: Repository state
git status --short

# Check 5: Vault accessible
vault status -format=json | jq '{sealed, initialized, version}'
```

### 1.2 Bootstrap the Session

```bash
# Create a sessions directory
mkdir -p sessions

# Bootstrap with the scenario case ID
./tools/sirm/sirm-bootstrap.sh \
  --operator "$(whoami)" \
  --case-id "CASE-2026-WORKSHOP-001" \
  --classification "elevated" \
  --session-dir ./sessions \
  --verbose
```

Expected output: The bootstrap runs 5 validation phases:
1. **Operator Authentication** -- verifies operator identity
2. **Environment Validation** -- checks required tools
3. **Repository State Capture** -- records git branch, commit, dirty files
4. **Infrastructure Health** -- checks Vault status
5. **Context Snapshot** -- captures full environment state

Each phase reports PASS/WARN/FAIL. All must pass (WARNs are acceptable) for the session to reach ACTIVE state.

### 1.3 Examine the Session Directory

```bash
# Find the session ID from the bootstrap output
# It follows the format: SIRM-YYYYMMDD-HHMMSS-XXXX
SESSION_ID=$(ls sessions/ | sort | tail -1)
echo "Session ID: $SESSION_ID"

# Explore the session structure
ls -la sessions/$SESSION_ID/
```

Expected structure:
```
sessions/<SESSION_ID>/
├── bootstrap.json      # Full bootstrap context snapshot
├── session-state.json  # Current session state and metadata
├── audit.log           # Append-only audit trail
├── evidence/           # Evidence chain records
└── timeline/           # Timeline events
```

### 1.4 Check Session Status

```bash
./tools/sirm/sirm-session.sh status "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: Session is in ACTIVE state with operator, case ID, and classification displayed.

### 1.5 Review the Audit Log

```bash
cat sessions/$SESSION_ID/audit.log
```

Expected: Timestamped entries for every bootstrap phase, each with operator identity and result.

**Verification:**
- [ ] Session bootstrapped with all phases passing
- [ ] Session directory contains `bootstrap.json`, `session-state.json`, and `audit.log`
- [ ] Session status shows ACTIVE state
- [ ] Audit log contains timestamped entries for each bootstrap phase

---

## Lab 2: Evidence Collection and Chain of Custody (25 minutes)

### Concept

Evidence registration captures the SHA-256 hash of an artifact at a specific point in time, with operator identity and a description. The original file is never copied or modified -- only hashed and recorded. This maintains forensic integrity while enabling verification at any point.

### 2.1 Create Simulated Evidence Artifacts

For the workshop, we create artifacts that simulate what would be found during a real secret exposure incident.

```bash
# Create evidence directory (outside the session -- evidence is external files)
mkdir -p /tmp/workshop-evidence

# Artifact 1: The git log showing the commit with the exposed key
git log --all --oneline -20 > /tmp/workshop-evidence/git-log-snapshot.txt

# Artifact 2: Simulated gitleaks scan output
cat > /tmp/workshop-evidence/gitleaks-scan-results.json <<'EOF'
{
  "scan_timestamp": "2026-03-13T14:22:00Z",
  "scanner": "gitleaks/8.21.2",
  "findings": [
    {
      "description": "Generic API Key",
      "file": "src/payments/config.py",
      "commit": "a1b2c3d",
      "author": "developer@example.com",
      "date": "2026-03-13T09:15:00Z",
      "line": 42,
      "match": "PAYMENT_API_KEY = \"pk_live_*****\"",
      "rule_id": "generic-api-key",
      "entropy": 4.8
    }
  ],
  "total_findings": 1
}
EOF

# Artifact 3: Vault audit log excerpt (simulated)
cat > /tmp/workshop-evidence/vault-audit-excerpt.json <<'EOF'
{
  "type": "response",
  "time": "2026-03-13T14:30:00Z",
  "auth": {
    "token_type": "service",
    "policies": ["demo-app"],
    "metadata": {"role_name": "demo-app"}
  },
  "request": {
    "operation": "read",
    "path": "secret/data/payments/api-keys",
    "remote_address": "10.0.1.42"
  },
  "response": {
    "data": {"keys": ["api_key", "webhook_secret"]}
  }
}
EOF

# Artifact 4: The .env file from the developer's machine (simulated)
cat > /tmp/workshop-evidence/developer-env-snapshot.txt <<'EOF'
# Captured from developer workstation 2026-03-13T15:00:00Z
# Operator: workshop-analyst
# Method: screenshot of terminal output
VAULT_ADDR=http://localhost:8200
PAYMENT_API_KEY=pk_live_EXPOSED_KEY_VALUE
DATABASE_URL=postgresql://app:password@db:5432/payments
EOF

echo "Evidence artifacts created in /tmp/workshop-evidence/"
ls -la /tmp/workshop-evidence/
```

### 2.2 Register Evidence

```bash
# Register each artifact with the session
./tools/sirm/sirm-evidence.sh register "$SESSION_ID" \
  /tmp/workshop-evidence/git-log-snapshot.txt \
  --description "Git log snapshot at time of incident detection" \
  --classification "INTERNAL" \
  --session-dir ./sessions

./tools/sirm/sirm-evidence.sh register "$SESSION_ID" \
  /tmp/workshop-evidence/gitleaks-scan-results.json \
  --description "Gitleaks scan output showing exposed API key in payments config" \
  --classification "INTERNAL" \
  --session-dir ./sessions

./tools/sirm/sirm-evidence.sh register "$SESSION_ID" \
  /tmp/workshop-evidence/vault-audit-excerpt.json \
  --description "Vault audit log excerpt showing payments secret access patterns" \
  --classification "INTERNAL" \
  --session-dir ./sessions

./tools/sirm/sirm-evidence.sh register "$SESSION_ID" \
  /tmp/workshop-evidence/developer-env-snapshot.txt \
  --description "Developer workstation environment snapshot showing exposed key" \
  --classification "RESTRICTED" \
  --session-dir ./sessions
```

Expected: Each registration outputs the evidence ID, SHA-256 hash, and timestamp.

### 2.3 List Registered Evidence

```bash
./tools/sirm/sirm-evidence.sh list "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: A table or list showing all 4 evidence items with their IDs, descriptions, hashes, and registration timestamps.

### 2.4 Verify Evidence Integrity

```bash
# Verify all evidence
./tools/sirm/sirm-evidence.sh verify "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: All evidence items pass integrity verification (SHA-256 hashes match).

**Simulate tampering:**

```bash
# Tamper with an evidence file
echo "TAMPERED" >> /tmp/workshop-evidence/developer-env-snapshot.txt

# Re-verify
./tools/sirm/sirm-evidence.sh verify "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: The tampered file fails verification (hash mismatch). This demonstrates why evidence is hashed at registration time.

**Restore the file for subsequent labs:**

```bash
# Remove the tampered line
head -n -1 /tmp/workshop-evidence/developer-env-snapshot.txt > /tmp/workshop-evidence/tmp && \
  mv /tmp/workshop-evidence/tmp /tmp/workshop-evidence/developer-env-snapshot.txt
```

### 2.5 Generate Evidence Manifest

```bash
./tools/sirm/sirm-evidence.sh manifest "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: A complete manifest listing all evidence items, their hashes, registration timestamps, and chain of custody entries.

**Verification:**
- [ ] Registered 4 evidence artifacts with descriptions and classifications
- [ ] Each registration produced a SHA-256 hash
- [ ] Evidence integrity verification passed for all items
- [ ] Tampering was detected by the verification step
- [ ] Evidence manifest generated successfully

---

## Lab 3: Timeline Construction with F/O/I/H Classification (25 minutes)

### Concept

The SIRM timeline is an ordered sequence of events, each classified by confidence level:

| Code | Classification | Definition | Weight |
|------|---------------|-----------|--------|
| **F** | Fact | Directly observed, independently verifiable | Full evidentiary weight |
| **O** | Observation | Witnessed but not independently verified | Increases weight |
| **I** | Inference | Derived from facts/observations via reasoning | Conditional weight |
| **H** | Hypothesis | Proposed explanation requiring validation | No weight until supported |

This classification prevents narrative bias -- a common failure mode in incident response where investigators assume a conclusion and fit evidence to match.

### 3.1 Add Timeline Events

Build the incident timeline from the scenario:

```bash
# Event 1: FACT — The commit containing the key
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-13T09:15:00Z" \
  --source "git-log" \
  --type "commit" \
  --confidence "F" \
  --description "Developer committed payments/config.py containing PAYMENT_API_KEY to branch feature/checkout-v2" \
  --evidence-ref "EV-001" \
  --session-dir ./sessions

# Event 2: FACT — The push to remote
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-13T09:18:00Z" \
  --source "git-log" \
  --type "push" \
  --confidence "F" \
  --description "Branch feature/checkout-v2 pushed to origin (remote repository)" \
  --session-dir ./sessions

# Event 3: OBSERVATION — Last known key usage before exposure
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-13T08:45:00Z" \
  --source "vault-audit" \
  --type "secret-access" \
  --confidence "O" \
  --description "Vault audit log shows payments/api-keys read from 10.0.1.42 via demo-app role" \
  --evidence-ref "EV-003" \
  --session-dir ./sessions

# Event 4: FACT — Gitleaks detection
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-16T14:22:00Z" \
  --source "scanner" \
  --type "detection" \
  --confidence "F" \
  --description "Gitleaks pre-commit scan detected generic-api-key pattern in payments/config.py with entropy 4.8" \
  --evidence-ref "EV-002" \
  --session-dir ./sessions

# Event 5: INFERENCE — Exposure window estimate
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-13T09:18:00Z" \
  --source "analyst" \
  --type "analysis" \
  --confidence "I" \
  --description "Key was exposed in remote repository from push time (03-13 09:18Z) to detection (03-16 14:22Z) -- approximately 77 hours" \
  --session-dir ./sessions

# Event 6: HYPOTHESIS — Was the key used by an unauthorized party?
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-16T15:00:00Z" \
  --source "analyst" \
  --type "hypothesis" \
  --confidence "H" \
  --description "The exposed key MAY have been harvested by automated GitHub scanning bots that target payment API keys" \
  --session-dir ./sessions

# Event 7: FACT — Key rotation initiated
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-16T15:10:00Z" \
  --source "operator" \
  --type "remediation" \
  --confidence "F" \
  --description "Payment API key rotated via vendor dashboard; old key invalidated" \
  --session-dir ./sessions
```

### 3.2 View the Timeline

```bash
./tools/sirm/sirm-timeline.sh export "$SESSION_ID" \
  --format json \
  --session-dir ./sessions | jq .
```

Expected: All 7 events in chronological order with their classifications, sources, and evidence references.

### 3.3 Filter by Confidence Level

```bash
# Show only Facts
./tools/sirm/sirm-timeline.sh export "$SESSION_ID" \
  --filter-confidence "F" \
  --format json \
  --session-dir ./sessions | jq '.[] | {timestamp, description, confidence}'

# Show only Hypotheses (need validation)
./tools/sirm/sirm-timeline.sh export "$SESSION_ID" \
  --filter-confidence "H" \
  --format json \
  --session-dir ./sessions | jq '.[] | {timestamp, description, confidence}'
```

### 3.4 Filter by Time Range

```bash
# Events on the day of the commit only
./tools/sirm/sirm-timeline.sh export "$SESSION_ID" \
  --filter-since "2026-03-13T00:00:00Z" \
  --filter-until "2026-03-14T00:00:00Z" \
  --format json \
  --session-dir ./sessions | jq '.[] | {timestamp, type, description}'
```

### 3.5 Analyze the Timeline

Key observations from the timeline:

1. **Facts (F)** establish the hard boundaries: the key was committed at 09:15Z, pushed at 09:18Z, detected at 14:22Z three days later, and rotated at 15:10Z.
2. **Observations (O)** provide context: the key was accessed via Vault before the exposure, suggesting the developer may have copied it from a legitimate source.
3. **Inferences (I)** quantify risk: the 77-hour exposure window is derived from facts but is itself an interpretation.
4. **Hypotheses (H)** identify open questions: whether the key was actually harvested requires investigation of payment API vendor logs (external evidence not yet collected).

The F/O/I/H classification prevents premature conclusions. An analyst can filter to Facts-only to see what is definitively known, then assess whether Hypotheses have enough supporting evidence to escalate.

**Verification:**
- [ ] Added 7 timeline events with different confidence classifications
- [ ] Timeline exports in chronological order
- [ ] Can filter events by confidence level (F, O, I, H)
- [ ] Can filter events by time range
- [ ] Participant can explain why separating F/O/I/H prevents narrative bias

---

## Lab 4: Report Generation and Session Sealing (20 minutes)

### Concept

A SIRM session concludes with report generation and sealing. Sealing produces a SHA-256 manifest of all session artifacts, making the record tamper-evident. A sealed session cannot be modified.

### 4.1 Close the Session with Findings

```bash
./tools/sirm/sirm-session.sh close "$SESSION_ID" \
  --findings "Payment API key (pk_live_*) exposed in Git commit a1b2c3d on branch feature/checkout-v2. Exposure window: 77 hours (2026-03-13T09:18Z to 2026-03-16T14:22Z). Key rotated and old key invalidated. Root cause: developer hardcoded key instead of using Vault SDK. Recommendation: enforce pre-commit hooks on all developer workstations, add payments-specific gitleaks rules, require PR review for files matching **/payments/**." \
  --session-dir ./sessions
```

Expected: Session transitions from ACTIVE to CLOSED state.

### 4.2 Generate the Report

```bash
./tools/sirm/sirm-session.sh export "$SESSION_ID" \
  --format json \
  --session-dir ./sessions | jq .
```

Expected: A complete session export containing:
- Session metadata (ID, operator, case ID, classification)
- Bootstrap context snapshot
- Evidence manifest with hashes
- Full timeline with classifications
- Findings and recommendations
- Audit log entries

### 4.3 Verify Session Status

```bash
./tools/sirm/sirm-session.sh status "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: Session shows CLOSED state with findings summary.

### 4.4 Seal the Session

Sealing is irreversible. It computes a SHA-256 hash over the entire session directory and writes an immutable manifest.

```bash
./tools/sirm/sirm-session.sh seal "$SESSION_ID" \
  --session-dir ./sessions
```

Expected: Session transitions from CLOSED to SEALED. A `manifest.sha256` file is generated.

### 4.5 Verify the Sealed Session

```bash
# Check session status
./tools/sirm/sirm-session.sh status "$SESSION_ID" \
  --session-dir ./sessions

# Examine the manifest
cat sessions/$SESSION_ID/manifest.sha256 2>/dev/null || \
  echo "(Manifest location may vary -- check session directory)"

# List all session files
find sessions/$SESSION_ID/ -type f | sort
```

### 4.6 Attempt to Modify a Sealed Session (Expect Failure)

```bash
# Try to add an event to a sealed session
./tools/sirm/sirm-timeline.sh add "$SESSION_ID" \
  --timestamp "2026-03-16T16:00:00Z" \
  --source "analyst" \
  --type "note" \
  --confidence "O" \
  --description "This should fail because the session is sealed" \
  --session-dir ./sessions 2>&1 || true
```

Expected: The operation fails because sealed sessions are immutable.

**Verification:**
- [ ] Session closed with findings text
- [ ] Full session export contains all evidence, timeline, and findings
- [ ] Session sealed successfully with SHA-256 manifest
- [ ] Attempt to modify a sealed session fails
- [ ] Participant understands the ACTIVE -> CLOSED -> SEALED state machine

---

## Lab 5: Break-Glass Procedure Drill (15 minutes)

### Concept

Break-glass procedures provide emergency access when normal authentication paths fail. These procedures must be tested regularly -- untested emergency procedures are not procedures, they are hopes.

### 5.1 Review the Break-Glass Playbook

```bash
cat docs/incident-playbooks/break-glass-procedure.md | head -80
```

Key elements:
- Dual-control requirement (two authorized personnel)
- Shamir key reconstruction (3-of-5 unseal keys)
- Immediate audit trail creation
- Post-event key rotation

### 5.2 Run the Break-Glass Drill

The repository includes a drill runner that simulates the break-glass procedure:

```bash
# Run in dry-run mode (no actual changes)
./tools/drill/break_glass_drill.sh \
  --dry-run \
  --operator "$(whoami)" 2>&1 || echo "(Drill runner output above)"
```

Expected: The drill runner walks through each step of the break-glass procedure, verifying that:
- Unseal key locations are documented
- Key holder contact information is current
- The procedure can be executed within the time window
- Post-event rotation steps are clear

### 5.3 Simulate Vault Seal/Unseal

```bash
# Seal Vault (in dev mode, this is safe)
vault operator seal

# Verify Vault is sealed
vault status 2>&1 | head -5
```

Expected: `Sealed: true`

```bash
# In dev mode, the unseal key is derived from the root token
# Unseal with the dev unseal key
vault operator unseal $(vault operator init -format=json 2>/dev/null | jq -r '.unseal_keys_b64[0]' 2>/dev/null || echo "")

# If the above fails in dev mode, just restart Vault
docker restart dev-vault && sleep 3
vault status
```

Expected: Vault returns to unsealed state.

### 5.4 Record the Drill in a SIRM Session

In production, every break-glass drill is documented in a SIRM session:

```bash
# Bootstrap a drill session
./tools/sirm/sirm-bootstrap.sh \
  --operator "$(whoami)" \
  --case-id "DRILL-2026-WORKSHOP-001" \
  --classification "routine" \
  --session-dir ./sessions \
  --verbose 2>&1 | tail -5

DRILL_SESSION=$(ls sessions/ | sort | tail -1)
echo "Drill session: $DRILL_SESSION"

# Add timeline events for the drill
./tools/sirm/sirm-timeline.sh add "$DRILL_SESSION" \
  --timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --source "drill-runner" \
  --type "drill" \
  --confidence "F" \
  --description "Break-glass drill executed in workshop environment. Vault seal/unseal cycle completed. All procedure steps verified." \
  --session-dir ./sessions

# Close the drill session
./tools/sirm/sirm-session.sh close "$DRILL_SESSION" \
  --findings "Break-glass drill completed successfully. Procedure documentation is current. All key holder contacts verified. Time to execute: <15 minutes." \
  --session-dir ./sessions
```

**Verification:**
- [ ] Reviewed the break-glass playbook and identified key elements
- [ ] Executed the drill runner (dry-run mode)
- [ ] Sealed and unsealed Vault
- [ ] Documented the drill in a SIRM session
- [ ] Participant can list the steps in the break-glass procedure from memory

---

## Cleanup

```bash
# Remove workshop sessions
rm -rf sessions/

# Remove evidence artifacts
rm -rf /tmp/workshop-evidence

# Reset the dev environment
make dev-reset
```

---

## Review Questions

1. **Why does SIRM hash evidence at registration time rather than copying it?**
   Copying creates a duplicate that must itself be secured and tracked. Hashing proves the evidence existed in a specific state at a specific time without duplicating data. If the original is later modified, the hash mismatch proves tampering. This follows forensic best practice: observe and record, never alter.

2. **What is the risk of classifying an Inference as a Fact?**
   It inflates the evidentiary weight of an unverified conclusion. Downstream decisions (escalation, legal action, public disclosure) may be based on something that was actually derived reasoning, not independently verifiable. The F/O/I/H system forces explicit acknowledgment of confidence levels.

3. **Why must break-glass procedures be drilled regularly?**
   People forget procedures under stress. Contact information goes stale. Key holders leave the organization. Physical safe combinations change. Storage locations move. A procedure that has not been tested in 6 months is an assumption, not a capability. Quarterly drills catch these issues before an actual emergency.

4. **What makes a sealed SIRM session tamper-evident?**
   The SHA-256 manifest covers every file in the session directory. If any file is modified after sealing, the manifest hash will not match. The seal operation is irreversible -- the session cannot transition back to an editable state. This provides the same integrity guarantee as a notarized document.

5. **When should a session use `legal-hold` classification?**
   When the session output may be used in litigation, regulatory proceedings, or expert witness testimony. Legal-hold sessions require notification to counsel, stricter evidence handling, and may be subject to preservation orders. Everything in the session becomes potentially discoverable.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `sirm-bootstrap.sh: Permission denied` | `chmod +x tools/sirm/*.sh` |
| Bootstrap fails at infrastructure health | Ensure Vault is running: `make dev-up` |
| `sha256sum: command not found` (macOS) | Use `shasum -a 256` or `brew install coreutils` |
| Evidence registration fails | Check that the file path is absolute or relative to CWD |
| Session seal fails | Session must be in CLOSED state first; close with `--findings` |
| Vault sealed after restart | Dev mode auto-unseals; run `docker restart dev-vault` |

---

## Next Steps

- **Reference:** [SIRM Framework](../19-sirm-framework.md) for the full design rationale
- **Reference:** [SIRM Session Protocol](../20-sirm-session-protocol.md) for production operational procedures
- **Reference:** [Secret Exposure Response Playbook](../incident-playbooks/secret-exposure-response.md)
- **Reference:** [Break-Glass Procedure](../incident-playbooks/break-glass-procedure.md)
