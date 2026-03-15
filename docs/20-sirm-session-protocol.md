# SIRM Session Protocol — Operational Runbook

This document is the operational protocol for running SIRM sessions. For architecture and design rationale, see [SIRM Framework](19-sirm-framework.md).

---

## Pre-Session Checklist

Complete before invoking `sirm bootstrap`:

| # | Check | Command / Action | Pass Criteria |
|---|-------|-----------------|---------------|
| 1 | Operator identified | `whoami && hostname` | Known operator, authorized workstation |
| 2 | Case ID assigned | Manual or from case management system | Non-empty, unique, follows `CASE-YYYY-NNN` format |
| 3 | Classification set | `SIRM_CLASSIFICATION={routine,elevated,critical,legal-hold}` | Appropriate to incident severity |
| 4 | Git repo clean | `git status` | Working tree clean or changes documented |
| 5 | Required tools present | `make doctor` | `vault`, `sops`, `openssl`, `jq`, `sha256sum` available |
| 6 | Vault accessible (if needed) | `vault status` | Vault unsealed and responsive |
| 7 | Time sync verified | `date -u` | System clock within 5s of NTP source |
| 8 | Session directory writable | `mkdir -p sessions/` | Write permissions confirmed |

### Classification Levels

| Level | When to Use | Ceremony Required |
|-------|------------|-------------------|
| `routine` | Scheduled audits, health checks, drill reviews | Standard bootstrap |
| `elevated` | Active security concern, failed scan, suspicious finding | Standard bootstrap + notification |
| `critical` | Confirmed incident, active compromise, data exposure | Full bootstrap + escalation |
| `legal-hold` | Litigation, regulatory inquiry, expert witness engagement | Full bootstrap + counsel notification |

---

## Bootstrap Sequence

### Step 1: Initialize Session

```bash
# Set session parameters
export SIRM_CASE_ID="CASE-2026-042"
export SIRM_CLASSIFICATION="elevated"
export SIRM_OPERATOR="$(whoami)"

# Bootstrap the session
make sirm-init
```

Bootstrap runs the 5-phase validation (see [SIRM Framework, Bootstrap Protocol](19-sirm-framework.md#bootstrap-protocol-5-phases)):

1. Operator authentication
2. Environment validation
3. Repository state capture
4. Infrastructure health
5. Context snapshot

Each phase outputs pass/fail. All phases must pass for the session to reach `ACTIVE` state.

### Step 2: Verify Bootstrap

```bash
# Check session status
make sirm-status
```

Expected output for a healthy session:

```
SIRM Session: CASE-2026-042
State:         ACTIVE
Operator:      dbrush
Classification: elevated
Bootstrap:     2026-03-15T14:30:00Z
Evidence:      0 artifacts registered
Timeline:      1 entry (bootstrap)
```

---

## During-Session Protocol

### Registering Evidence

Evidence can be registered from tool output or external files:

```bash
# Run a tool and register its output as evidence
./tools/sirm/sirm.sh run secrets-doctor
./tools/sirm/sirm.sh run identity-inventory
./tools/sirm/sirm.sh run credential-age-report

# Register an external file as evidence
./tools/sirm/sirm.sh register-evidence /path/to/artifact.log \
  --source "manual collection from production host" \
  --description "Application server auth.log for March 15"

# Import git log as timeline events
./tools/sirm/sirm.sh import-git-log --since="2026-03-01"
```

Every registration:

1. Copies the artifact to the session evidence directory
2. Computes SHA-256 hash
3. Appends an entry to the evidence manifest
4. Logs a timeline event recording the registration

### Adding Timeline Entries

```bash
# Add a classified finding
./tools/sirm/sirm.sh add-finding \
  --classification F \
  --confidence dominant \
  --summary "Static root token in CI environment" \
  --detail "GitHub Actions org secret VAULT_TOKEN contains a Vault root token. Token has no TTL and full policy access." \
  --evidence-refs "001,003" \
  --tags "vault,ci,critical"

# Add an observation
./tools/sirm/sirm.sh add-finding \
  --classification O \
  --confidence strong \
  --summary "14 service accounts with no last-used date" \
  --detail "Identity inventory shows 14 NHIs with creation dates >1 year ago and no recorded usage." \
  --evidence-refs "002"

# Add a hypothesis
./tools/sirm/sirm.sh add-finding \
  --classification H \
  --confidence weak \
  --summary "Potential lateral movement via shared service account" \
  --detail "SA 'deploy-bot' has access to production Vault namespace. If compromised, provides cross-environment access."
```

### Context Snapshots

Take additional context snapshots during the session to capture environmental changes:

```bash
# Capture a mid-session context snapshot
./tools/sirm/sirm.sh snapshot --reason "Post-remediation state capture"
```

Snapshots are registered as evidence and provide before/after comparison capability.

---

## Session Close Protocol

### Step 1: Review Findings

Before closing, verify that all findings are recorded and classified:

```bash
# List all findings with their classifications
./tools/sirm/sirm.sh list-findings
```

Review the output. Ensure:

- Every finding has an appropriate classification (F/O/I/H)
- Confidence levels reflect the evidence weight
- Evidence references are correct
- No pending observations remain unrecorded

### Step 2: Generate Report

```bash
# Generate the session report
make sirm-report
```

The report aggregates:

- Session metadata (case ID, operator, duration, classification)
- Executive summary (auto-generated from findings)
- All findings ordered by severity and confidence
- Recommendations derived from findings
- Evidence inventory with hashes
- Session timeline summary

### Step 3: Verify Evidence Integrity

```bash
# Verify all evidence hashes before closing
./tools/sirm/sirm.sh verify-evidence
```

This re-computes SHA-256 for every registered artifact and compares against the manifest. Any mismatch is flagged as a potential tamper event.

### Step 4: Close the Session

```bash
# Close the session (transitions from ACTIVE to CLOSED)
./tools/sirm/sirm.sh close \
  --summary "Identified 3 critical findings: root token in CI, stale NHIs, expired certificates. Recommendations issued."
```

---

## Session Seal Protocol

### When to Seal

Seal a session when:

- The investigation is complete and no further evidence will be added
- The report has been reviewed and accepted
- The session artifacts may be needed for compliance evidence or legal proceedings
- You need to produce a tamper-evident package for external parties

### Sealing Process

```bash
# Seal the session (irreversible)
make sirm-seal
```

Sealing performs:

1. Final re-verification of all evidence hashes
2. Timeline integrity check (sequential, no gaps, no modifications)
3. Report hash computation
4. Merkle-style root hash generation over all session artifacts
5. `seal.json` creation with root hash, operator identity, timestamp
6. Final timeline entry recording the seal event

### What Sealing Means

- The session is cryptographically frozen
- Any modification to any file in the session directory will be detectable via hash mismatch
- The seal can be independently verified by any party using standard tools (`sha256sum`, `jq`)
- A sealed session cannot be reopened — start a new session referencing the sealed one

### Independent Verification

Any third party can verify a sealed session:

```bash
# Verify a sealed session
./tools/sirm/sirm.sh verify-seal sessions/CASE-2026-042/

# Output:
# Verifying seal for CASE-2026-042...
# [OK] context.json: hash matches
# [OK] evidence/001-secrets-doctor-output.txt: hash matches
# [OK] evidence/002-identity-inventory.json: hash matches
# [OK] timeline.jsonl: hash matches
# [OK] report.md: hash matches
# [OK] Root hash verified: a1b2c3d4e5f6...
# SEAL VALID — session integrity confirmed
```

---

## Break-Glass Session Protocol

For emergencies where full ceremony is not feasible:

### Reduced Bootstrap

```bash
# Emergency session with reduced ceremony
export SIRM_CASE_ID="CASE-2026-EMG-001"
export SIRM_CLASSIFICATION="critical"
export SIRM_BREAK_GLASS=true

make sirm-init
```

Break-glass sessions:

- Skip Phase 4 (infrastructure health) if infrastructure is compromised
- Skip Phase 3 (repository state) if operating from a clean clone
- Still enforce Phase 1 (operator identity) and Phase 5 (context snapshot)
- Are flagged in the timeline and report as break-glass sessions
- Must be back-filled with full context when the emergency is resolved

### Post-Emergency Back-Fill

After the emergency:

```bash
# Add context that was skipped during break-glass
./tools/sirm/sirm.sh backfill-context \
  --reason "Break-glass session CASE-2026-EMG-001 back-fill" \
  --phases "3,4"
```

---

## Multi-Operator Sessions

### Adding an Operator

When a second responder joins an active session:

```bash
# Register additional operator
./tools/sirm/sirm.sh add-operator \
  --name "jsmith" \
  --role "forensic-analyst" \
  --reason "Escalation — expertise in network forensics required"
```

This creates a timeline entry recording the operator addition, including who authorized it.

### Custody Transfer

When primary responsibility transfers between operators:

```bash
# Transfer primary custody
./tools/sirm/sirm.sh transfer-custody \
  --from "dbrush" \
  --to "jsmith" \
  --reason "End of shift — continuing analysis"
```

Custody transfers:

- Log a timeline event with both operators identified
- Require acknowledgment from the receiving operator
- Do not change evidence — only the active operator designation
- Are reflected in the session report

### Handoff Protocol

1. Current operator runs `sirm list-findings` and `sirm status` to produce a summary
2. Current operator adds a timeline entry summarizing work completed and work remaining
3. Custody transfer command is executed
4. New operator takes a context snapshot to capture their environment
5. New operator adds a timeline entry acknowledging receipt and planned next steps

---

## Court-Readiness Checklist

A sealed SIRM session provides the following for legal proceedings:

| Requirement | How SIRM Satisfies It |
|------------|----------------------|
| **Chain of custody** | Evidence manifest with operator, timestamp, and hash per artifact |
| **Evidence integrity** | SHA-256 at registration, re-verified at seal, Merkle root covering all files |
| **Tamper detection** | Any post-seal modification invalidates the root hash |
| **Operator identification** | Bootstrap phase 1 records operator identity; multi-operator sessions tracked |
| **Timeline reconstruction** | Append-only JSONL timeline with classified events and confidence ratings |
| **Methodology documentation** | Bootstrap protocol, tool versions, and context snapshots provide reproducibility |
| **Finding classification** | F/O/I/H codes with confidence levels distinguish fact from inference from hypothesis |
| **Independent verifiability** | Seal verification requires only `sha256sum` and `jq` — no proprietary tools |
| **Completeness** | Evidence inventory in the report lists every artifact with source and hash |
| **Report structure** | Executive summary, findings, recommendations — standard forensic report format |

### Expert Witness Package

For expert testimony, a sealed session provides:

1. The sealed session directory (all artifacts, timeline, report, seal)
2. The `verify-seal` output demonstrating integrity
3. The SIRM framework documentation (this repo) establishing the methodology
4. Tool version information from the context snapshot

This package allows opposing counsel or the court to independently verify that evidence was collected, preserved, and analyzed using a documented, repeatable methodology.
