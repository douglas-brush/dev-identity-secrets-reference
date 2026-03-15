# SIRM Framework — Security Incident Response Management Sessions

## Purpose

The SIRM (Security Incident Response Management) framework provides structured session management for incident response, forensic analysis, and security operations. Every SIRM session produces a self-contained, tamper-evident artifact that serves as both an operational record and court-admissible evidence.

SIRM sessions enforce:

- **Chain of custody** — every evidence artifact is registered with operator identity, timestamp, and cryptographic hash
- **Evidence integrity** — SHA-256 verification at registration and seal time; read-only evidence directories
- **Reproducibility** — full context capture (git state, tool versions, vault health) at session bootstrap
- **Auditability** — immutable timeline with classified entries, structured findings, and sealed reports

This framework integrates with the existing tooling in this repository (`secrets-doctor`, `identity-inventory`, `credential-age-report`, `break-glass-drill`) to provide a forensically sound wrapper around security operations.

---

## Session Lifecycle State Machine

```
                    ┌──────────────────────────────────┐
                    │          NOT_STARTED              │
                    └──────────────┬───────────────────┘
                                   │ sirm bootstrap
                                   │ [operator authenticated, case ID assigned]
                    ┌──────────────▼───────────────────┐
                    │          BOOTSTRAPPING            │
                    │  (5-phase validation sequence)    │
                    └──────────────┬───────────────────┘
                                   │ all phases pass
                                   │ [context snapshot captured]
                    ┌──────────────▼───────────────────┐
                    │            ACTIVE                 │
                    │  (evidence, timeline, findings)   │
                    └───────┬──────────────┬───────────┘
                            │              │
                   sirm close         sirm abort
                   [findings written]  [reason logged]
                    ┌───────▼──────┐  ┌─▼─────────────┐
                    │   CLOSED     │  │   ABORTED      │
                    │ (report gen) │  │ (partial data) │
                    └───────┬──────┘  └────────────────┘
                            │ sirm seal
                            │ [SHA-256 manifest, irreversible]
                    ┌───────▼──────────────────────────┐
                    │           SEALED                  │
                    │  (tamper-evident, immutable)      │
                    └──────────────────────────────────┘
```

### Transition Guards

| Transition | Guard Condition |
|------------|----------------|
| NOT_STARTED -> BOOTSTRAPPING | Operator identity verified, case ID non-empty |
| BOOTSTRAPPING -> ACTIVE | All 5 bootstrap phases pass; context snapshot written |
| ACTIVE -> CLOSED | At least one finding recorded; evidence manifest generated |
| ACTIVE -> ABORTED | Abort reason provided; partial evidence preserved |
| CLOSED -> SEALED | Report generated; all evidence hashes verified; operator confirms |

Transitions are append-only in the session log. No backward transitions exist. A sealed session cannot be reopened — start a new session referencing the sealed one.

---

## Bootstrap Protocol (5 Phases)

Bootstrap runs sequentially. Each phase must pass before the next begins. Failure at any phase halts the session with a diagnostic.

### Phase 1: Operator Authentication

- Verify operator identity (username, hostname, SSH key fingerprint if available)
- Record operator's role and authorization level
- Timestamp: ISO 8601 UTC

### Phase 2: Environment Validation

- Verify required tools are installed (`vault`, `sops`, `openssl`, `jq`, `sha256sum`)
- Check tool versions against minimum requirements
- Validate shell environment (`set -euo pipefail` enforcement)

### Phase 3: Repository State Capture

- Git branch, commit hash, dirty status, remote URL
- Uncommitted changes inventory (filenames only, not content)
- `.sops.yaml` configuration hash
- Pre-commit hook status

### Phase 4: Infrastructure Health

- Vault connectivity and seal status (if `VAULT_ADDR` set)
- SOPS decryption test (if encrypted files exist)
- Certificate expiry check on any loaded certs
- DNS resolution for critical endpoints

### Phase 5: Context Snapshot

- Aggregate phases 1-4 into a JSON context document
- Generate SHA-256 hash of the context document
- Write context to `session/<session-id>/context.json`
- Record bootstrap completion timestamp

---

## Evidence Management Principles

### Read-Only Evidence

Evidence directories are treated as **append-only, never-modify** stores:

```
session/<session-id>/
├── context.json              # Bootstrap context snapshot
├── evidence/                 # Registered evidence artifacts
│   ├── manifest.json         # Evidence registry (hash, source, timestamp)
│   ├── 001-secrets-doctor-output.txt
│   ├── 002-identity-inventory.json
│   └── ...
├── timeline.jsonl            # Append-only timeline events
├── findings.json             # Classified findings
├── report.md                 # Generated report
└── seal.json                 # Seal manifest (after sealing)
```

### Hash Verification

Every evidence artifact is hashed at registration time:

```json
{
  "evidence_id": "001",
  "filename": "secrets-doctor-output.txt",
  "sha256": "a1b2c3d4...",
  "registered_by": "dbrush",
  "registered_at": "2026-03-15T14:30:00Z",
  "source": "tools/secrets-doctor/doctor.sh audit",
  "description": "Full secrets-doctor audit output"
}
```

At seal time, every hash is re-verified. Any mismatch aborts the seal with a tamper alert.

### Chain of Custody

The evidence manifest records:

1. **Who** registered each artifact (operator identity)
2. **When** it was registered (UTC timestamp)
3. **What** produced it (source command or manual entry)
4. **How** it was verified (SHA-256 at registration, re-verified at seal)

### Tamper Detection

- Evidence files are hashed at write time and re-verified at seal time
- The session timeline is append-only JSONL — no edits, no deletions
- The seal manifest includes a hash of hashes (Merkle-style root) covering all session artifacts
- Any modification to any file after sealing invalidates the root hash

---

## Timeline Event Model

The timeline is an append-only JSONL file. Each event follows this structure:

```json
{
  "seq": 1,
  "timestamp": "2026-03-15T14:32:00Z",
  "operator": "dbrush",
  "type": "finding",
  "classification": "F",
  "confidence": "dominant",
  "summary": "Vault root token found in CI variable store",
  "detail": "Environment variable VAULT_TOKEN in GitHub Actions org secrets contains a root token, not a scoped policy token.",
  "evidence_refs": ["001", "003"],
  "tags": ["vault", "ci", "root-token", "critical"]
}
```

### Confidence Classification

Every timeline entry with an analytical claim carries a classification code and confidence level:

| Code | Type | Weight Rule | Example |
|------|------|-------------|---------|
| **F** | Fact | Increases evidentiary weight | "Root token present in env var — confirmed via API" |
| **O** | Observation | Increases evidentiary weight | "Token last rotated 847 days ago per audit log" |
| **I** | Inference | Conditional weight only | "Likely exposed during the March deploy pipeline" |
| **H** | Hypothesis | No weight until supported | "Attacker may have exfiltrated via CI logs" |

Confidence scale:

| Level | Threshold | Meaning |
|-------|-----------|---------|
| `weak` | < 0.35 | Preliminary, needs corroboration |
| `moderate` | 0.35 - 0.65 | Supported but competing explanations exist |
| `strong` | 0.65 - 0.85 | Dominant path, tested against alternatives |
| `dominant` | > 0.85 | Corroborated across independent evidence |

Only **F** and **O** entries with `strong` or `dominant` confidence contribute to findings. **I** and **H** entries are preserved in the timeline for completeness but flagged in reports.

---

## Context Loading

At bootstrap and optionally during the session, SIRM captures context snapshots. Each snapshot records:

| Context Area | What Is Captured | Why |
|-------------|-----------------|-----|
| Git state | Branch, commit, dirty files, remote | Reproducibility — pin findings to exact code state |
| Vault health | Seal status, HA mode, version, auth methods | Infrastructure posture at time of analysis |
| Identity inventory | Service accounts, API keys, non-human identities | Scope of exposure — what credentials exist |
| Certificate status | Expiry dates, chain validity, key sizes | PKI posture assessment |
| Tool versions | Vault CLI, SOPS, OpenSSL, jq, gitleaks | Reproducibility — same tools, same results |
| Secrets doctor | Overall health score, failing checks | Baseline repository security posture |

Context snapshots are themselves registered as evidence artifacts, ensuring the environmental conditions at the time of analysis are preserved.

---

## Integration Points

SIRM wraps existing tools, capturing their output as registered evidence:

| Tool | SIRM Integration | Evidence Type |
|------|-----------------|---------------|
| `secrets-doctor` | `sirm run secrets-doctor` | Health diagnostic output |
| `identity-inventory` | `sirm run identity-inventory` | NHI inventory JSON |
| `credential-age-report` | `sirm run credential-age-report` | Credential age analysis |
| `break-glass-drill` | `sirm run break-glass-drill` | Drill results and timing |
| `enhanced-scan` | `sirm run enhanced-scan` | Secret scanning results |
| `entropy-check` | `sirm run entropy-check` | Entropy analysis output |
| Git log | `sirm import-git-log` | Commit history for timeline |
| Manual entry | `sirm add-finding` | Analyst observations and findings |

When run through SIRM, each tool's output is:

1. Captured to a temp file
2. SHA-256 hashed
3. Copied to the session evidence directory
4. Registered in the evidence manifest
5. Optionally imported into the timeline as events

---

## Report Generation

Reports follow the standard format: **executive summary -> findings -> recommendations**.

### Structure

```markdown
# SIRM Session Report — [Case ID]
## Executive Summary
- Session ID, operator, duration, classification
- One-paragraph synopsis of findings
- Critical finding count and severity breakdown

## Findings
### Finding F-001: [Title]
- Classification: F/O/I/H
- Confidence: weak/moderate/strong/dominant
- Evidence: [refs]
- Detail: [description]
- Impact: [assessment]

## Recommendations
### R-001: [Title]
- Priority: critical/high/medium/low
- Related findings: [refs]
- Action: [specific remediation steps]

## Evidence Inventory
| ID | Filename | SHA-256 | Source | Registered |
|----|----------|---------|--------|------------|

## Session Metadata
- Bootstrap context hash, seal status, operator, timestamps
```

Reports are generated from structured data — not manually written. The `sirm report` command aggregates findings, evidence, and timeline into the report template.

---

## Security Model

### Session Sealing

Sealing is a one-way operation that:

1. Re-verifies every evidence artifact hash
2. Re-verifies the timeline integrity (sequential, no gaps)
3. Generates a Merkle-style root hash covering all session files
4. Writes a `seal.json` with the root hash, operator, and timestamp
5. Records the seal event as the final timeline entry

After sealing:

- No files in the session directory should be modified (the seal hash will not match)
- The seal can be independently verified by any party with `sha256sum`
- The sealed session is a self-contained evidentiary package

### Audit Trail Immutability

- Timeline entries are append-only JSONL — parseable, diffable, not editable in place
- Evidence manifest entries are append-only
- Session state transitions are logged and never reversed
- All timestamps are UTC ISO 8601, sourced from the system clock at write time

### SHA-256 Tamper Evidence

Every artifact in the session is covered by SHA-256:

```
seal.json
├── root_hash: SHA-256(context.json || manifest.json || timeline.jsonl || findings.json || report.md)
├── evidence_hashes: { "001": "a1b2...", "002": "c3d4...", ... }
├── timeline_hash: SHA-256(timeline.jsonl)
└── sealed_by: "dbrush"
    sealed_at: "2026-03-15T16:00:00Z"
```

---

## Compliance Mapping

SIRM sessions directly produce evidence for compliance frameworks:

| Framework | Control Area | What SIRM Provides |
|-----------|-------------|-------------------|
| **SOC 2** | CC7.2 — Incident monitoring | Structured session with timeline, evidence, findings |
| **SOC 2** | CC7.3 — Incident response | Bootstrap-to-seal workflow with chain of custody |
| **SOC 2** | CC7.4 — Incident recovery | Recommendations with priority and remediation steps |
| **NIST CSF** | RS.AN — Analysis | Classified findings with confidence ratings |
| **NIST CSF** | RS.RP — Response planning | Structured protocol with pre-session checklist |
| **NIST CSF** | DE.AE — Anomaly detection | Tool integration captures detection evidence |
| **NIST 800-53** | IR-4 — Incident handling | Full lifecycle from bootstrap to sealed report |
| **NIST 800-53** | IR-5 — Incident monitoring | Append-only timeline with classified events |
| **NIST 800-53** | AU-10 — Non-repudiation | SHA-256 sealing with operator identity |
| **ISO 27001** | A.5.24 — Incident management planning | Defined protocol with checklists and state machine |
| **ISO 27001** | A.5.25 — Assessment and decision | Confidence classification (F/O/I/H) on all findings |
| **ISO 27001** | A.5.26 — Response to incidents | Evidence-backed report with recommendations |
| **ISO 27001** | A.5.28 — Collection of evidence | Hash-verified evidence with chain of custody |

A sealed SIRM session, combined with its report, satisfies the evidence collection and incident documentation requirements across these frameworks without additional artifact preparation.
