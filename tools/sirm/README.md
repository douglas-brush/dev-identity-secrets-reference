# SIRM — Security Incident Response Management Toolkit

Shell-based forensic session management for incident response, digital forensics, and expert witness work. Designed for environments where chain of custody, evidence integrity, and court-admissible workflows are non-negotiable.

## Why SIRM Exists

Standard IR tooling assumes cloud-first, API-driven workflows. SIRM is built for the operator who needs:

- **Chain of custody from first keystroke** — every session action is logged with ISO UTC timestamps, operator identity, and cryptographic hashes
- **Evidence integrity guarantees** — evidence files are NEVER copied, moved, or modified; only hashed and recorded
- **Court-admissible audit trails** — structured, tamper-evident session records suitable for federal court proceedings
- **Air-gapped compatibility** — pure shell, no network dependencies, no SaaS lock-in
- **Confidence-classified timelines** — every timeline event carries a Fact/Observation/Inference/Hypothesis classification per the Brush evidentiary weighting model

## Tools

| Script | Purpose |
|--------|---------|
| `sirm-bootstrap.sh` | Session initialization with 5-phase bootstrap protocol |
| `sirm-session.sh` | Session lifecycle management (status, suspend, resume, close, seal) |
| `sirm-evidence.sh` | Evidence chain registration, verification, and custody tracking |
| `sirm-timeline.sh` | Forensic timeline construction with confidence classification |

## Bootstrap Protocol

`sirm-bootstrap.sh` executes a 5-phase initialization sequence:

```
Phase 1: Tool Validation
  Checks for critical (git, openssl, jq) and optional (vault, sops, age) tools.
  Critical failures abort. Optional failures warn.

Phase 2: Operator Identity
  Records git config identity, hostname, Vault entity (if available).
  Establishes who is operating the session for chain of custody.

Phase 3: Environment Context
  Captures git branch, uncommitted changes, recent commits,
  Vault health, SOPS configuration, certificate inventory.

Phase 4: Session Creation
  Generates UUID, creates session directory structure,
  initializes session.json and audit.log.

Phase 5: Dashboard Output
  Displays structured session dashboard with full context.
```

### Quick Start

```bash
# Basic session
./tools/sirm/sirm-bootstrap.sh --operator "D. Brush"

# Full forensic session with case ID
./tools/sirm/sirm-bootstrap.sh \
  --operator "D. Brush" \
  --case-id "2024-CV-1234" \
  --classification RESTRICTED \
  --verbose

# Dry run — validate environment without creating session
./tools/sirm/sirm-bootstrap.sh --operator "D. Brush" --dry-run
```

## Session Lifecycle

### State Machine

```
                          ┌─────────────┐
                          │INITIALIZING │
                          └──────┬──────┘
                                 │ bootstrap complete
                                 ▼
                ┌───────── ┌──────────┐ ─────────┐
                │          │  ACTIVE   │          │
                │          └────┬──┬───┘          │
                │   suspend     │  │    resume    │
                │   + reason    │  │              │
                ▼               │  │              │
         ┌────────────┐        │  └──────────────┘
         │ SUSPENDED  │────────┘
         └────────────┘  resume
                                │ close + findings
                                ▼
                          ┌──────────┐
                          │  CLOSED  │
                          └────┬─────┘
                               │ seal
                               ▼
                          ┌──────────┐
                          │  SEALED  │  (irreversible)
                          └──────────┘
```

### Commands

```bash
# Check session status
./tools/sirm/sirm-session.sh status <session-id>

# Suspend with reason (e.g., awaiting lab results)
./tools/sirm/sirm-session.sh suspend <session-id> --reason "Awaiting disk image from lab"

# Resume
./tools/sirm/sirm-session.sh resume <session-id>

# Close with findings
./tools/sirm/sirm-session.sh close <session-id> --findings "No evidence of exfiltration"

# Seal (irreversible — computes SHA-256 of session record)
./tools/sirm/sirm-session.sh seal <session-id>

# List all sessions
./tools/sirm/sirm-session.sh list

# Export session
./tools/sirm/sirm-session.sh export <session-id> --format markdown
```

Partial UUID matching is supported. If `abc123` uniquely identifies a session, you do not need the full UUID.

## Evidence Management

### Principles

1. **READ-ONLY** — evidence files are never copied, moved, or modified
2. **Hash-and-record** — SHA-256 is computed and stored at registration
3. **Verify-on-demand** — re-hash at any time to confirm integrity
4. **Chain of custody** — every transfer is logged with from/to/reason/timestamp

### Commands

```bash
# Register evidence (computes SHA-256, records path — never touches the file)
./tools/sirm/sirm-evidence.sh register <session-id> /path/to/disk.img \
  --description "Primary disk image from workstation" \
  --classification RESTRICTED

# Verify all evidence integrity
./tools/sirm/sirm-evidence.sh verify <session-id>

# Verify specific evidence item
./tools/sirm/sirm-evidence.sh verify <session-id> EV-001

# Log custody transfer
./tools/sirm/sirm-evidence.sh transfer <session-id> EV-001 \
  --to "Lab Tech A" \
  --reason "Forensic analysis — write blocker attached"

# Generate evidence manifest with chain of custody
./tools/sirm/sirm-evidence.sh manifest <session-id> --format text

# List registered evidence
./tools/sirm/sirm-evidence.sh list <session-id>
```

## Timeline Builder

### Confidence Classification

Every timeline event carries a confidence code derived from the Brush evidentiary weighting model:

| Code | Level | Weight | Description |
|------|-------|--------|-------------|
| `F` | Fact | Evidentiary | Verified through independent evidence; machine-generated logs with proven integrity |
| `O` | Observation | Evidentiary | Direct observation by qualified operator; first-hand account |
| `I` | Inference | Conditional | Derived from facts/observations; logical deduction with stated assumptions |
| `H` | Hypothesis | None | Unverified theory; requires supporting evidence before weight is assigned |

Only `F` and `O` events carry evidentiary weight in court proceedings.

### Event Types

Common event types (not restricted — use any string):

- `action` — deliberate operator action
- `observation` — something observed during investigation
- `artifact` — discovery of a forensic artifact
- `commit` — git commit (auto-assigned by import-git)
- `log_entry` — imported log entry
- `vault_audit` — Vault audit log entry
- `network` — network activity event
- `access` — access/authentication event

### Commands

```bash
# Add a manual event
./tools/sirm/sirm-timeline.sh add <session-id> \
  --source operator \
  --type action \
  --description "Initiated disk acquisition via dd" \
  --confidence F \
  --evidence-ref EV-001

# Import git log as timeline events (all commits = confidence F)
./tools/sirm/sirm-timeline.sh import-git <session-id> --since "2024-01-01"

# Import syslog
./tools/sirm/sirm-timeline.sh import-log <session-id> /var/log/auth.log --format syslog

# Import JSON-structured logs
./tools/sirm/sirm-timeline.sh import-log <session-id> app.log.json --format json

# Import Vault audit log
./tools/sirm/sirm-timeline.sh import-log <session-id> vault-audit.log --format vault-audit

# Show timeline with filters
./tools/sirm/sirm-timeline.sh show <session-id> --confidence F --type action

# Export as markdown
./tools/sirm/sirm-timeline.sh export <session-id> --format markdown
```

## Integration with Repo Tools

SIRM sessions complement the existing tooling in this repository:

| Repo Tool | SIRM Integration |
|-----------|-----------------|
| `secrets-doctor` | Run before bootstrap to validate environment health; register output as evidence |
| `identity-inventory` | Register identity audit reports as evidence artifacts |
| `credential-age-report` | Import credential age data as timeline events for exposure analysis |
| `ceremony/` | Ceremony outputs (key generation, rotation) can be registered as evidence |
| `scanning/` | Scan results registered as evidence; findings added to timeline |

### Example: Full IR Workflow

```bash
# 1. Bootstrap session
./tools/sirm/sirm-bootstrap.sh --operator "D. Brush" --case-id "IR-2024-0042" \
  --classification CONFIDENTIAL --verbose

# 2. Run secrets-doctor, register output
./tools/secrets-doctor/doctor.sh all --json > /tmp/doctor-report.json
./tools/sirm/sirm-evidence.sh register <session-id> /tmp/doctor-report.json \
  --description "secrets-doctor baseline scan"

# 3. Register evidence artifacts
./tools/sirm/sirm-evidence.sh register <session-id> /evidence/disk.img \
  --description "Suspect workstation disk image" --classification RESTRICTED

# 4. Build timeline from git history
./tools/sirm/sirm-timeline.sh import-git <session-id> --since "2024-01-01"

# 5. Add investigator observations
./tools/sirm/sirm-timeline.sh add <session-id> \
  --source operator --type observation \
  --description "Anomalous commits to secrets/ directory outside business hours" \
  --confidence O --evidence-ref EV-001

# 6. Verify evidence integrity before closing
./tools/sirm/sirm-evidence.sh verify <session-id>

# 7. Close and seal
./tools/sirm/sirm-session.sh close <session-id> \
  --findings "Unauthorized access to secrets directory confirmed via git log analysis"
./tools/sirm/sirm-session.sh seal <session-id>

# 8. Export for counsel
./tools/sirm/sirm-session.sh export <session-id> --format markdown > report.md
```

## Session Directory Structure

```
sessions/
└── <uuid>/
    ├── session.json      # Session state, evidence registry, timeline, audit trail
    ├── audit.log         # Append-only audit log (ISO UTC timestamps)
    └── evidence/         # Reserved for evidence metadata (source files never copied here)
```

## Session JSON Schema

```json
{
  "id": "uuid",
  "version": "1.0.0",
  "operator": "string",
  "classification": "INTERNAL|CONFIDENTIAL|RESTRICTED|COURT-SEALED|PUBLIC",
  "case_id": "string",
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",
  "state": "INITIALIZING|ACTIVE|SUSPENDED|CLOSED|SEALED",
  "identity": { "git_user", "git_email", "hostname", "vault_entity" },
  "context": { "git_branch", "git_uncommitted", "vault_health", "sops_config", "cert_count" },
  "phases": [{ "phase", "status", "timestamp", "detail" }],
  "tools": [{ "tool", "status", "critical", "version" }],
  "evidence": [{
    "id": "EV-NNN",
    "path": "absolute path",
    "hash": "SHA-256",
    "description": "string",
    "classification": "string",
    "chain_of_custody": [{ "timestamp", "custodian", "action", "detail" }]
  }],
  "timeline": [{
    "timestamp": "ISO-8601",
    "source": "string",
    "type": "string",
    "description": "string",
    "confidence": "F|O|I|H",
    "evidence_refs": ["EV-NNN"]
  }],
  "findings": "string (set on close)",
  "sealed": false,
  "seal_hash": "SHA-256 (set on seal)"
}
```

## Requirements

**Critical** (bootstrap fails without these):
- `git`
- `openssl`
- `jq`

**Optional** (warned if missing):
- `vault` — Vault identity and health checks
- `sops` — SOPS configuration validation
- `age` / `age-keygen` — age encryption support
- `uuidgen` — session UUID generation (falls back to openssl)
- `sha256sum` / `shasum` — evidence hashing (one must be present)
