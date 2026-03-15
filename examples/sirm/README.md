# SIRM Session Examples

Example scripts demonstrating SIRM (Security Incident Response Management) session workflows.

## Examples

| Script | Use Case | Classification |
|--------|----------|---------------|
| `basic-session.sh` | Routine audit, health check review, scheduled assessment | `routine` |
| `incident-response-session.sh` | Active security incident with evidence collection and IR findings | `critical` |

## When to Use Each Pattern

### Basic Session (`basic-session.sh`)

Use for scheduled, non-urgent work:

- Quarterly secrets health audits
- Break-glass drill documentation
- Compliance evidence collection (SOC 2, NIST CSF, ISO 27001)
- Post-rotation verification sessions
- Certificate expiry review and documentation

The basic session demonstrates: bootstrap, tool execution with evidence registration, classified timeline entries, report generation, and sealing.

### Incident Response Session (`incident-response-session.sh`)

Use when responding to a security event:

- Credential exposure or leak
- Unauthorized access detection
- Failed secret scans in CI
- Certificate compromise
- Break-glass activation (real, not drill)

The IR session demonstrates: elevated bootstrap, git log import for timeline correlation, full tool suite execution, manual findings with F/O/I/H classification and confidence ratings, mid-session context snapshots, and sealed evidence packaging.

## Running the Examples

```bash
# Basic session with defaults
./examples/sirm/basic-session.sh

# Basic session with custom case ID
SIRM_CASE_ID="CASE-2026-Q1-AUDIT" ./examples/sirm/basic-session.sh

# IR session with case tracking
SIRM_CASE_ID="CASE-2026-042" \
SIRM_CLASSIFICATION="critical" \
  ./examples/sirm/incident-response-session.sh
```

## Session Output

Both examples produce a session directory under `sessions/<case-id>/` containing:

```
sessions/CASE-2026-042/
├── context.json       # Bootstrap context snapshot
├── evidence/          # Numbered evidence artifacts with SHA-256 hashes
│   ├── manifest.json  # Evidence registry
│   ├── 001-*.txt      # Tool outputs
│   └── ...
├── timeline.jsonl     # Append-only classified event log
├── findings.json      # Structured findings
├── report.md          # Generated report (exec summary → findings → recommendations)
└── seal.json          # Tamper-evident seal (after sealing)
```

## Related Documentation

- [SIRM Framework](../../docs/19-sirm-framework.md) — architecture, state machine, evidence model
- [SIRM Session Protocol](../../docs/20-sirm-session-protocol.md) — operational runbook, checklists, court-readiness
