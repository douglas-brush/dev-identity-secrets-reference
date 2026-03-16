# Compliance Automation

This guide covers the automated compliance tooling in this reference architecture: evidence collection, control matrix checking, audit preparation workflows, and integration with GRC platforms.

---

## 1. Evidence Collection

### Overview

`tools/compliance/generate_evidence.sh` automates the collection of audit evidence by running diagnostic tools, capturing their output, and packaging results into timestamped directories with SHA-256 integrity manifests.

### Supported Frameworks

| Framework | Flag | Control Set |
|-----------|------|-------------|
| SOC 2 Type II | `--framework soc2` | CC5.2, CC6.x, CC7.x, CC8.1 |
| PCI DSS 4.0 | `--framework pci` | Req 3, 6, 8, 11 |
| NIST CSF 2.0 | `--framework nist-csf` | GV, ID, PR, DE, RS, RC functions |
| ISO 27001:2022 | `--framework iso27001` | Annex A controls (A.5–A.8) |
| HIPAA | `--framework hipaa` | 164.308, 164.312, 164.316 safeguards |

### Evidence Artifacts

Each evidence package contains:

| Artifact | Source Tool | What It Proves |
|----------|-------------|----------------|
| `secrets-doctor.txt` | `tools/secrets-doctor/doctor.sh` | Infrastructure health, auth methods, policy status |
| `cert-inventory.txt` | Vault PKI + kubectl + local scan | Certificate lifecycle management, expiry tracking |
| `credential-age.txt` | `tools/audit/credential_age_report.sh` | Rotation compliance, credential freshness |
| `scan-results.txt` | `tools/scanning/scan_repo.sh` | No plaintext secrets, scanning enforcement |
| `policy-inventory/` | Vault HCL + SOPS config + docs | Policy documentation, access control definitions |
| `control-matrix.txt` | `tools/compliance/control_matrix.sh` | Automated control verification results |
| `index.json` | SHA-256 manifest | Integrity verification, chain of custody |

### Control Mapping

Every artifact in `index.json` includes a `control_mappings` field that ties it to specific framework control IDs. This mapping enables auditors to trace evidence directly to the control it satisfies.

Example manifest entry:
```json
{
  "path": "secrets-doctor.txt",
  "sha256": "a1b2c3...",
  "size_bytes": 4521,
  "collected_at": "2024-01-15T10:30:00Z",
  "control_mappings": {
    "soc2": "CC6.1,CC6.8,CC8.1"
  }
}
```

### Usage

```bash
# Collect SOC 2 evidence
tools/compliance/generate_evidence.sh --framework soc2

# Collect all frameworks
tools/compliance/generate_evidence.sh --framework all

# Dry run to preview what would be collected
tools/compliance/generate_evidence.sh --framework pci --dry-run --verbose

# Custom output directory
tools/compliance/generate_evidence.sh --framework iso27001 --output-dir /secure/audit/2024-q1
```

### Output Structure

```
evidence/soc2-20240115/
├── index.json              # Manifest with SHA-256 hashes + control mappings
├── secrets-doctor.txt      # Infrastructure diagnostic
├── cert-inventory.txt      # Certificate inventory
├── credential-age.txt      # Credential age report
├── scan-results.txt        # Secret scan results
├── control-matrix.txt      # Automated control checks
└── policy-inventory/
    ├── developer-read.hcl  # Vault policies
    ├── ci-issuer.hcl
    ├── admin-emergency.hcl
    ├── sops-config.yaml    # SOPS configuration
    └── compliance-mapping.md
```

---

## 2. Control Matrix

### Overview

`tools/compliance/control_matrix.sh` performs automated verification of compliance controls by inspecting repository structure, Vault configurations, policy files, and tooling availability. Each control receives a status:

| Status | Meaning |
|--------|---------|
| **PASS** | Automated check confirmed the control is implemented |
| **FAIL** | Automated check detected a gap |
| **MANUAL** | Control requires human verification (organizational process) |
| **NOT_APPLICABLE** | Control is outside the scope of secrets management |

### Usage

```bash
# Check all frameworks
tools/compliance/control_matrix.sh

# Single framework
tools/compliance/control_matrix.sh --framework soc2

# JSON output for programmatic consumption
tools/compliance/control_matrix.sh --framework pci --json

# Verbose mode
tools/compliance/control_matrix.sh --framework nist-csf --verbose
```

### What Gets Checked

The control matrix verifies the presence and configuration of:

- **Auth methods**: OIDC, Kubernetes auth, JWT/GitHub Actions, AppRole
- **Vault policies**: Existence, scoping, deny rules, wildcard avoidance
- **Dynamic credentials**: Database roles, PKI roles, SSH CA
- **Encryption**: SOPS configuration, transit keys, TLS enforcement
- **Audit logging**: Vault audit backend configuration
- **Scanning**: Pre-commit hooks, repo scanner, plaintext detection
- **Secret delivery**: ExternalSecret, SecretProviderClass, Vault Agent
- **Incident response**: Runbooks, rotation tooling, ceremony procedures
- **Documentation**: Threat model, controls, compliance mapping

### Interpreting Results

**PASS controls** require no immediate action but should be re-validated during audits.

**FAIL controls** indicate either:
1. A missing implementation — the control needs to be built
2. A configuration gap — the control exists but is incomplete
3. A detection limitation — the automated check may need tuning for your environment

**MANUAL controls** represent organizational processes that cannot be verified by inspecting code:
- MFA enforcement in the IdP
- Periodic access review cadence
- Security awareness training
- SIEM integration and alert response

Run the control matrix before every audit cycle to identify gaps early.

---

## 3. Audit Preparation Workflow

### Quarterly Audit Prep

```bash
# 1. Run the control matrix to identify gaps
tools/compliance/control_matrix.sh --framework soc2

# 2. Fix any FAIL items

# 3. Collect evidence
tools/compliance/generate_evidence.sh --framework soc2

# 4. Verify evidence integrity
cd evidence/soc2-$(date -u +%Y%m%d)
cat index.json | jq -r '.artifacts[] | "\(.sha256)  \(.path)"' | while read hash path; do
  computed=$(shasum -a 256 "$path" | awk '{print $1}')
  if [[ "$hash" == "$computed" ]]; then
    echo "VERIFIED: $path"
  else
    echo "MISMATCH: $path (expected $hash, got $computed)"
  fi
done

# 5. Archive the evidence package
tar czf soc2-evidence-$(date -u +%Y%m%d).tar.gz evidence/soc2-$(date -u +%Y%m%d)/
```

### Pre-Audit Checklist

1. Run `control_matrix.sh` for target framework — resolve all FAIL items
2. Collect evidence with `generate_evidence.sh`
3. Verify SHA-256 hashes in `index.json`
4. Document MANUAL control status with organizational evidence
5. Review credential age report for any overdue rotations
6. Confirm cert-manager certificates are not approaching expiry
7. Archive evidence package with timestamp

### Continuous Compliance

For continuous compliance monitoring, schedule evidence collection:

```bash
# Cron: weekly evidence collection for SOC 2
0 2 * * 1 /path/to/tools/compliance/generate_evidence.sh --framework soc2

# Cron: daily control matrix check
0 6 * * * /path/to/tools/compliance/control_matrix.sh --framework all --json > /var/log/compliance/control-matrix-$(date +\%Y\%m\%d).json
```

Integrate control matrix JSON output with monitoring/alerting to detect drift:

```bash
# Alert on new failures
FAIL_COUNT=$(tools/compliance/control_matrix.sh --framework all --json 2>/dev/null | jq '.summary.fail')
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "ALERT: ${FAIL_COUNT} compliance controls failed" | notify
fi
```

---

## 4. GRC Tool Integration

### Export Formats

The control matrix supports JSON output (`--json`) for integration with GRC platforms. The JSON schema:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "framework": "soc2",
  "summary": {
    "total": 12,
    "pass": 9,
    "fail": 1,
    "manual": 2,
    "not_applicable": 0
  },
  "controls": [
    {
      "framework": "soc2",
      "control_id": "CC6.1",
      "title": "Logical and physical access controls",
      "status": "PASS",
      "detail": "Vault auth methods configured"
    }
  ]
}
```

### Common GRC Integrations

**ServiceNow GRC**: Import control matrix JSON via the GRC API. Map `control_id` to ServiceNow control records. Use `status` to update control test results.

**Vanta / Drata / Secureframe**: Upload evidence artifacts directly. The `index.json` manifest provides the artifact-to-control mapping that these platforms require. Schedule periodic evidence collection to maintain continuous monitoring.

**Archer / OneTrust**: Export control matrix to CSV for bulk import:

```bash
tools/compliance/control_matrix.sh --framework all --json | \
  jq -r '.controls[] | [.framework, .control_id, .title, .status, .detail] | @csv' \
  > control-matrix.csv
```

**Custom dashboards**: Parse JSON output into Grafana, Datadog, or similar. Track pass/fail trends over time to demonstrate continuous compliance.

### Evidence Chain of Custody

The `index.json` manifest in each evidence package provides:

- SHA-256 hash of every artifact at collection time
- Timestamp of collection
- Git commit hash of the repository at collection time
- Framework-to-control mapping for each artifact

To verify evidence integrity after collection:

```bash
jq -r '.artifacts[] | "\(.sha256)  \(.path)"' evidence/soc2-20240115/index.json | \
  sha256sum -c
```

---

## 5. Extending the Framework

### Adding a New Framework

1. Add control mappings to `generate_evidence.sh` (declare a new associative array)
2. Add automated checks to `control_matrix.sh` (new `check_<framework>()` function)
3. Update the compliance mapping in `docs/14-compliance-mapping.md`
4. Add the framework to both scripts' `--help` output and validation

### Adding a New Evidence Artifact

1. Create the collection function in `generate_evidence.sh`
2. Add the artifact key to all framework mapping arrays
3. Update the manifest generation to include the new artifact
4. Document the artifact in this guide

### Custom Control Checks

The `control_matrix.sh` check helpers make it straightforward to add checks:

```bash
# File existence check
file_exists "path/relative/to/repo/root"

# Content match check
file_contains "path/to/file" "grep-pattern"

# Directory has files check
dir_has_files "path/to/directory"

# YAML content search across repo
yaml_contains "pattern-to-find"
```

---

## Related Documentation

- [Compliance Mapping](14-compliance-mapping.md) — Full framework-to-control mapping
- [Controls and Guardrails](06-controls-and-guardrails.md) — Architecture control objectives C1–C6
- [Threat Model](07-threat-model.md) — Threats T1–T7 and mitigations
- [Runbooks](09-runbooks.md) — Operational procedures including incident response
- [Key Ceremony Guide](18-key-ceremony-guide.md) — Ceremony procedures for key management
