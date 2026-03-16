# Compliance Examples

Example scripts demonstrating compliance automation workflows for secrets management. These scripts use the tooling in `tools/compliance/` and map to the control frameworks documented in `docs/14-compliance-mapping.md`.

## Scripts

### `soc2-evidence-collection.sh`

End-to-end SOC 2 Type II audit preparation workflow:

1. Runs the control matrix to identify gaps before collection
2. Collects evidence artifacts mapped to Trust Service Criteria (CC5.2, CC6.x, CC7.x, CC8.1)
3. Verifies SHA-256 integrity of all collected artifacts
4. Generates an `AUDIT-SUMMARY.md` with criteria-to-evidence mapping

```bash
# Default collection
./soc2-evidence-collection.sh

# Custom output directory
./soc2-evidence-collection.sh --output-dir /secure/audit/2024-q4

# Skip the control matrix pre-check
./soc2-evidence-collection.sh --skip-matrix
```

Output: `evidence/soc2-<date>/` containing all artifacts, manifest, and audit summary.

### `pci-dss-validation.sh`

PCI DSS 4.0 requirement validation focused on secrets management scope:

- **Requirement 3** (Protect Stored Data): SOPS encryption, Vault transit keys, key lifecycle management
- **Requirement 6** (Secure Development): Pre-commit scanning, repo scanning, entropy checks
- **Requirement 8** (Identify and Authenticate): OIDC auth, dynamic credentials, service account management

```bash
# Run validation with verbose output
./pci-dss-validation.sh --verbose

# JSON output for CI integration
./pci-dss-validation.sh --json

# Exit code: 0 = all automated checks pass, 1 = failures detected
```

## Prerequisites

These examples rely on the core compliance tooling:

| Tool | Path | Purpose |
|------|------|---------|
| Evidence collector | `tools/compliance/generate_evidence.sh` | Collects and packages audit evidence |
| Control matrix | `tools/compliance/control_matrix.sh` | Automated control status checks |
| Secrets doctor | `tools/secrets-doctor/doctor.sh` | Infrastructure health diagnostic |
| Credential age | `tools/audit/credential_age_report.sh` | Credential freshness audit |
| Repo scanner | `tools/scanning/scan_repo.sh` | Secret scanning orchestrator |

Optional runtime dependencies (checks degrade gracefully if unavailable):
- `vault` CLI with `VAULT_ADDR` set
- `kubectl` with cluster access
- `python3` for JSON parsing
- `jq` for manifest inspection

## Extending

To add a new compliance example:

1. Create a script following the `set -euo pipefail` + color output conventions
2. Use `tools/compliance/control_matrix.sh --framework <fw> --json` for automated checks
3. Use `tools/compliance/generate_evidence.sh --framework <fw>` for evidence collection
4. Map checks to specific control IDs from `docs/14-compliance-mapping.md`

## Related

- [Compliance Automation Guide](../../docs/21-compliance-automation.md) — Full documentation
- [Compliance Mapping](../../docs/14-compliance-mapping.md) — Framework-to-control mapping
- [Controls and Guardrails](../../docs/06-controls-and-guardrails.md) — Architecture control objectives
- [Compliance Tests](../../tests/compliance/) — CI-oriented control validation
