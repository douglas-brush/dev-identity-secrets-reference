# Secret Lifecycle Metrics & Reporting

Unified metrics collection, risk scoring, and reporting across all secrets lifecycle tools.

## Quick Start

```bash
# Collect metrics from all tools
tools/metrics/collect-metrics.sh

# Calculate risk score
tools/metrics/risk-scorer.sh --input logs/metrics/metrics-latest.json

# Generate a report
tools/metrics/generate-report.sh --input logs/metrics/metrics-latest.json --format terminal

# Generate markdown report for sharing
tools/metrics/generate-report.sh --input logs/metrics/metrics-latest.json --format markdown > report.md

# Trend comparison against previous run
tools/metrics/collect-metrics.sh --baseline logs/metrics/metrics-previous.json
```

## Tools

### `collect-metrics.sh`

Runs all secrets lifecycle tools in JSON mode and aggregates results into a single metrics document.

**Data sources collected:**

| Section | Tool | What it measures |
|---------|------|------------------|
| `secrets_doctor` | `tools/secrets-doctor/doctor.sh` | Infrastructure health: deps, SOPS, git, Vault, K8s, certs |
| `cert_inventory` | `tools/audit/cert_inventory.sh` | Certificate status, expiry, key strength |
| `credential_age` | `tools/audit/credential_age_report.sh` | Credential rotation compliance |
| `control_matrix` | `tools/compliance/control_matrix.sh` | Compliance framework control pass rates |
| `scanning` | `tools/scanning/scan_repo.sh` | Secret scanning findings |

**Options:**

| Flag | Description |
|------|-------------|
| `--output <file>` | Write metrics JSON to file (default: `logs/metrics/metrics-<timestamp>.json`) |
| `--baseline <file>` | Previous metrics JSON for trend comparison |
| `--verbose` | Show detailed progress |
| `--json` | Output only JSON to stdout |

### `risk-scorer.sh`

Calculates a composite risk score (0-100) from metrics JSON using weighted category scoring.

**Options:**

| Flag | Description |
|------|-------------|
| `--input <file>` | Metrics JSON from `collect-metrics.sh` (required) |
| `--weights-file <file>` | Custom weights JSON |
| `--json` | Output as JSON |
| `--verbose` | Show per-check scoring detail |

### `generate-report.sh`

Generates a human-readable report from metrics JSON with executive summary, section breakdowns, trend indicators, and prioritized action items.

**Options:**

| Flag | Description |
|------|-------------|
| `--input <file>` | Metrics JSON (required) |
| `--format terminal\|markdown\|json` | Output format (default: terminal) |
| `--verbose` | Include per-check details |

## Risk Scoring

### Score Range

| Score | Rating | Meaning |
|-------|--------|---------|
| 90-100 | EXCELLENT | Minimal risk, all controls healthy |
| 70-89 | GOOD | Minor issues to address |
| 50-69 | FAIR | Significant gaps exist |
| 30-49 | POOR | Urgent remediation needed |
| 0-29 | CRITICAL | Immediate action required |

### Category Weights

The composite score is a weighted average of five category scores:

| Category | Default Weight | Source | Scoring Logic |
|----------|---------------|--------|---------------|
| `secrets_hygiene` | 0.25 | secrets-doctor | Pass=100%, Warn=50%, Fail=0% per check |
| `cert_health` | 0.25 | cert_inventory | OK=100%, Expiring=40%, Weak=20%, Expired=0% |
| `credential_age` | 0.20 | credential_age_report | OK=100%, Warn=50%, Fail=0% per credential |
| `policy_compliance` | 0.20 | control_matrix | Pass=100%, Manual=60%, Fail=0% per control |
| `scanning` | 0.10 | scan_repo | 0 findings=100%, 1-2=70%, 3-5=40%, 6+=diminishing |

### Custom Weights

Create a JSON file with your preferred weights (values are normalized automatically):

```json
{
  "secrets_hygiene": 0.30,
  "cert_health": 0.30,
  "credential_age": 0.15,
  "policy_compliance": 0.15,
  "scanning": 0.10
}
```

```bash
risk-scorer.sh --input metrics.json --weights-file my-weights.json
```

## Trend Indicators

When `--baseline` is provided to `collect-metrics.sh`, each section includes trend data comparing current vs. previous values.

| Symbol | Meaning |
|--------|---------|
| `↑` / `:arrow_up:` | Improving (metric moving in the right direction) |
| `↓` / `:arrow_down:` | Degrading (metric getting worse) |
| `→` / `:arrow_right:` | Stable (no change) |
| `•` / `:new:` | New (no baseline for comparison) |

## Report Sections

1. **Executive Summary** — composite risk score with progress bar and rating
2. **Secrets Hygiene** — secrets-doctor pass/warn/fail counts
3. **Certificate Health** — OK/expiring/weak/expired certificate counts
4. **Credential Age** — compliant/warning/non-compliant credential counts
5. **Policy Compliance** — control matrix pass/fail/manual counts
6. **Secret Scanning** — scanners run and total findings
7. **Trends** — comparison table (when baseline provided)
8. **Top 5 Action Items** — prioritized by risk impact (CRITICAL > HIGH > MEDIUM)

## CI/CD Integration

The `weekly-report.yml` workflow runs every Monday at 09:00 UTC:

1. Collects metrics from all tools
2. Calculates risk score
3. Generates a markdown report
4. Posts it as a GitHub issue (closes previous weekly-report issue)
5. Uploads metrics as a build artifact for future trend comparison
6. Fails the workflow if risk score is below 30 (CRITICAL)

### Manual Trigger

Trigger from GitHub Actions UI with optional baseline artifact name for trend comparison.

## Output Locations

| File | Description |
|------|-------------|
| `logs/metrics/metrics-<timestamp>.json` | Raw metrics collection |
| `logs/metrics/metrics-latest.json` | Symlink to most recent collection |
| `logs/metrics/risk-score.json` | Risk score breakdown (CI) |
| `logs/metrics/report.md` | Markdown report (CI) |
