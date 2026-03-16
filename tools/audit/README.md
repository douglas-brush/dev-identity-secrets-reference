# Audit Tools

Security audit and compliance tooling for identity, credential, and certificate lifecycle management.

## Tools

### `cert_inventory.sh`

Comprehensive certificate scanner and inventory reporter. Discovers X.509 certificates across filesystem, Vault PKI, and Kubernetes, then analyzes each for expiry, key strength, and SANs.

**Sources scanned:**
- Filesystem: `.pem`, `.crt`, `.cert`, `.p12`, `.pfx` files
- Vault PKI mounts (with `--vault`): issued certs, CA chain, CRL status
- Kubernetes (with `--k8s`): TLS secrets, cert-manager Certificate resources

**Flags raised:**
- `EXPIRED` — certificate past its `notAfter` date
- `EXPIRING_SOON` — certificate expires within threshold (default 30 days)
- `WEAK_KEY` — RSA < 2048 bits or EC < 256 bits

```bash
# Scan repo root (default)
tools/audit/cert_inventory.sh

# Scan /etc/ssl with 60-day window, JSON output
tools/audit/cert_inventory.sh --path /etc/ssl --threshold 60 --json

# Full scan: filesystem + Vault + Kubernetes
tools/audit/cert_inventory.sh --vault --k8s --verbose

# Plain text for piping
tools/audit/cert_inventory.sh --no-color | tee report.txt
```

**Options:** `--path`, `--vault`, `--k8s`, `--json`, `--threshold <days>`, `--verbose`, `--no-color`, `--help`

**Exit codes:** `0` healthy, `1` issues found, `2` usage error

---

### `cert_monitor.sh`

Lightweight monitoring wrapper around `cert_inventory.sh`. Designed for cron, systemd timers, or CI pipelines. Compares against a previous baseline to detect certificate additions, removals, and status changes.

**Features:**
- Baseline diffing: new certs, removed certs, status transitions
- Webhook alerting (POST JSON payload)
- Email alerting via sendmail
- CI mode with GitHub Actions annotations and outputs
- Saves each run as `logs/cert-inventory-latest.json` for future baselines

```bash
# Basic monitoring run
tools/audit/cert_monitor.sh

# Compare against previous baseline
tools/audit/cert_monitor.sh --baseline logs/cert-inventory-latest.json

# CI gate — exits non-zero on issues
tools/audit/cert_monitor.sh --ci

# Alert to Slack webhook, suppress OK output
tools/audit/cert_monitor.sh --alert-only --webhook https://hooks.slack.com/...

# Pass extra args to cert_inventory.sh
tools/audit/cert_monitor.sh --ci -- --path /etc/ssl --vault
```

**Options:** `--baseline <path>`, `--webhook <url>`, `--email <addr>`, `--alert-only`, `--ci`, `--threshold <days>`, `--help`

**Exit codes:** `0` healthy, `1` issues found, `2` usage error

---

### `identity_inventory.sh`

Non-human identity inventory across Kubernetes, Vault, GitHub, AWS, Azure, and GCP. Enumerates service accounts, auth methods, policies, deploy keys, and cloud IAM roles. Flags high-risk configurations (default SA usage, wildcard Vault policies, read-write deploy keys).

```bash
tools/audit/identity_inventory.sh              # Text table
tools/audit/identity_inventory.sh --json       # JSON for automation
tools/audit/identity_inventory.sh --namespace prod --verbose
```

---

### `credential_age_report.sh`

Credential age audit and compliance reporter. Checks age of secrets in Vault KV, Kubernetes secrets, and SOPS-encrypted files against a configurable maximum age policy.

```bash
tools/audit/credential_age_report.sh                         # Default 90-day policy
tools/audit/credential_age_report.sh --max-age 30 --k8s-only # 30-day, K8s only
tools/audit/credential_age_report.sh --format json            # JSON for CI
tools/audit/credential_age_report.sh --format csv > report.csv
```

## CI Integration

The `cert-monitor.yml` workflow runs weekly (Monday 08:00 UTC) and on PRs that modify certificate files. It:

1. Scans all certificates in the repository
2. Posts a summary comment on PRs with cert changes
3. Creates/updates a GitHub issue labeled `cert-monitor` on scheduled runs when issues are found
4. Uploads the inventory JSON as a build artifact (90-day retention)
5. Fails the workflow if expired, expiring, or weak certificates are detected

## Environment Variables

| Variable | Used by | Purpose |
|----------|---------|---------|
| `VAULT_ADDR` | cert_inventory, identity_inventory, credential_age_report | Vault server URL |
| `VAULT_TOKEN` | cert_inventory, identity_inventory, credential_age_report | Vault auth token |
| `KUBECONFIG` | cert_inventory, identity_inventory, credential_age_report | Kubernetes config |
| `GITHUB_TOKEN` | identity_inventory | GitHub API access |
| `CREDENTIAL_MAX_AGE` | credential_age_report | Override default max age |

## Log Files

All tools write timestamped logs to `logs/`:
- `logs/cert-inventory-<timestamp>.log`
- `logs/cert-monitor-<timestamp>.log`
- `logs/cert-inventory-latest.json` (latest monitor run, usable as baseline)
