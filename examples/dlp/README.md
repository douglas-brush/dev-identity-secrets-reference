# DLP Integration for Secret Scanning

Data Loss Prevention (DLP) integration patterns for routing secret scan findings to monitoring, alerting, and compliance systems.

## Integration Architecture

```
 pre-commit hook ──┐
                    ├──> scan_repo.sh ──> JSON report ──┬──> Slack webhook
 CI pipeline ──────┘                                    ├──> PagerDuty event
                                                        ├──> Splunk HEC
                                                        ├──> GitHub Security (SARIF)
                                                        └──> S3/GCS archive
```

## SIEM Integration (Splunk)

Pipe JSON scan output to Splunk HTTP Event Collector:

```bash
# Generate JSON report and send to Splunk HEC
./tools/scanning/scan_repo.sh --json | \
  curl -s -k "https://splunk.internal:8088/services/collector/event" \
    -H "Authorization: Splunk ${HEC_TOKEN}" \
    -d @- --data-binary '{"sourcetype":"secret_scan","event":'$(cat)'}'
```

For scheduled scanning, use a cron job or CI schedule trigger that archives results:

```bash
# In CI (scheduled)
./tools/scanning/scan_repo.sh --json > "scan-$(date +%Y%m%d).json"
# Forward to SIEM via your log shipper (Fluentd, Vector, Filebeat)
```

## Alerting: Slack Webhook

Post findings to a Slack channel when secrets are detected:

```bash
SCAN_OUTPUT=$(./tools/scanning/scan_repo.sh --json 2>/dev/null)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  FINDING_COUNT=$(echo "$SCAN_OUTPUT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(sum(s.get('finding_count',0) for s in d.get('scanners',[])))")

  curl -X POST "${SLACK_WEBHOOK_URL}" \
    -H 'Content-type: application/json' \
    -d "{\"text\":\"Secret scan alert: ${FINDING_COUNT} finding(s) in $(git remote get-url origin) @ $(git rev-parse --short HEAD)\"}"
fi
```

## Alerting: PagerDuty

Trigger a PagerDuty incident for critical findings:

```bash
if [ $EXIT_CODE -ne 0 ]; then
  curl -X POST "https://events.pagerduty.com/v2/enqueue" \
    -H 'Content-Type: application/json' \
    -d "{
      \"routing_key\": \"${PD_ROUTING_KEY}\",
      \"event_action\": \"trigger\",
      \"payload\": {
        \"summary\": \"Secret detected in $(basename $(git remote get-url origin))\",
        \"severity\": \"critical\",
        \"source\": \"secret-scanner\",
        \"custom_details\": ${SCAN_OUTPUT}
      }
    }"
fi
```

## GitHub Security Tab (SARIF)

The enhanced CI workflow (`secret-scan-enhanced.yml`) automatically uploads SARIF to the GitHub Security tab. For manual SARIF generation:

```bash
gitleaks detect \
  --config tools/scanning/custom-gitleaks.toml \
  --report-format sarif \
  --report-path results.sarif
```

Upload via the GitHub API:

```bash
gzip -c results.sarif | base64 -w0 > sarif.b64
gh api -X POST "/repos/{owner}/{repo}/code-scanning/sarifs" \
  -f "commit_sha=$(git rev-parse HEAD)" \
  -f "ref=$(git symbolic-ref HEAD)" \
  -f "sarif=@sarif.b64"
```

## Scanning Strategy Comparison

| Dimension | Pre-commit | CI Pipeline | Scheduled |
|-----------|-----------|-------------|-----------|
| **When** | Before every commit | On push/PR | Cron (daily/weekly) |
| **Latency** | Instant feedback | Minutes | Hours |
| **Coverage** | Only staged changes | Full diff or repo | Full repo history |
| **Bypass risk** | `--no-verify` skips | None (enforced) | None |
| **Best for** | Developer feedback | Gate enforcement | Compliance audit |
| **False positives** | High friction | Moderate friction | Low friction |

**Recommended layered approach:**

1. **Pre-commit** -- fast pattern matching + entropy (developer feedback loop)
2. **CI pipeline** -- full gitleaks + SARIF upload (enforcement gate)
3. **Scheduled weekly** -- full repo scan + history scan + SIEM export (compliance)

## Managing a Baseline

When adopting scanning on an existing repo, establish a baseline of known findings to avoid blocking all PRs:

```bash
# Generate baseline (one-time)
gitleaks detect \
  --config tools/scanning/custom-gitleaks.toml \
  --report-path .gitleaks-baseline.json \
  --report-format json

# Commit baseline
git add .gitleaks-baseline.json
git commit -m "chore: add gitleaks baseline for existing findings"

# Future scans compare against baseline
gitleaks detect \
  --config tools/scanning/custom-gitleaks.toml \
  --baseline-path .gitleaks-baseline.json
```

## Managing Exceptions

For known false positives:

1. **`.secretsignore`** -- path-based exclusions for `check_no_plaintext_secrets.sh`
2. **`custom-gitleaks.toml` allowlists** -- regex or path-based exclusions for gitleaks
3. **Inline comments** -- `# gitleaks:allow` on a line suppresses that finding

Review exceptions periodically. Every suppression should have a documented justification.

## Rotating Detected Secrets

When a real secret is detected:

1. **Revoke immediately** -- rotate the credential at the source
2. **Remove from history** -- use `git filter-repo` or BFG Repo Cleaner
3. **Update baseline** -- regenerate `.gitleaks-baseline.json`
4. **Post-incident** -- document in your incident response process
