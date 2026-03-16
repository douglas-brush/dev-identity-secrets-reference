#!/usr/bin/env bash
set -euo pipefail

# soc2-evidence-collection.sh — Example: SOC 2 Type II evidence collection workflow
# Demonstrates end-to-end audit prep for SOC 2 Trust Service Criteria.
#
# This script:
#   1. Runs the control matrix to identify gaps
#   2. Collects evidence artifacts mapped to SOC 2 criteria
#   3. Verifies evidence integrity via SHA-256
#   4. Produces an audit-ready summary
#
# Usage: soc2-evidence-collection.sh [--output-dir <dir>] [--skip-matrix]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DATE_STAMP="$(date -u +%Y%m%d)"

# ── Defaults ──────────────────────────────────────────────────────────────

OUTPUT_DIR="${REPO_ROOT}/evidence/soc2-${DATE_STAMP}"
SKIP_MATRIX=""

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'soc2-evidence-collection.sh') — SOC 2 Type II Evidence Collection Example

$(_bold 'USAGE')
  soc2-evidence-collection.sh [OPTIONS]

$(_bold 'OPTIONS')
  --output-dir <dir>   Override evidence output directory
  --skip-matrix        Skip control matrix pre-check
  --help               Show this help message

$(_bold 'SOC 2 CRITERIA COVERED')
  CC5.2   Control activities deployed
  CC6.1   Logical and physical access controls
  CC6.2   System credentials / passwords
  CC6.3   Role-based access
  CC6.6   System boundaries
  CC6.7   Restrict data movement
  CC6.8   Prevent unauthorized access
  CC7.1   Detect and monitor threats
  CC7.2   Monitor for anomalies
  CC7.3   Evaluate detected events
  CC7.4   Respond to identified events
  CC8.1   Control environment changes

$(_bold 'WORKFLOW')
  1. Run control matrix pre-check (identifies gaps before collection)
  2. Collect evidence artifacts via generate_evidence.sh
  3. Verify SHA-256 integrity of all artifacts
  4. Generate audit-ready summary with criteria mapping
  5. Output package location for auditor delivery
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
    --skip-matrix)  SKIP_MATRIX="true"; shift ;;
    --help|-h)      usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# ── Phase 1: Control Matrix Pre-Check ────────────────────────────────────

echo ""
printf '%s\n' "$(_bold '========== SOC 2 Type II Evidence Collection ==========')"
printf '  %s\n' "$(_dim "Started: ${TIMESTAMP}")"
printf '  %s\n' "$(_dim "Output:  ${OUTPUT_DIR}")"
echo ""

if [[ -z "$SKIP_MATRIX" ]]; then
  printf '%s\n' "$(_bold '--- Phase 1: Control Matrix Pre-Check ---')"
  echo ""

  if [[ -x "${REPO_ROOT}/tools/compliance/control_matrix.sh" ]]; then
    # Run matrix and capture results
    matrix_output=$(bash "${REPO_ROOT}/tools/compliance/control_matrix.sh" --framework soc2 --json 2>/dev/null) || true

    if [[ -n "$matrix_output" ]]; then
      fail_count=$(echo "$matrix_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['summary']['fail'])" 2>/dev/null || echo "unknown")
      pass_count=$(echo "$matrix_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['summary']['pass'])" 2>/dev/null || echo "unknown")
      manual_count=$(echo "$matrix_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['summary']['manual'])" 2>/dev/null || echo "unknown")

      printf '  %s %s\n' "$(_green 'Pass:')" "$pass_count"
      printf '  %s %s\n' "$(_red 'Fail:')" "$fail_count"
      printf '  %s %s\n' "$(_yellow 'Manual:')" "$manual_count"

      if [[ "$fail_count" != "0" && "$fail_count" != "unknown" ]]; then
        echo ""
        printf '  %s\n' "$(_yellow 'WARNING: Some controls are failing. Evidence will still be collected,')"
        printf '  %s\n' "$(_yellow 'but auditors will need remediation plans for failed controls.')"
      fi
    fi
  else
    printf '  %s\n' "$(_yellow 'control_matrix.sh not found — skipping pre-check')"
  fi
  echo ""
fi

# ── Phase 2: Evidence Collection ──────────────────────────────────────────

printf '%s\n' "$(_bold '--- Phase 2: Evidence Collection ---')"
echo ""

if [[ -x "${REPO_ROOT}/tools/compliance/generate_evidence.sh" ]]; then
  bash "${REPO_ROOT}/tools/compliance/generate_evidence.sh" \
    --framework soc2 \
    --output-dir "$OUTPUT_DIR" \
    --verbose
else
  printf '  %s\n' "$(_red 'ERROR: generate_evidence.sh not found')"
  printf '  %s\n' "Expected at: tools/compliance/generate_evidence.sh"
  exit 1
fi

# ── Phase 3: Integrity Verification ──────────────────────────────────────

echo ""
printf '%s\n' "$(_bold '--- Phase 3: Integrity Verification ---')"
echo ""

if [[ -f "${OUTPUT_DIR}/index.json" ]]; then
  verify_count=0
  verify_fail=0

  # Use python3 for JSON parsing (more portable than jq for this use case)
  while IFS='|' read -r hash path; do
    [[ -z "$hash" || -z "$path" ]] && continue
    full_path="${OUTPUT_DIR}/${path}"
    if [[ -f "$full_path" ]]; then
      computed=$(shasum -a 256 "$full_path" 2>/dev/null | awk '{print $1}' || sha256sum "$full_path" 2>/dev/null | awk '{print $1}')
      if [[ "$hash" == "$computed" ]]; then
        printf '  %s %s\n' "$(_green 'VERIFIED')" "$path"
        verify_count=$((verify_count + 1))
      else
        printf '  %s %s (hash mismatch)\n' "$(_red 'FAILED ')" "$path"
        verify_fail=$((verify_fail + 1))
      fi
    else
      printf '  %s %s (file not found)\n' "$(_yellow 'MISSING')" "$path"
      verify_fail=$((verify_fail + 1))
    fi
  done < <(python3 -c "
import json, sys
with open('${OUTPUT_DIR}/index.json') as f:
    data = json.load(f)
for a in data.get('artifacts', []):
    print(f\"{a['sha256']}|{a['path']}\")
" 2>/dev/null || true)

  echo ""
  if [[ $verify_fail -eq 0 && $verify_count -gt 0 ]]; then
    printf '  %s\n' "$(_green "All ${verify_count} artifacts verified")"
  elif [[ $verify_count -eq 0 ]]; then
    printf '  %s\n' "$(_yellow 'No artifacts to verify (check index.json)')"
  else
    printf '  %s\n' "$(_red "${verify_fail} artifact(s) failed verification")"
  fi
else
  printf '  %s\n' "$(_yellow 'No index.json found — skipping verification')"
fi

# ── Phase 4: Audit Summary ───────────────────────────────────────────────

echo ""
printf '%s\n' "$(_bold '--- Phase 4: Audit Summary ---')"
echo ""

summary_file="${OUTPUT_DIR}/AUDIT-SUMMARY.md"
cat > "$summary_file" <<EOF
# SOC 2 Type II Evidence Package

## Collection Details

| Field | Value |
|-------|-------|
| Framework | SOC 2 Type II |
| Collected | ${TIMESTAMP} |
| Repository | $(cd "$REPO_ROOT" && basename "$(pwd)") |
| Git Commit | $(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'N/A') |
| Git Branch | $(cd "$REPO_ROOT" && git branch --show-current 2>/dev/null || echo 'N/A') |
| Collector | generate_evidence.sh + soc2-evidence-collection.sh |

## Trust Service Criteria Coverage

| Criteria | Title | Evidence Artifact |
|----------|-------|-------------------|
| CC5.2 | Control activities deployed | policy-inventory/, control-matrix.txt |
| CC6.1 | Logical and physical access controls | secrets-doctor.txt, policy-inventory/ |
| CC6.2 | System credentials / passwords | credential-age.txt, secrets-doctor.txt |
| CC6.3 | Role-based access | policy-inventory/, control-matrix.txt |
| CC6.6 | System boundaries | control-matrix.txt (MANUAL) |
| CC6.7 | Restrict data movement | policy-inventory/sops-config.yaml |
| CC6.8 | Prevent unauthorized access | scan-results.txt, secrets-doctor.txt |
| CC7.1 | Detect and monitor threats | secrets-doctor.txt, cert-inventory.txt |
| CC7.2 | Monitor for anomalies | control-matrix.txt (MANUAL) |
| CC7.3 | Evaluate detected events | Incident runbooks in policy-inventory/ |
| CC7.4 | Respond to identified events | Rotation tooling evidence in control-matrix.txt |
| CC8.1 | Control environment changes | policy-inventory/sops-config.yaml, scan-results.txt |

## Artifacts

See \`index.json\` for SHA-256 hashes and per-artifact control mappings.

## Manual Review Items

The following criteria require organizational evidence beyond automated collection:

- **CC6.6**: Namespace isolation and environment separation — verify in cluster configuration
- **CC7.2**: SIEM integration and anomaly alerting — verify in monitoring platform
- **Identity provider MFA**: Verify phishing-resistant MFA enforcement in IdP admin console
- **Access review cadence**: Document last periodic access review date

## Integrity

All artifacts are hashed with SHA-256 at collection time. Verify with:

\`\`\`bash
# Using the manifest
python3 -c "
import json, hashlib, pathlib
data = json.load(open('index.json'))
for a in data['artifacts']:
    h = hashlib.sha256(pathlib.Path(a['path']).read_bytes()).hexdigest()
    status = 'OK' if h == a['sha256'] else 'MISMATCH'
    print(f'{status}: {a[\"path\"]}')"
\`\`\`
EOF

printf '  %s\n' "$(_green "Audit summary written: ${summary_file}")"

# ── Done ──────────────────────────────────────────────────────────────────

echo ""
printf '%s\n' "$(_bold '========== Collection Complete ==========')"
printf '  %s %s\n' "$(_dim 'Package:')" "$OUTPUT_DIR"
printf '  %s %s\n' "$(_dim 'Summary:')" "$summary_file"
printf '  %s %s\n' "$(_dim 'Manifest:')" "${OUTPUT_DIR}/index.json"
echo ""
printf '  %s\n' "Deliver the evidence/ directory to your auditor."
printf '  %s\n' "Run 'shasum -a 256 -c' against index.json hashes to prove integrity."
echo ""
