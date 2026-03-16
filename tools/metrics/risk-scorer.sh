#!/usr/bin/env bash
set -euo pipefail

# risk-scorer.sh — Calculate composite risk score from secrets lifecycle metrics
# Reads a metrics JSON (from collect-metrics.sh), applies weighted scoring across
# categories, and outputs a 0-100 risk score with per-category breakdown.
# Usage: risk-scorer.sh --input <metrics.json> [--weights-file <weights.json>] [--json] [--verbose]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"; export REPO_ROOT
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; export TIMESTAMP

# ── Defaults ──────────────────────────────────────────────────────────────

INPUT_FILE=""
WEIGHTS_FILE=""
JSON_OUTPUT=""
VERBOSE=""

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'risk-scorer.sh') — Secrets lifecycle risk score calculator

$(_bold 'USAGE')
  risk-scorer.sh --input <metrics.json> [OPTIONS]

$(_bold 'OPTIONS')
  --input <file>         Metrics JSON from collect-metrics.sh (required)
  --weights-file <file>  Custom weights JSON (overrides defaults)
  --json                 Output as JSON
  --verbose              Show per-check scoring detail
  --no-color             Disable colored output
  -h, --help             Show this help

$(_bold 'SCORING')
  The risk score is 0-100, where 0 = highest risk, 100 = no risk.

  Default category weights (must sum to 1.0):
    secrets_hygiene   0.25   secrets-doctor pass/fail/warn ratio
    cert_health       0.25   certificate expiry and key strength
    credential_age    0.20   credential rotation compliance
    policy_compliance 0.20   compliance control matrix pass rate
    scanning          0.10   secret scanning results

  Score interpretation:
    90-100  Excellent   — minimal risk
    70-89   Good        — minor issues to address
    50-69   Fair        — significant gaps exist
    30-49   Poor        — urgent remediation needed
    0-29    Critical    — immediate action required

$(_bold 'WEIGHTS FILE FORMAT')
  {
    "secrets_hygiene": 0.25,
    "cert_health": 0.25,
    "credential_age": 0.20,
    "policy_compliance": 0.20,
    "scanning": 0.10
  }

$(_bold 'EXIT CODES')
  0   Score calculated (score >= 50)
  1   Score calculated (score < 50 — high risk)
  2   Usage error or missing input

$(_bold 'EXAMPLES')
  risk-scorer.sh --input logs/metrics/metrics-latest.json
  risk-scorer.sh --input metrics.json --weights-file custom-weights.json --json
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)         usage ;;
    --input)           INPUT_FILE="$2"; shift 2 ;;
    --weights-file)    WEIGHTS_FILE="$2"; shift 2 ;;
    --json)            JSON_OUTPUT=1; shift ;;
    --verbose)         VERBOSE=1; shift ;;
    --no-color)        NO_COLOR=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$INPUT_FILE" ]]; then
  printf 'Error: --input is required\n' >&2
  printf 'Run risk-scorer.sh --help for usage.\n' >&2
  exit 2
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  printf 'Error: input file not found: %s\n' "$INPUT_FILE" >&2
  exit 2
fi

# ── Score calculation via Python ──────────────────────────────────────────

score_output=$(python3 << 'PYTHON_SCORE' - "$INPUT_FILE" "$WEIGHTS_FILE" "$VERBOSE"
import json, sys

input_file = sys.argv[1]
weights_file = sys.argv[2] if sys.argv[2] else None
verbose = sys.argv[3] == "1"

# Load metrics
with open(input_file) as f:
    metrics = json.load(f)

# Default weights
weights = {
    "secrets_hygiene": 0.25,
    "cert_health": 0.25,
    "credential_age": 0.20,
    "policy_compliance": 0.20,
    "scanning": 0.10,
}

# Override with custom weights if provided
if weights_file:
    try:
        with open(weights_file) as f:
            custom = json.load(f)
        for k in weights:
            if k in custom:
                weights[k] = float(custom[k])
    except Exception as e:
        print(json.dumps({"error": f"Failed to load weights: {e}"}))
        sys.exit(2)

# Normalize weights to sum to 1.0
total_w = sum(weights.values())
if total_w > 0:
    weights = {k: v / total_w for k, v in weights.items()}

sections = metrics.get("sections", {})
category_scores = {}
category_details = {}

# ── 1. Secrets Hygiene (from secrets_doctor) ──
doctor = sections.get("secrets_doctor", {})
doc_summary = doctor.get("summary", {})
doc_passed = int(doc_summary.get("passed", 0))
doc_warned = int(doc_summary.get("warnings", 0))
doc_failed = int(doc_summary.get("failed", 0))
doc_total = doc_passed + doc_warned + doc_failed

if doc_total > 0:
    # Pass = 100%, warn = 50%, fail = 0%
    raw = (doc_passed * 100 + doc_warned * 50) / doc_total
    category_scores["secrets_hygiene"] = round(raw)
    category_details["secrets_hygiene"] = {
        "passed": doc_passed,
        "warnings": doc_warned,
        "failed": doc_failed,
        "total_checks": doc_total,
        "raw_score": round(raw),
    }
else:
    category_scores["secrets_hygiene"] = 0
    category_details["secrets_hygiene"] = {"error": "no data", "raw_score": 0}

# ── 2. Certificate Health ──
certs = sections.get("cert_inventory", {})
cert_list = certs.get("certificates", [])
cert_total = len(cert_list)

if cert_total > 0:
    expired = len([c for c in cert_list if c.get("status") == "EXPIRED"])
    expiring = len([c for c in cert_list if c.get("status") == "EXPIRING_SOON"])
    weak = len([c for c in cert_list if c.get("status") == "WEAK_KEY"])
    ok = cert_total - expired - expiring - weak
    # OK = 100%, expiring = 40%, weak = 20%, expired = 0%
    raw = (ok * 100 + expiring * 40 + weak * 20) / cert_total
    category_scores["cert_health"] = round(raw)
    category_details["cert_health"] = {
        "total": cert_total,
        "ok": ok,
        "expiring_soon": expiring,
        "weak_key": weak,
        "expired": expired,
        "raw_score": round(raw),
    }
else:
    # No certs found — not a problem, give full score
    category_scores["cert_health"] = 100
    category_details["cert_health"] = {"total": 0, "note": "no certificates found", "raw_score": 100}

# ── 3. Credential Age ──
creds = sections.get("credential_age", {})
cred_list = creds.get("credentials", [])
cred_total = len(cred_list)

if cred_total > 0:
    cred_ok = len([c for c in cred_list if c.get("status") == "OK"])
    cred_warn = len([c for c in cred_list if c.get("status") == "WARN"])
    cred_fail = len([c for c in cred_list if c.get("status") == "FAIL"])
    raw = (cred_ok * 100 + cred_warn * 50) / cred_total
    category_scores["credential_age"] = round(raw)
    category_details["credential_age"] = {
        "total": cred_total,
        "ok": cred_ok,
        "warning": cred_warn,
        "failed": cred_fail,
        "raw_score": round(raw),
    }
else:
    category_scores["credential_age"] = 100
    category_details["credential_age"] = {"total": 0, "note": "no credentials found", "raw_score": 100}

# ── 4. Policy Compliance (control_matrix) ──
matrix = sections.get("control_matrix", {})
mx_summary = matrix.get("summary", {})
mx_pass = int(mx_summary.get("pass", 0))
mx_fail = int(mx_summary.get("fail", 0))
mx_manual = int(mx_summary.get("manual", 0))
mx_total = mx_pass + mx_fail + mx_manual

if mx_total > 0:
    # Pass = 100%, manual = 60% (partial credit), fail = 0%
    raw = (mx_pass * 100 + mx_manual * 60) / mx_total
    category_scores["policy_compliance"] = round(raw)
    category_details["policy_compliance"] = {
        "pass": mx_pass,
        "fail": mx_fail,
        "manual": mx_manual,
        "total": mx_total,
        "raw_score": round(raw),
    }
else:
    category_scores["policy_compliance"] = 0
    category_details["policy_compliance"] = {"error": "no data", "raw_score": 0}

# ── 5. Scanning ──
scanning = sections.get("scanning", {})
scan_exit = int(scanning.get("exit_code", 0))
scanners = scanning.get("scanners", [])
total_findings = 0
scanner_count = 0
for s in scanners:
    if s.get("status") == "completed":
        scanner_count += 1
        total_findings += int(s.get("finding_count", 0))

if scanner_count > 0:
    if total_findings == 0:
        raw = 100
    elif total_findings <= 2:
        raw = 70
    elif total_findings <= 5:
        raw = 40
    else:
        raw = max(0, 100 - total_findings * 10)
    category_scores["scanning"] = round(raw)
    category_details["scanning"] = {
        "scanners_run": scanner_count,
        "total_findings": total_findings,
        "raw_score": round(raw),
    }
else:
    # No scanners ran — penalize slightly
    category_scores["scanning"] = 50
    category_details["scanning"] = {"note": "no scanners ran", "raw_score": 50}

# ── Composite score ──
composite = 0.0
for category, weight in weights.items():
    score = category_scores.get(category, 0)
    composite += score * weight

composite = round(composite)

# Risk rating
if composite >= 90:
    rating = "EXCELLENT"
elif composite >= 70:
    rating = "GOOD"
elif composite >= 50:
    rating = "FAIR"
elif composite >= 30:
    rating = "POOR"
else:
    rating = "CRITICAL"

result = {
    "risk_score": composite,
    "rating": rating,
    "weights": weights,
    "categories": {},
    "timestamp": metrics.get("timestamp", ""),
}

for cat in weights:
    result["categories"][cat] = {
        "weight": weights[cat],
        "score": category_scores.get(cat, 0),
        "weighted_contribution": round(category_scores.get(cat, 0) * weights[cat], 1),
        "details": category_details.get(cat, {}),
    }

print(json.dumps(result, indent=2))
PYTHON_SCORE
)

# ── Output ────────────────────────────────────────────────────────────────

if [[ -n "$JSON_OUTPUT" ]]; then
  echo "$score_output"
else
  # Parse key values for display
  score=$(echo "$score_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])")
  rating=$(echo "$score_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['rating'])")

  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║              Secret Lifecycle Risk Score                  ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════╣'
  printf '\n'

  # Score display with color
  local_score_color=""
  if [[ "$score" -ge 90 ]]; then
    local_score_color="$(_green "${score}/100")"
  elif [[ "$score" -ge 70 ]]; then
    local_score_color="$(_green "${score}/100")"
  elif [[ "$score" -ge 50 ]]; then
    local_score_color="$(_yellow "${score}/100")"
  elif [[ "$score" -ge 30 ]]; then
    local_score_color="$(_red "${score}/100")"
  else
    local_score_color="$(_red "${score}/100")"
  fi

  printf '║                                                           ║\n'
  printf '║     Risk Score:  %s  (%s)%*s║\n' "$local_score_color" "$rating" $((20 - ${#rating})) ""
  printf '║                                                           ║\n'

  # Progress bar
  bar_width=40
  filled=$(( score * bar_width / 100 ))
  empty=$(( bar_width - filled ))
  printf '║     ['
  if [[ "$score" -ge 70 ]]; then
    printf '\033[0;32m'
  elif [[ "$score" -ge 50 ]]; then
    printf '\033[0;33m'
  else
    printf '\033[0;31m'
  fi
  printf '%*s' "$filled" '' | tr ' ' '#'
  printf '\033[0m'
  printf '%*s' "$empty" '' | tr ' ' '.'
  printf ']  ║\n'

  printf '║                                                           ║\n'
  _bold '╠═══════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  %-22s %-8s %-8s %-14s  ║\n' "Category" "Weight" "Score" "Contribution"
  printf '║  %-22s %-8s %-8s %-14s  ║\n' "──────────────────────" "──────" "──────" "────────────"

  # Category breakdown
  echo "$score_output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for cat in ['secrets_hygiene','cert_health','credential_age','policy_compliance','scanning']:
    c = data['categories'].get(cat, {})
    w = c.get('weight', 0)
    s = c.get('score', 0)
    contrib = c.get('weighted_contribution', 0)
    print(f'{cat}|{w:.2f}|{s}|{contrib}')
" 2>/dev/null | while IFS='|' read -r cat weight cscore contrib; do
    score_disp=""
    if [[ "$cscore" -ge 70 ]]; then
      score_disp="$(_green "$cscore")"
    elif [[ "$cscore" -ge 50 ]]; then
      score_disp="$(_yellow "$cscore")"
    else
      score_disp="$(_red "$cscore")"
    fi
    printf '║  %-22s %-8s %s%*s %-14s  ║\n' "$cat" "$weight" "$score_disp" $((6 - ${#cscore})) "" "$contrib"
  done

  _bold '╚═══════════════════════════════════════════════════════════╝'
  printf '\n'

  # Verbose details
  if [[ -n "$VERBOSE" ]]; then
    printf '\n%s\n' "$(_bold 'Category Details:')"
    echo "$score_output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for cat, info in data['categories'].items():
    details = info.get('details', {})
    print(f'  {cat}:')
    for k, v in details.items():
        print(f'    {k}: {v}')
" 2>/dev/null
  fi
fi

# Exit 1 if score < 50
risk_score=$(echo "$score_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk_score'])")
if [[ "$risk_score" -lt 50 ]]; then
  exit 1
fi
exit 0
