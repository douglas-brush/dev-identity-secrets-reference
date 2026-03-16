#!/usr/bin/env bash
set -euo pipefail

# collect-metrics.sh — Collect metrics from all secrets lifecycle tools into unified JSON
# Runs secrets-doctor, cert_inventory, credential_age_report, control_matrix, and scan_repo.
# Aggregates results into a single metrics JSON with optional trend comparison.
# Usage: collect-metrics.sh [--output <file>] [--baseline <file>] [--verbose] [--json]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPORT_DIR="${REPO_ROOT}/logs/metrics"

# ── Defaults ──────────────────────────────────────────────────────────────

OUTPUT_FILE=""
BASELINE_FILE=""
VERBOSE=""
JSON_ONLY=""

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

log() {
  [[ -n "$JSON_ONLY" ]] && return
  printf '  %s %s\n' "$(_blue '[*]')" "$1"
}

log_verbose() {
  [[ -z "$VERBOSE" ]] && return
  [[ -n "$JSON_ONLY" ]] && return
  printf '  %s %s\n' "$(_dim '[.]')" "$1"
}

log_ok() {
  [[ -n "$JSON_ONLY" ]] && return
  printf '  %s %s\n' "$(_green '[+]')" "$1"
}

log_warn() {
  [[ -n "$JSON_ONLY" ]] && return
  printf '  %s %s\n' "$(_yellow '[!]')" "$1" >&2
}

log_err() {
  [[ -n "$JSON_ONLY" ]] && return
  printf '  %s %s\n' "$(_red '[!]')" "$1" >&2
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'collect-metrics.sh') — Unified secrets lifecycle metrics collector

$(_bold 'USAGE')
  collect-metrics.sh [OPTIONS]

$(_bold 'OPTIONS')
  --output <file>     Write metrics JSON to file (default: logs/metrics/metrics-<timestamp>.json)
  --baseline <file>   Compare against a previous metrics JSON for trend analysis
  --verbose           Show detailed progress for each collector
  --json              Output only JSON to stdout (suppress progress messages)
  -h, --help          Show this help

$(_bold 'DESCRIPTION')
  Runs each secrets lifecycle tool in JSON mode, captures the output, and
  aggregates into a single metrics document with sections for:
    - secrets_doctor: infrastructure health checks
    - cert_inventory: certificate status and expiry
    - credential_age: credential rotation compliance
    - control_matrix: compliance framework status
    - scanning: secret scanning results

  When --baseline is provided, each section includes trend indicators
  showing whether metrics improved, degraded, or stayed stable.

$(_bold 'EXIT CODES')
  0   Metrics collected successfully
  1   One or more collectors reported issues
  2   Usage error

$(_bold 'EXAMPLES')
  collect-metrics.sh                                    # Collect and save
  collect-metrics.sh --output report.json               # Custom output path
  collect-metrics.sh --baseline logs/metrics/prev.json  # With trend comparison
  collect-metrics.sh --json                             # JSON to stdout only
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    --output)     OUTPUT_FILE="$2"; shift 2 ;;
    --baseline)   BASELINE_FILE="$2"; shift 2 ;;
    --verbose)    VERBOSE=1; shift ;;
    --json)       JSON_ONLY=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# Default output path
if [[ -z "$OUTPUT_FILE" ]]; then
  mkdir -p "$REPORT_DIR"
  OUTPUT_FILE="${REPORT_DIR}/metrics-${TIMESTAMP//[:T]/-}.json"
fi

# Validate baseline if provided
if [[ -n "$BASELINE_FILE" && ! -f "$BASELINE_FILE" ]]; then
  log_warn "Baseline file not found: ${BASELINE_FILE} — skipping trend analysis"
  BASELINE_FILE=""
fi

# ── Collector helpers ─────────────────────────────────────────────────────

# Run a tool and capture its JSON output; return empty object on failure
run_collector() {
  local name="$1"; shift
  local cmd="$1"; shift
  local args=("$@")

  log "Running ${name}..."
  log_verbose "Command: ${cmd} ${args[*]}"

  local output=""
  local exit_code=0

  if [[ -x "$cmd" ]]; then
    output=$("$cmd" "${args[@]}" 2>/dev/null) || exit_code=$?
    log_verbose "${name} exited with code ${exit_code}"
  else
    log_warn "${name}: command not found or not executable: ${cmd}"
    output="{\"error\":\"command not found\",\"path\":\"${cmd}\"}"
    exit_code=127
  fi

  # Validate JSON
  if echo "$output" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    log_ok "${name}: collected"
    echo "$output"
  else
    log_warn "${name}: output is not valid JSON — wrapping raw output"
    local escaped
    escaped=$(echo "$output" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo '""')
    echo "{\"error\":\"invalid_json\",\"exit_code\":${exit_code},\"raw_output\":${escaped}}"
  fi

  return "$exit_code"
}

# Extract a numeric value from JSON using python3
jq_py() {
  local json="$1" path="$2" default="${3:-0}"
  echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    keys = '${path}'.split('.')
    val = data
    for k in keys:
        if isinstance(val, dict):
            val = val.get(k, None)
        else:
            val = None
            break
    print(val if val is not None else '${default}')
except:
    print('${default}')
" 2>/dev/null || echo "$default"
}

# ── Trend calculation ─────────────────────────────────────────────────────

# Compare two numeric values, return trend indicator
calc_trend() {
  local current="$1" previous="$2" higher_is_better="${3:-false}"
  if [[ -z "$previous" || "$previous" == "null" || "$previous" == "0" ]]; then
    echo "new"
    return
  fi
  if [[ "$current" == "$previous" ]]; then
    echo "stable"
  elif [[ "$higher_is_better" == "true" ]]; then
    if [[ "$current" -gt "$previous" ]]; then
      echo "improving"
    else
      echo "degrading"
    fi
  else
    if [[ "$current" -lt "$previous" ]]; then
      echo "improving"
    else
      echo "degrading"
    fi
  fi
}

# Build trend JSON object for a section
build_trends() {
  local section="$1" current_json="$2"
  if [[ -z "$BASELINE_FILE" ]]; then
    echo "{}"
    return
  fi

  local baseline_section
  baseline_section=$(python3 -c "
import sys, json
with open('${BASELINE_FILE}') as f:
    data = json.load(f)
section = data.get('sections', {}).get('${section}', {})
json.dump(section, sys.stdout)
" 2>/dev/null || echo "{}")

  case "$section" in
    secrets_doctor)
      local cur_pass cur_fail cur_warn prev_pass prev_fail prev_warn
      cur_pass=$(jq_py "$current_json" "summary.passed" "0")
      cur_fail=$(jq_py "$current_json" "summary.failed" "0")
      cur_warn=$(jq_py "$current_json" "summary.warnings" "0")
      prev_pass=$(jq_py "$baseline_section" "summary.passed" "0")
      prev_fail=$(jq_py "$baseline_section" "summary.failed" "0")
      prev_warn=$(jq_py "$baseline_section" "summary.warnings" "0")

      local t_pass t_fail t_warn
      t_pass=$(calc_trend "$cur_pass" "$prev_pass" "true")
      t_fail=$(calc_trend "$cur_fail" "$prev_fail" "false")
      t_warn=$(calc_trend "$cur_warn" "$prev_warn" "false")

      printf '{"passed":{"current":%s,"previous":%s,"trend":"%s"},"failed":{"current":%s,"previous":%s,"trend":"%s"},"warnings":{"current":%s,"previous":%s,"trend":"%s"}}' \
        "$cur_pass" "$prev_pass" "$t_pass" \
        "$cur_fail" "$prev_fail" "$t_fail" \
        "$cur_warn" "$prev_warn" "$t_warn"
      ;;
    cert_inventory)
      local cur_total prev_total
      cur_total=$(jq_py "$current_json" "total_certificates" "0")
      prev_total=$(jq_py "$baseline_section" "total_certificates" "0")

      local cur_expired cur_expiring prev_expired prev_expiring
      cur_expired=$(echo "$current_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([c for c in d.get('certificates',[]) if c.get('status')=='EXPIRED']))" 2>/dev/null || echo "0")
      cur_expiring=$(echo "$current_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([c for c in d.get('certificates',[]) if c.get('status')=='EXPIRING_SOON']))" 2>/dev/null || echo "0")
      prev_expired=$(echo "$baseline_section" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([c for c in d.get('certificates',[]) if c.get('status')=='EXPIRED']))" 2>/dev/null || echo "0")
      prev_expiring=$(echo "$baseline_section" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([c for c in d.get('certificates',[]) if c.get('status')=='EXPIRING_SOON']))" 2>/dev/null || echo "0")

      local t_expired t_expiring
      t_expired=$(calc_trend "$cur_expired" "$prev_expired" "false")
      t_expiring=$(calc_trend "$cur_expiring" "$prev_expiring" "false")

      printf '{"expired":{"current":%s,"previous":%s,"trend":"%s"},"expiring":{"current":%s,"previous":%s,"trend":"%s"}}' \
        "$cur_expired" "$prev_expired" "$t_expired" \
        "$cur_expiring" "$prev_expiring" "$t_expiring"
      ;;
    credential_age)
      local cur_total prev_total
      cur_total=$(jq_py "$current_json" "total_credentials" "0")
      prev_total=$(jq_py "$baseline_section" "total_credentials" "0")
      local t_total
      t_total=$(calc_trend "$cur_total" "$prev_total" "false")
      printf '{"total":{"current":%s,"previous":%s,"trend":"%s"}}' \
        "$cur_total" "$prev_total" "$t_total"
      ;;
    control_matrix)
      local cur_pass cur_fail prev_pass prev_fail
      cur_pass=$(jq_py "$current_json" "summary.pass" "0")
      cur_fail=$(jq_py "$current_json" "summary.fail" "0")
      prev_pass=$(jq_py "$baseline_section" "summary.pass" "0")
      prev_fail=$(jq_py "$baseline_section" "summary.fail" "0")

      local t_pass t_fail
      t_pass=$(calc_trend "$cur_pass" "$prev_pass" "true")
      t_fail=$(calc_trend "$cur_fail" "$prev_fail" "false")

      printf '{"pass":{"current":%s,"previous":%s,"trend":"%s"},"fail":{"current":%s,"previous":%s,"trend":"%s"}}' \
        "$cur_pass" "$prev_pass" "$t_pass" \
        "$cur_fail" "$prev_fail" "$t_fail"
      ;;
    scanning)
      local cur_exit prev_exit
      cur_exit=$(jq_py "$current_json" "exit_code" "0")
      prev_exit=$(jq_py "$baseline_section" "exit_code" "0")
      local t_exit
      t_exit=$(calc_trend "$cur_exit" "$prev_exit" "false")
      printf '{"exit_code":{"current":%s,"previous":%s,"trend":"%s"}}' \
        "$cur_exit" "$prev_exit" "$t_exit"
      ;;
    *)
      echo "{}"
      ;;
  esac
}

# ── Main collection ───────────────────────────────────────────────────────

main() {
  if [[ -z "$JSON_ONLY" ]]; then
    printf '\n'
    _bold '╔═══════════════════════════════════════════════════════════╗'
    printf '\n'
    _bold '║         Secret Lifecycle Metrics Collector                ║'
    printf '\n'
    _bold '╠═══════════════════════════════════════════════════════════╣'
    printf '\n'
    printf '║  Timestamp: %-44s ║\n' "$TIMESTAMP"
    printf '║  Output:    %-44s ║\n' "$(basename "$OUTPUT_FILE")"
    if [[ -n "$BASELINE_FILE" ]]; then
      printf '║  Baseline:  %-44s ║\n' "$(basename "$BASELINE_FILE")"
    fi
    _bold '╚═══════════════════════════════════════════════════════════╝'
    printf '\n\n'
  fi

  local overall_exit=0

  # ── 1. Secrets Doctor ──
  local doctor_json=""
  doctor_json=$(run_collector "secrets-doctor" \
    "${REPO_ROOT}/tools/secrets-doctor/doctor.sh" \
    all --json --no-color) || overall_exit=1

  # ── 2. Certificate Inventory ──
  local cert_json=""
  cert_json=$(run_collector "cert-inventory" \
    "${REPO_ROOT}/tools/audit/cert_inventory.sh" \
    --json --no-color) || overall_exit=1

  # ── 3. Credential Age Report ──
  local cred_json=""
  cred_json=$(run_collector "credential-age" \
    "${REPO_ROOT}/tools/audit/credential_age_report.sh" \
    --format json) || overall_exit=1

  # ── 4. Control Matrix ──
  local matrix_json=""
  matrix_json=$(run_collector "control-matrix" \
    "${REPO_ROOT}/tools/compliance/control_matrix.sh" \
    --json) || overall_exit=1

  # ── 5. Secret Scanning ──
  local scan_json=""
  scan_json=$(run_collector "scan-repo" \
    "${REPO_ROOT}/tools/scanning/scan_repo.sh" \
    --json) || overall_exit=1

  # ── Build trend data ──
  local trend_doctor trend_cert trend_cred trend_matrix trend_scan
  trend_doctor=$(build_trends "secrets_doctor" "$doctor_json")
  trend_cert=$(build_trends "cert_inventory" "$cert_json")
  trend_cred=$(build_trends "credential_age" "$cred_json")
  trend_matrix=$(build_trends "control_matrix" "$matrix_json")
  trend_scan=$(build_trends "scanning" "$scan_json")

  # ── Assemble final JSON ──
  local baseline_ref="null"
  if [[ -n "$BASELINE_FILE" ]]; then
    baseline_ref="\"$(basename "$BASELINE_FILE")\""
  fi

  mkdir -p "$(dirname "$OUTPUT_FILE")"

  python3 -c "
import json, sys

sections = {
    'secrets_doctor': json.loads(sys.argv[1]) if sys.argv[1] else {},
    'cert_inventory': json.loads(sys.argv[2]) if sys.argv[2] else {},
    'credential_age': json.loads(sys.argv[3]) if sys.argv[3] else {},
    'control_matrix': json.loads(sys.argv[4]) if sys.argv[4] else {},
    'scanning':       json.loads(sys.argv[5]) if sys.argv[5] else {},
}

trends = {
    'secrets_doctor': json.loads(sys.argv[6]),
    'cert_inventory': json.loads(sys.argv[7]),
    'credential_age': json.loads(sys.argv[8]),
    'control_matrix': json.loads(sys.argv[9]),
    'scanning':       json.loads(sys.argv[10]),
}

report = {
    'report': 'secret_lifecycle_metrics',
    'version': '1.0.0',
    'timestamp': sys.argv[11],
    'baseline': json.loads(sys.argv[12]) if sys.argv[12] != 'null' else None,
    'sections': sections,
    'trends': trends,
}

print(json.dumps(report, indent=2))
" \
    "$doctor_json" \
    "$cert_json" \
    "$cred_json" \
    "$matrix_json" \
    "$scan_json" \
    "$trend_doctor" \
    "$trend_cert" \
    "$trend_cred" \
    "$trend_matrix" \
    "$trend_scan" \
    "$TIMESTAMP" \
    "$baseline_ref" \
    > "$OUTPUT_FILE"

  if [[ -n "$JSON_ONLY" ]]; then
    cat "$OUTPUT_FILE"
  else
    log_ok "Metrics written to: ${OUTPUT_FILE}"

    # Symlink latest
    local latest="${REPORT_DIR}/metrics-latest.json"
    ln -sf "$(basename "$OUTPUT_FILE")" "$latest" 2>/dev/null || true
    log_ok "Symlinked latest: ${latest}"

    printf '\n'
    _bold '┌─────────────────────────────────────────────────────────┐'
    printf '\n'
    _bold '│                 Collection Summary                      │'
    printf '\n'
    _bold '├─────────────────────────────────────────────────────────┤'
    printf '\n'

    # Print per-section status
    for section in secrets_doctor cert_inventory credential_age control_matrix scanning; do
      local status
      status=$(python3 -c "
import json
with open('${OUTPUT_FILE}') as f:
    data = json.load(f)
s = data.get('sections',{}).get('${section}',{})
if 'error' in s:
    print('ERROR')
elif s.get('overall','') in ('UNHEALTHY','ACTION_REQUIRED','NON_COMPLIANT'):
    print('ISSUES')
elif s.get('overall_status','') in ('UNHEALTHY','ACTION_REQUIRED','NON_COMPLIANT'):
    print('ISSUES')
elif s.get('exit_code',0) != 0:
    print('ISSUES')
else:
    print('OK')
" 2>/dev/null || echo "UNKNOWN")

      local icon
      case "$status" in
        OK)      icon="$(_green 'OK')" ;;
        ISSUES)  icon="$(_yellow 'ISSUES')" ;;
        ERROR)   icon="$(_red 'ERROR')" ;;
        *)       icon="$(_dim 'UNKNOWN')" ;;
      esac
      printf '│  %-20s %s\n' "$section" "$icon"
    done

    printf '\n'
    _bold '└─────────────────────────────────────────────────────────┘'
    printf '\n'
  fi

  return "$overall_exit"
}

main
