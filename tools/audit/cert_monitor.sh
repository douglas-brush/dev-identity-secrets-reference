#!/usr/bin/env bash

#!/usr/bin/env bash
# cert_monitor.sh — Certificate monitoring wrapper with change detection and alerting
# Designed for cron, systemd timer, or CI gating
# Usage: cert_monitor.sh [--baseline <json>] [--webhook <url>] [--email <addr>] [--alert-only] [--ci]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERT_INVENTORY="${SCRIPT_DIR}/cert_inventory.sh"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${REPO_ROOT}/logs/cert-monitor-${TIMESTAMP//[:T]/-}.log"

# ── Defaults ──────────────────────────────────────────────────────────────

BASELINE_FILE=""
WEBHOOK_URL=""
EMAIL_ADDR=""
ALERT_ONLY=""
CI_MODE=""
THRESHOLD_DAYS=30
EXTRA_ARGS=()
EXIT_CODE=0

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }

# ── Logging ───────────────────────────────────────────────────────────────

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} [${level}] ${msg}"

  case "$level" in
    INFO)  printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)  printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR) printf '  %s %s\n' "$(_red 'ERROR')" "$msg" ;;
    OK)    printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
  esac

  mkdir -p "$(dirname "$LOG_FILE")"
  echo "$entry" >> "$LOG_FILE"
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'cert_monitor.sh') — Certificate monitoring and change detection

$(_bold 'USAGE')
  cert_monitor.sh [OPTIONS] [-- INVENTORY_ARGS...]

$(_bold 'OPTIONS')
  --baseline <path>    Path to previous cert_inventory.sh JSON output for diffing
  --webhook <url>      Send alert payload to webhook URL (POST, JSON body)
  --email <addr>       Send alert via sendmail to this address
  --alert-only         Only output if issues are found (suppress OK results)
  --ci                 CI mode: strict exit codes, no-color, machine-readable
  --threshold <days>   Override expiry threshold (default: 30, passed to inventory)
  -h, --help           Show this help

  Any arguments after -- are passed directly to cert_inventory.sh.

$(_bold 'DESCRIPTION')
  Lightweight monitoring wrapper around cert_inventory.sh. Designed to run
  on a schedule (cron, systemd timer) or as a CI gate.

  Features:
  - Runs cert_inventory.sh and captures JSON output
  - Compares against a previous baseline to detect:
    - Newly added certificates
    - Removed certificates
    - Status changes (OK -> EXPIRED, etc.)
  - Sends alerts via webhook or email when issues are found
  - Exits non-zero if any EXPIRED or EXPIRING_SOON certificates found

  CI gating:
    cert_monitor.sh --ci exits 1 if any certificate is expired or
    expiring soon, making it suitable as a CI pipeline gate.

$(_bold 'EXIT CODES')
  0   All certificates healthy, no concerning changes
  1   Expired, expiring, or weak certificates found
  2   Usage error

$(_bold 'EXAMPLES')
  cert_monitor.sh                                       # Basic scan
  cert_monitor.sh --baseline /tmp/prev.json             # Compare to baseline
  cert_monitor.sh --webhook https://hooks.slack.com/... # Alert to Slack
  cert_monitor.sh --ci -- --path /etc/ssl               # CI gate, custom path
  cert_monitor.sh --alert-only --email ops@example.com  # Email on issues only
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage ;;
    --baseline)      BASELINE_FILE="$2"; shift 2 ;;
    --webhook)       WEBHOOK_URL="$2"; shift 2 ;;
    --email)         EMAIL_ADDR="$2"; shift 2 ;;
    --alert-only)    ALERT_ONLY=1; shift ;;
    --ci)            CI_MODE=1; shift ;;
    --threshold)     THRESHOLD_DAYS="$2"; shift 2 ;;
    --)              shift; EXTRA_ARGS=("$@"); break ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# ── Run inventory ────────────────────────────────────────────────────────

run_inventory() {
  local inventory_args=(--json --threshold "$THRESHOLD_DAYS")

  if [[ -n "$CI_MODE" ]]; then
    inventory_args+=(--no-color)
  fi

  # Append any extra args
  if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
    inventory_args+=("${EXTRA_ARGS[@]}")
  fi

  if [[ ! -x "$CERT_INVENTORY" ]]; then
    log ERROR "cert_inventory.sh not found or not executable at: $CERT_INVENTORY"
    exit 2
  fi

  local output
  local inv_exit=0
  output=$("$CERT_INVENTORY" "${inventory_args[@]}" 2>/dev/null) || inv_exit=$?

  # cert_inventory.sh outputs mixed log lines + JSON; extract JSON only
  # The JSON starts with { and is the last block
  local json_output
  json_output=$(echo "$output" | sed -n '/^{/,/^}/p' | tail -n +1)

  if [[ -z "$json_output" ]]; then
    # Try to get just the JSON blob
    json_output=$(echo "$output" | grep -A9999 '^{' | head -n "$(echo "$output" | grep -A9999 '^{' | grep -n '^}' | tail -1 | cut -d: -f1)")
  fi

  if ! echo "$json_output" | jq . &>/dev/null 2>&1; then
    log ERROR "cert_inventory.sh did not produce valid JSON"
    log ERROR "Raw output: ${output:0:500}"
    exit 2
  fi

  printf '%s' "$json_output"
  return $inv_exit
}

# ── Diff against baseline ────────────────────────────────────────────────

diff_inventories() {
  local current_json="$1" baseline_json="$2"

  local added=() removed=() changed=()

  # Extract cert paths and statuses from current
  local current_paths
  current_paths=$(echo "$current_json" | jq -r '.certificates[]? | "\(.path)|\(.status)"' 2>/dev/null || echo "")

  # Extract cert paths and statuses from baseline
  local baseline_paths
  baseline_paths=$(echo "$baseline_json" | jq -r '.certificates[]? | "\(.path)|\(.status)"' 2>/dev/null || echo "")

  # Find new certs (in current but not baseline)
  while IFS='|' read -r path status; do
    [[ -z "$path" ]] && continue
    if ! echo "$baseline_paths" | grep -q "^${path}|"; then
      added+=("${path} (${status})")
    fi
  done <<< "$current_paths"

  # Find removed certs (in baseline but not current)
  while IFS='|' read -r path status; do
    [[ -z "$path" ]] && continue
    if ! echo "$current_paths" | grep -q "^${path}|"; then
      removed+=("${path} (was: ${status})")
    fi
  done <<< "$baseline_paths"

  # Find status changes
  while IFS='|' read -r path status; do
    [[ -z "$path" ]] && continue
    local old_status
    old_status=$(echo "$baseline_paths" | grep "^${path}|" | head -1 | cut -d'|' -f2)
    if [[ -n "$old_status" && "$old_status" != "$status" ]]; then
      changed+=("${path}: ${old_status} -> ${status}")
    fi
  done <<< "$current_paths"

  # Build diff report (human-readable goes to stderr, JSON to stdout)
  local has_changes=""

  if [[ ${#added[@]} -gt 0 ]]; then
    has_changes=1
    printf '\n  %s\n' "$(_bold 'New certificates detected:')" >&2
    for item in "${added[@]}"; do
      printf '    %s %s\n' "$(_green '+')" "$item" >&2
    done
  fi

  if [[ ${#removed[@]} -gt 0 ]]; then
    has_changes=1
    printf '\n  %s\n' "$(_bold 'Removed certificates:')" >&2
    for item in "${removed[@]}"; do
      printf '    %s %s\n' "$(_red '-')" "$item" >&2
    done
  fi

  if [[ ${#changed[@]} -gt 0 ]]; then
    has_changes=1
    printf '\n  %s\n' "$(_bold 'Status changes:')" >&2
    for item in "${changed[@]}"; do
      printf '    %s %s\n' "$(_yellow '~')" "$item" >&2
    done
  fi

  if [[ -z "$has_changes" ]]; then
    printf '\n  %s\n' "$(_green 'No changes from baseline.')" >&2
  fi

  # Return diff as JSON on stdout for caller to capture
  local added_json removed_json changed_json
  if [[ ${#added[@]} -gt 0 ]]; then
    added_json=$(printf '%s\n' "${added[@]}" | jq -R . | jq -s .)
  else
    added_json="[]"
  fi
  if [[ ${#removed[@]} -gt 0 ]]; then
    removed_json=$(printf '%s\n' "${removed[@]}" | jq -R . | jq -s .)
  else
    removed_json="[]"
  fi
  if [[ ${#changed[@]} -gt 0 ]]; then
    changed_json=$(printf '%s\n' "${changed[@]}" | jq -R . | jq -s .)
  else
    changed_json="[]"
  fi

  jq -n \
    --argjson added "$added_json" \
    --argjson removed "$removed_json" \
    --argjson changed "$changed_json" \
    '{added: $added, removed: $removed, changed: $changed}' 2>/dev/null || echo '{}'
}

# ── Alerting ─────────────────────────────────────────────────────────────

build_alert_payload() {
  local current_json="$1"
  local diff_json="${2:-{}}"

  local overall_status total expired expiring weak
  overall_status=$(echo "$current_json" | jq -r '.overall_status // "UNKNOWN"' 2>/dev/null)
  total=$(echo "$current_json" | jq -r '.total_certificates // 0' 2>/dev/null)
  expired=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "EXPIRED")] | length' 2>/dev/null || echo "0")
  expiring=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "EXPIRING_SOON")] | length' 2>/dev/null || echo "0")
  weak=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "WEAK_KEY")] | length' 2>/dev/null || echo "0")

  # Build problem list
  local problems
  problems=$(echo "$current_json" | jq -r '[.certificates[]? | select(.status != "OK" and .status != "UNKNOWN") | "\(.status): \(.path) (\(.not_after // "n/a"))"] | join("\n")' 2>/dev/null || echo "")

  cat <<EOF
{
  "source": "cert_monitor",
  "timestamp": "${TIMESTAMP}",
  "overall_status": "${overall_status}",
  "summary": {
    "total": ${total},
    "expired": ${expired},
    "expiring_soon": ${expiring},
    "weak_key": ${weak}
  },
  "problems": $(echo "$problems" | jq -R . | jq -s .),
  "diff": ${diff_json}
}
EOF
}

send_webhook() {
  local payload="$1"

  if [[ -z "$WEBHOOK_URL" ]]; then
    return
  fi

  log INFO "Sending webhook alert to: ${WEBHOOK_URL}"

  local http_code
  http_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "$WEBHOOK_URL" 2>/dev/null || echo "000")

  if [[ "$http_code" =~ ^2[0-9]{2}$ ]]; then
    log OK "Webhook delivered (HTTP ${http_code})"
  else
    log ERROR "Webhook delivery failed (HTTP ${http_code})"
  fi
}

send_email() {
  local payload="$1"

  if [[ -z "$EMAIL_ADDR" ]]; then
    return
  fi

  if ! command -v sendmail &>/dev/null; then
    log ERROR "sendmail not found — cannot send email alert"
    return
  fi

  local subject="[cert-monitor] Certificate alert — ${TIMESTAMP}"
  local overall_status
  overall_status=$(echo "$payload" | jq -r '.overall_status // "UNKNOWN"' 2>/dev/null)

  local body
  body="Certificate Monitor Alert
===========================
Timestamp: ${TIMESTAMP}
Status: ${overall_status}

$(echo "$payload" | jq -r '.problems[]? // empty' 2>/dev/null)

---
Full report attached as JSON.
"

  log INFO "Sending email alert to: ${EMAIL_ADDR}"

  {
    printf 'To: %s\n' "$EMAIL_ADDR"
    printf 'Subject: %s\n' "$subject"
    printf 'Content-Type: text/plain; charset=utf-8\n'
    printf '\n'
    printf '%s\n' "$body"
  } | sendmail "$EMAIL_ADDR" 2>/dev/null && \
    log OK "Email sent to ${EMAIL_ADDR}" || \
    log ERROR "Failed to send email to ${EMAIL_ADDR}"
}

# ── CI output ────────────────────────────────────────────────────────────

ci_output() {
  local current_json="$1"

  local overall_status total expired expiring weak
  overall_status=$(echo "$current_json" | jq -r '.overall_status // "UNKNOWN"' 2>/dev/null)
  total=$(echo "$current_json" | jq -r '.total_certificates // 0' 2>/dev/null)
  expired=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "EXPIRED")] | length' 2>/dev/null || echo "0")
  expiring=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "EXPIRING_SOON")] | length' 2>/dev/null || echo "0")
  weak=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "WEAK_KEY")] | length' 2>/dev/null || echo "0")

  printf '::group::Certificate Monitor Results\n'
  printf 'Status: %s\n' "$overall_status"
  printf 'Total certificates: %s\n' "$total"
  printf 'Expired: %s\n' "$expired"
  printf 'Expiring soon: %s\n' "$expiring"
  printf 'Weak keys: %s\n' "$weak"

  if [[ "$expired" -gt 0 || "$expiring" -gt 0 || "$weak" -gt 0 ]]; then
    printf '\nProblems:\n'
    echo "$current_json" | jq -r '.certificates[]? | select(.status != "OK" and .status != "UNKNOWN") | "  - [\(.status)] \(.path) (expires: \(.not_after // "n/a"))"' 2>/dev/null
  fi

  printf '::endgroup::\n'

  # Set GitHub Actions outputs
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
      echo "status=${overall_status}"
      echo "total=${total}"
      echo "expired=${expired}"
      echo "expiring=${expiring}"
      echo "weak=${weak}"
    } >> "$GITHUB_OUTPUT"
  fi

  # Annotations for GitHub Actions
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "$current_json" | jq -r '.certificates[]? | select(.status == "EXPIRED") | "::error title=Expired Certificate::Certificate expired: \(.path) (expired: \(.not_after // "unknown"))"' 2>/dev/null
    echo "$current_json" | jq -r '.certificates[]? | select(.status == "EXPIRING_SOON") | "::warning title=Expiring Certificate::Certificate expiring soon: \(.path) (expires: \(.not_after // "unknown"))"' 2>/dev/null
    echo "$current_json" | jq -r '.certificates[]? | select(.status == "WEAK_KEY") | "::warning title=Weak Key::Weak key detected: \(.path) (\(.flags))"' 2>/dev/null
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  log INFO "Certificate monitor started at ${TIMESTAMP}"

  # Run inventory
  local current_json
  local inv_exit=0
  current_json=$(run_inventory) || inv_exit=$?
  EXIT_CODE=$inv_exit

  if [[ -z "$current_json" ]]; then
    log ERROR "Failed to run certificate inventory"
    exit 2
  fi

  local overall_status
  overall_status=$(echo "$current_json" | jq -r '.overall_status // "UNKNOWN"' 2>/dev/null)

  # Alert-only mode: suppress output if everything is OK
  if [[ -n "$ALERT_ONLY" && "$overall_status" == "HEALTHY" ]]; then
    log OK "All certificates healthy — suppressing output (--alert-only)"
    exit 0
  fi

  # Diff against baseline if provided
  local diff_json="{}"
  if [[ -n "$BASELINE_FILE" ]]; then
    if [[ ! -f "$BASELINE_FILE" ]]; then
      log WARN "Baseline file not found: ${BASELINE_FILE} — skipping diff"
    else
      local baseline_json
      baseline_json=$(cat "$BASELINE_FILE")
      if echo "$baseline_json" | jq . &>/dev/null 2>&1; then
        if [[ -z "$CI_MODE" ]]; then
          printf '\n%s\n' "$(_bold '═══ Certificate Changes ═══')"
        fi
        # diff_inventories sends human-readable to stderr, JSON to stdout
        if [[ -n "$CI_MODE" ]]; then
          diff_json=$(diff_inventories "$current_json" "$baseline_json" 2>/dev/null)
        else
          diff_json=$(diff_inventories "$current_json" "$baseline_json")
        fi
      else
        log WARN "Baseline file is not valid JSON — skipping diff"
      fi
    fi
  fi

  # CI mode output
  if [[ -n "$CI_MODE" ]]; then
    ci_output "$current_json"
  else
    # Print summary
    local total expired expiring
    total=$(echo "$current_json" | jq -r '.total_certificates // 0' 2>/dev/null)
    expired=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "EXPIRED")] | length' 2>/dev/null || echo "0")
    expiring=$(echo "$current_json" | jq '[.certificates[]? | select(.status == "EXPIRING_SOON")] | length' 2>/dev/null || echo "0")

    printf '\n%s\n' "$(_bold '═══ Certificate Monitor Summary ═══')"
    printf '  Total certificates: %s\n' "$total"

    if [[ "$expired" -gt 0 ]]; then
      printf '  %s\n' "$(_red "Expired: ${expired}")"
    fi
    if [[ "$expiring" -gt 0 ]]; then
      printf '  %s\n' "$(_yellow "Expiring soon: ${expiring}")"
    fi
    if [[ "$overall_status" == "HEALTHY" ]]; then
      printf '  %s\n' "$(_green 'All certificates are healthy.')"
    fi
    printf '\n'
  fi

  # Send alerts
  local alert_payload
  alert_payload=$(build_alert_payload "$current_json" "$diff_json")
  send_webhook "$alert_payload"
  send_email "$alert_payload"

  # Save current run as potential future baseline
  local baseline_dir="${REPO_ROOT}/logs"
  mkdir -p "$baseline_dir"
  echo "$current_json" > "${baseline_dir}/cert-inventory-latest.json"
  log INFO "Current inventory saved to: ${baseline_dir}/cert-inventory-latest.json"
  log INFO "Log file: ${LOG_FILE}"

  exit $EXIT_CODE
}

main
