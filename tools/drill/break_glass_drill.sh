#!/usr/bin/env bash
# break_glass_drill.sh — Break-glass procedure drill and validation tool
# Simulates emergency access scenarios non-destructively, validates documentation
# Usage: break_glass_drill.sh [--dry-run] [--verbose] [--log-file <path>]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DRILL_LOG_DIR="${REPO_ROOT}/logs/drills"
DRILL_LOG="${DRILL_LOG_DIR}/break-glass-drill-${TIMESTAMP//[:T]/-}.log"

# ── Defaults ──────────────────────────────────────────────────────────────

DRY_RUN=""
VERBOSE=""
EXIT_CODE=0
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

PLAYBOOK="${REPO_ROOT}/docs/incident-playbooks/break-glass-procedure.md"

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
    DRY)   printf '  %s %s\n' "$(_yellow ' DRY')" "$msg" ;;
    SKIP)  printf '  %s %s\n' "$(_dim 'SKIP')" "$msg" ;;
  esac

  mkdir -p "$(dirname "$DRILL_LOG")"
  echo "$entry" >> "$DRILL_LOG"
}

pass() {
  local msg="$1"
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '  %s %s\n' "$(_green 'PASS')" "$msg"
  mkdir -p "$(dirname "$DRILL_LOG")"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [PASS] ${msg}" >> "$DRILL_LOG"
}

fail_check() {
  local msg="$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  EXIT_CODE=1
  printf '  %s %s\n' "$(_red 'FAIL')" "$msg"
  mkdir -p "$(dirname "$DRILL_LOG")"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [FAIL] ${msg}" >> "$DRILL_LOG"
}

warn_check() {
  local msg="$1"
  WARN_COUNT=$((WARN_COUNT + 1))
  printf '  %s %s\n' "$(_yellow 'WARN')" "$msg"
  mkdir -p "$(dirname "$DRILL_LOG")"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [WARN] ${msg}" >> "$DRILL_LOG"
}

skip_check() {
  local msg="$1"
  SKIP_COUNT=$((SKIP_COUNT + 1))
  printf '  %s %s\n' "$(_dim 'SKIP')" "$msg"
  mkdir -p "$(dirname "$DRILL_LOG")"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [SKIP] ${msg}" >> "$DRILL_LOG"
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'break_glass_drill.sh') — Break-glass procedure drill and validation

$(_bold 'USAGE')
  break_glass_drill.sh [OPTIONS]

$(_bold 'OPTIONS')
  --dry-run           Show what checks would run without executing Vault commands
  --log-file <path>   Custom log file path (default: logs/drills/break-glass-drill-<ts>.log)
  --verbose           Show additional diagnostic info
  -h, --help          Show this help

$(_bold 'DESCRIPTION')
  Validates break-glass emergency access procedures by:
  - Checking documentation completeness (playbook, contacts, recovery steps)
  - If Vault is available: verifying unseal key accessibility, emergency
    policy existence, and audit logging status
  - If Vault is not available: running documentation-only checks

  All checks are non-destructive. No credentials are created, rotated,
  or consumed. This tool generates quarterly compliance evidence.

$(_bold 'ENVIRONMENT')
  VAULT_ADDR          Vault server address (enables Vault drill checks)
  VAULT_TOKEN         Vault authentication token

$(_bold 'EXIT CODES')
  0   All drill checks passed
  1   One or more checks failed
  2   Usage error

$(_bold 'EXAMPLES')
  break_glass_drill.sh                     # Full drill
  break_glass_drill.sh --dry-run           # Preview drill checks
  break_glass_drill.sh --verbose           # Drill with extra output
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)      usage ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --log-file)     DRILL_LOG="$2"; shift 2 ;;
    --verbose)      VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# ── Documentation checks ─────────────────────────────────────────────────

check_playbook_exists() {
  printf '\n%s\n' "$(_bold '── Playbook Documentation ──')"

  if [[ -f "$PLAYBOOK" ]]; then
    pass "Break-glass playbook exists: docs/incident-playbooks/break-glass-procedure.md"
  else
    fail_check "Break-glass playbook NOT FOUND at docs/incident-playbooks/break-glass-procedure.md"
    return
  fi

  # Check file is non-trivial (at least 50 lines)
  local line_count
  line_count=$(wc -l < "$PLAYBOOK" | tr -d ' ')
  if [[ "$line_count" -ge 50 ]]; then
    pass "Playbook has substantive content (${line_count} lines)"
  else
    warn_check "Playbook seems sparse (${line_count} lines) — review for completeness"
  fi
}

check_emergency_contacts() {
  printf '\n%s\n' "$(_bold '── Emergency Contacts ──')"

  if [[ ! -f "$PLAYBOOK" ]]; then
    fail_check "Cannot check contacts — playbook missing"
    return
  fi

  # Check for key holder table
  if grep -q 'Key Holders' "$PLAYBOOK" 2>/dev/null; then
    pass "Key holders section found in playbook"
  else
    fail_check "Key holders section NOT FOUND — document who holds unseal keys"
  fi

  # Check for placeholder names vs actual names
  local placeholder_count
  placeholder_count=$(grep -c '\[Name' "$PLAYBOOK" 2>/dev/null || echo "0")
  if [[ "$placeholder_count" -gt 0 ]]; then
    warn_check "Found ${placeholder_count} placeholder name(s) — replace [Name ...] with actual contacts"
  else
    pass "No placeholder names detected — contacts appear populated"
  fi

  # Check for dual-control requirement
  if grep -qi 'dual.control\|two.*person\|two authorized' "$PLAYBOOK" 2>/dev/null; then
    pass "Dual-control / two-person requirement documented"
  else
    fail_check "Dual-control requirement not documented"
  fi

  # Check for minimum key holder count (Shamir 3-of-5)
  if grep -q '3-of-5\|3 of 5' "$PLAYBOOK" 2>/dev/null; then
    pass "Shamir threshold documented (3-of-5)"
  else
    warn_check "Shamir threshold not explicitly documented — verify quorum requirements"
  fi
}

check_recovery_steps() {
  printf '\n%s\n' "$(_bold '── Recovery Procedures ──')"

  if [[ ! -f "$PLAYBOOK" ]]; then
    fail_check "Cannot check recovery steps — playbook missing"
    return
  fi

  # Check for each scenario
  local scenarios=("Vault Unsealing" "Cloud Root Access" "SOPS Emergency Decryption" "SSH Emergency Access")
  for scenario in "${scenarios[@]}"; do
    if grep -qi "$scenario" "$PLAYBOOK" 2>/dev/null; then
      pass "Scenario documented: ${scenario}"
    else
      warn_check "Scenario NOT documented: ${scenario}"
    fi
  done

  # Check for post-break-glass rotation checklist
  if grep -qi 'POST-BREAK-GLASS\|post.break.glass\|rotation.*checklist\|credentials rotated' "$PLAYBOOK" 2>/dev/null; then
    pass "Post-break-glass rotation checklist found"
  else
    fail_check "Post-break-glass rotation checklist missing"
  fi

  # Check for incident report template
  if grep -qi 'INCIDENT REPORT\|incident.report' "$PLAYBOOK" 2>/dev/null; then
    pass "Incident report template found"
  else
    warn_check "Incident report template not found in playbook"
  fi

  # Check for drill procedure
  if grep -qi 'drill\|quarterly.*test\|quarterly.*drill' "$PLAYBOOK" 2>/dev/null; then
    pass "Drill / quarterly test procedure documented"
  else
    warn_check "Quarterly drill procedure not documented"
  fi
}

check_storage_locations() {
  printf '\n%s\n' "$(_bold '── Storage Locations ──')"

  if [[ ! -f "$PLAYBOOK" ]]; then
    fail_check "Cannot check storage locations — playbook missing"
    return
  fi

  # Check for storage location table
  if grep -qi 'Storage Locations' "$PLAYBOOK" 2>/dev/null; then
    pass "Break-glass material storage locations documented"
  else
    fail_check "Storage locations for break-glass materials not documented"
  fi

  # Check that key material types are listed
  local -A materials=(
    ["unseal key"]="unseal.key"
    ["root account"]="root.account"
    ["SSH emergency"]="SSH.emergency"
    ["SOPS/age break-glass"]="(age|SOPS).*break.glass"
  )
  for label in "${!materials[@]}"; do
    if grep -qiE "${materials[$label]}" "$PLAYBOOK" 2>/dev/null; then
      pass "Material type documented: ${label}"
    else
      warn_check "Material type may be missing: ${label}"
    fi
  done
}

# ── Vault checks (only when Vault is available) ──────────────────────────

check_vault_availability() {
  printf '\n%s\n' "$(_bold '── Vault Infrastructure Checks ──')"

  if ! command -v vault &>/dev/null; then
    skip_check "vault CLI not installed — running documentation-only checks"
    return 1
  fi

  if [[ -z "${VAULT_ADDR:-}" ]]; then
    skip_check "VAULT_ADDR not set — running documentation-only checks"
    return 1
  fi

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would check Vault connectivity at ${VAULT_ADDR}"
    log DRY "Would verify unseal key accessibility"
    log DRY "Would test emergency policy existence"
    log DRY "Would verify audit logging is active"
    return 1
  fi

  # Verify connectivity
  if ! vault status &>/dev/null 2>&1; then
    warn_check "Cannot connect to Vault at ${VAULT_ADDR}"
    return 1
  fi

  pass "Vault reachable at ${VAULT_ADDR}"
  return 0
}

check_vault_seal_status() {
  # Check seal status (non-destructive read)
  local status_json
  status_json=$(vault status -format=json 2>/dev/null || echo '{}')

  if [[ "$status_json" == "{}" ]]; then
    fail_check "Could not retrieve Vault seal status"
    return
  fi

  local sealed
  sealed=$(echo "$status_json" | jq -r '.sealed' 2>/dev/null || echo "unknown")

  if [[ "$sealed" == "false" ]]; then
    pass "Vault is unsealed"
  elif [[ "$sealed" == "true" ]]; then
    warn_check "Vault is currently sealed — break-glass may be needed"
  else
    warn_check "Could not determine Vault seal status"
  fi

  # Check seal type and threshold
  local seal_type threshold shares
  seal_type=$(echo "$status_json" | jq -r '.type // "unknown"' 2>/dev/null)
  threshold=$(echo "$status_json" | jq -r '.t // 0' 2>/dev/null)
  shares=$(echo "$status_json" | jq -r '.n // 0' 2>/dev/null)

  [[ -n "$VERBOSE" ]] && log INFO "Seal type: ${seal_type}, threshold: ${threshold}/${shares}"

  if [[ "$threshold" -gt 0 && "$shares" -gt 0 ]]; then
    pass "Shamir seal configured: ${threshold}-of-${shares}"
  fi
}

check_vault_emergency_policy() {
  # Check if an emergency/break-glass policy exists (read-only)
  local emergency_policies=("break-glass" "emergency" "emergency-access" "break_glass")
  local found_policy=""

  for policy_name in "${emergency_policies[@]}"; do
    if vault policy read "$policy_name" &>/dev/null 2>&1; then
      found_policy="$policy_name"
      break
    fi
  done

  if [[ -n "$found_policy" ]]; then
    pass "Emergency policy found: ${found_policy}"

    # Check if the policy is not overly broad (read-only inspection)
    local policy_content
    policy_content=$(vault policy read "$found_policy" 2>/dev/null || echo "")
    if echo "$policy_content" | grep -q 'path "*"' 2>/dev/null; then
      warn_check "Emergency policy '${found_policy}' grants wildcard access — review scope"
    fi
  else
    warn_check "No emergency/break-glass policy found — consider creating one"
  fi
}

check_vault_audit_logging() {
  # Verify audit devices are enabled (read-only)
  if ! vault token lookup &>/dev/null 2>&1; then
    skip_check "Cannot verify audit logging — not authenticated to Vault"
    return
  fi

  local audit_list
  audit_list=$(vault audit list -format=json 2>/dev/null || echo '{}')

  if [[ "$audit_list" == "{}" ]] || [[ "$(echo "$audit_list" | jq 'length' 2>/dev/null)" == "0" ]]; then
    fail_check "No audit devices enabled — break-glass events will not be logged"
  else
    local audit_count
    audit_count=$(echo "$audit_list" | jq 'length' 2>/dev/null || echo "0")
    pass "Vault audit logging active (${audit_count} audit device(s))"

    if [[ -n "$VERBOSE" ]]; then
      echo "$audit_list" | jq -r 'to_entries[] | "    \(.key): type=\(.value.type)"' 2>/dev/null
    fi
  fi
}

# ── Drill report ─────────────────────────────────────────────────────────

generate_report() {
  local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT + SKIP_COUNT))
  local result="PASS"
  [[ $WARN_COUNT -gt 0 ]] && result="PASS WITH WARNINGS"
  [[ $FAIL_COUNT -gt 0 ]] && result="FAIL"

  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║                     BREAK-GLASS DRILL REPORT                                 ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Date:        %-62s ║\n' "$TIMESTAMP"
  printf '║  Result:      %-62s ║\n' "$result"
  if [[ -n "$DRY_RUN" ]]; then
    printf '║  Mode:        %-62s ║\n' "DRY RUN"
  fi
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  %-10s %-10s %-10s %-10s %-25s ║\n' \
    "$(_green "PASS: ${PASS_COUNT}")" \
    "$(_yellow "WARN: ${WARN_COUNT}")" \
    "$(_red "FAIL: ${FAIL_COUNT}")" \
    "$(_dim "SKIP: ${SKIP_COUNT}")" \
    "Total: ${total}"
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'

  # Recommendations
  printf '║  %-75s ║\n' "RECOMMENDATIONS"
  _bold '║  ─────────────────────────────────────────────────────────────────────────── ║'
  printf '\n'

  if [[ $FAIL_COUNT -gt 0 ]]; then
    printf '║  %-75s ║\n' "- Address all FAIL items before next compliance review"
  fi
  if [[ $WARN_COUNT -gt 0 ]]; then
    printf '║  %-75s ║\n' "- Review WARN items and resolve where possible"
  fi

  # Calculate next quarterly drill date (roughly 90 days from now)
  local next_drill
  if date --version &>/dev/null 2>&1; then
    next_drill=$(date -u -d "+90 days" +%Y-%m-%d 2>/dev/null || echo "in ~90 days")
  else
    next_drill=$(date -u -v+90d +%Y-%m-%d 2>/dev/null || echo "in ~90 days")
  fi
  printf '║  %-75s ║\n' "- Schedule next drill: ${next_drill}"
  printf '║  %-75s ║\n' "- Retain this log for compliance evidence"

  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Log file:    %-62s ║\n' "${DRILL_LOG#"$REPO_ROOT"/}"
  _bold '╚═══════════════════════════════════════════════════════════════════════════════╝'
  printf '\n\n'

  # Write structured summary to log
  {
    echo ""
    echo "════════════════════════════════════════"
    echo "DRILL SUMMARY"
    echo "════════════════════════════════════════"
    echo "Date:     ${TIMESTAMP}"
    echo "Result:   ${result}"
    echo "Passed:   ${PASS_COUNT}"
    echo "Warnings: ${WARN_COUNT}"
    echo "Failed:   ${FAIL_COUNT}"
    echo "Skipped:  ${SKIP_COUNT}"
    echo "Total:    ${total}"
    [[ -n "$DRY_RUN" ]] && echo "Mode:     DRY RUN"
    echo "Next drill: ${next_drill}"
    echo "════════════════════════════════════════"
  } >> "$DRILL_LOG"
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  printf '\n%s\n' "$(_bold '═══ Break-Glass Drill ═══')"

  if [[ -n "$DRY_RUN" ]]; then
    printf '  %s\n' "$(_yellow 'DRY RUN MODE — Vault commands will not be executed')"
  fi

  log INFO "Drill started at ${TIMESTAMP}"
  log INFO "Log file: ${DRILL_LOG}"

  # Phase 1: Documentation checks (always run)
  check_playbook_exists
  check_emergency_contacts
  check_recovery_steps
  check_storage_locations

  # Phase 2: Vault infrastructure checks (when available)
  if check_vault_availability; then
    check_vault_seal_status
    check_vault_emergency_policy
    check_vault_audit_logging
  fi

  # Generate report
  generate_report

  exit $EXIT_CODE
}

main
