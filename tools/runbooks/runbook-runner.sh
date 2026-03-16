#!/usr/bin/env bash
# runbook-runner — Generic YAML runbook executor with validation, rollback, and structured logging
# Usage: runbook-runner.sh <runbook.yaml> [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${REPO_ROOT}/logs/runbooks"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="$(date -u +%Y%m%d-%H%M%S)-$$"

# ── Color & output ──────────────────────────────────────────────────────────

NO_COLOR="${NO_COLOR:-}"
VERBOSE="${VERBOSE:-}"
DRY_RUN=""
START_STEP=1
RUNBOOK_FILE=""

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

# ── Logging ─────────────────────────────────────────────────────────────────

LOG_FILE=""
declare -a LOG_ENTRIES=()

log_init() {
  mkdir -p "$LOG_DIR"
  local runbook_name
  runbook_name="$(basename "${RUNBOOK_FILE}" .yaml)"
  LOG_FILE="${LOG_DIR}/${runbook_name}-${RUN_ID}.log"
  : > "$LOG_FILE"
  log "INFO" "Runbook runner started — run_id=${RUN_ID} runbook=${RUNBOOK_FILE}"
}

log() {
  local level="$1" msg="$2"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} [${level}] ${msg}"
  echo "$entry" >> "$LOG_FILE"
  LOG_ENTRIES+=("${entry}")
  if [[ -n "$VERBOSE" ]] || [[ "$level" == "ERROR" ]]; then
    case "$level" in
      ERROR) printf '  %s %s\n' "$(_red "[${level}]")" "$msg" ;;
      WARN)  printf '  %s %s\n' "$(_yellow "[${level}]")" "$msg" ;;
      INFO)  printf '  %s %s\n' "$(_blue "[${level}]")" "$msg" ;;
      *)     printf '  %s %s\n' "$(_dim "[${level}]")" "$msg" ;;
    esac
  fi
}

# ── Help ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'runbook-runner') — Generic YAML runbook executor

$(_bold 'USAGE')
  runbook-runner.sh <runbook.yaml> [OPTIONS]

$(_bold 'OPTIONS')
  --dry-run       Show what would be executed without running commands
  --step N        Start execution from step N (1-indexed)
  --verbose       Show detailed execution output
  --no-color      Disable colored output
  -h, --help      Show this help

$(_bold 'RUNBOOK FORMAT')
  YAML file with the following structure:

    name: "Runbook Name"
    description: "What this runbook does"
    version: "1.0.0"
    requires:         # optional tool dependencies
      - vault
      - jq
    env:              # optional required env vars
      - VAULT_ADDR
    steps:
      - name: "Step description"
        command: "shell command to execute"
        validate: "command that returns 0 on success"    # optional
        rollback: "command to undo this step"             # optional
        continue_on_fail: false                           # optional, default false
        timeout: 30                                       # optional, seconds

$(_bold 'EXIT CODES')
  0   All steps completed successfully
  1   One or more steps failed
  2   Usage error or missing dependencies

$(_bold 'ENVIRONMENT')
  RUNBOOK_LOG_DIR   Override log directory (default: logs/runbooks/)
  NO_COLOR          Disable colored output

$(_bold 'EXAMPLES')
  runbook-runner.sh runbooks/secret-rotation.yaml
  runbook-runner.sh runbooks/vault-unseal.yaml --dry-run
  runbook-runner.sh runbooks/cert-renewal.yaml --step 3 --verbose
  runbook-runner.sh runbooks/incident-response.yaml --no-color
EOF
  exit 0
}

# ── YAML Parser ──────────────────────────────────────────────────────────────
# Minimal YAML parser using only bash + sed/awk/grep — no yq/python required.
# Handles the flat-list-of-maps structure used by runbook step definitions.

yaml_get_value() {
  # Extract a top-level scalar value: key: "value" or key: value
  local file="$1" key="$2"
  sed -n "s/^${key}:[[:space:]]*[\"']\{0,1\}\([^\"']*\)[\"']\{0,1\}[[:space:]]*$/\1/p" "$file" | head -1
}

yaml_get_list() {
  # Extract a top-level simple list (- item format) under a key
  local file="$1" key="$2"
  awk -v key="$key" '
    BEGIN { found=0 }
    $0 ~ "^"key":" { found=1; next }
    found && /^[[:space:]]*-[[:space:]]/ {
      sub(/^[[:space:]]*-[[:space:]]*/, "")
      sub(/[[:space:]]*$/, "")
      gsub(/"/, "")
      gsub(/'\''/, "")
      print
      next
    }
    found && /^[a-zA-Z]/ { found=0 }
  ' "$file"
}

yaml_count_steps() {
  local file="$1"
  grep -c '^[[:space:]]*-[[:space:]]*name:' "$file" 2>/dev/null || echo 0
}

yaml_get_step_field() {
  # Extract a field from the Nth step (1-indexed)
  local file="$1" step_num="$2" field="$3"
  awk -v step="$step_num" -v field="$field" '
    BEGIN { count=0; in_step=0 }
    /^[[:space:]]*-[[:space:]]*name:/ {
      count++
      in_step=(count == step) ? 1 : 0
      if (in_step && field == "name") {
        sub(/^[[:space:]]*-[[:space:]]*name:[[:space:]]*/, "")
        gsub(/^["'\''"]|["'\''"]$/, "")
        print
      }
      next
    }
    in_step && $0 ~ "^[[:space:]]*"field":" {
      sub(/^[[:space:]]*[a-z_]*:[[:space:]]*/, "")
      gsub(/^["'\''"]|["'\''"]$/, "")
      print
      in_step=0
    }
  ' "$file"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

[[ $# -eq 0 ]] && { usage; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    --dry-run)    DRY_RUN=1; shift ;;
    --step)
      [[ $# -lt 2 ]] && { printf 'Error: --step requires a number\n' >&2; exit 2; }
      START_STEP="$2"; shift 2 ;;
    --verbose)    VERBOSE=1; shift ;;
    --no-color)   NO_COLOR=1; shift ;;
    -*)
      printf 'Error: unknown option: %s\n' "$1" >&2
      printf 'Run runbook-runner.sh --help for usage.\n' >&2
      exit 2
      ;;
    *)
      if [[ -z "$RUNBOOK_FILE" ]]; then
        RUNBOOK_FILE="$1"; shift
      else
        printf 'Error: unexpected argument: %s\n' "$1" >&2
        exit 2
      fi
      ;;
  esac
done

# Resolve runbook path relative to script dir if not absolute
if [[ ! "$RUNBOOK_FILE" = /* ]]; then
  if [[ -f "${SCRIPT_DIR}/${RUNBOOK_FILE}" ]]; then
    RUNBOOK_FILE="${SCRIPT_DIR}/${RUNBOOK_FILE}"
  elif [[ -f "${RUNBOOK_FILE}" ]]; then
    RUNBOOK_FILE="$(cd "$(dirname "$RUNBOOK_FILE")" && pwd)/$(basename "$RUNBOOK_FILE")"
  fi
fi

if [[ ! -f "$RUNBOOK_FILE" ]]; then
  printf 'Error: runbook file not found: %s\n' "$RUNBOOK_FILE" >&2
  exit 2
fi

# Override log dir if env is set
[[ -n "${RUNBOOK_LOG_DIR:-}" ]] && LOG_DIR="$RUNBOOK_LOG_DIR"

# ── Dependency check ─────────────────────────────────────────────────────────

check_dependencies() {
  local deps
  deps="$(yaml_get_list "$RUNBOOK_FILE" "requires")"
  if [[ -n "$deps" ]]; then
    while IFS= read -r dep; do
      if ! command -v "$dep" &>/dev/null; then
        log "ERROR" "Required tool not found: ${dep}"
        printf '%s Required tool not found: %s\n' "$(_red 'ERROR')" "$dep" >&2
        return 1
      fi
      log "INFO" "Dependency OK: ${dep}"
    done <<< "$deps"
  fi
}

check_env_vars() {
  local vars
  vars="$(yaml_get_list "$RUNBOOK_FILE" "env")"
  if [[ -n "$vars" ]]; then
    while IFS= read -r var; do
      if [[ -z "${!var:-}" ]]; then
        log "ERROR" "Required environment variable not set: ${var}"
        printf '%s Required env var not set: %s\n' "$(_red 'ERROR')" "$var" >&2
        return 1
      fi
      log "INFO" "Env var OK: ${var}"
    done <<< "$vars"
  fi
}

# ── Step execution ───────────────────────────────────────────────────────────

declare -a COMPLETED_STEPS=()
STEP_RESULTS=()
TOTAL_STEPS=0
PASSED=0
FAILED=0
SKIPPED=0

execute_step() {
  local step_num="$1"
  local step_name step_cmd step_validate step_rollback step_continue_on_fail step_timeout
  step_name="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "name")"
  step_cmd="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "command")"
  step_validate="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "validate")"
  step_rollback="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "rollback")"
  step_continue_on_fail="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "continue_on_fail")"
  step_timeout="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "timeout")"

  [[ -z "$step_name" ]] && step_name="Step ${step_num}"
  [[ -z "$step_timeout" ]] && step_timeout=300

  printf '\n%s %s\n' "$(_bold "[$step_num/$TOTAL_STEPS]")" "$(_bold "$step_name")"
  log "INFO" "=== Step ${step_num}/${TOTAL_STEPS}: ${step_name} ==="

  if [[ -z "$step_cmd" ]]; then
    log "WARN" "Step ${step_num} has no command — skipping"
    printf '  %s No command defined\n' "$(_yellow 'SKIP')"
    SKIPPED=$((SKIPPED + 1))
    STEP_RESULTS+=("{\"step\":${step_num},\"name\":\"${step_name}\",\"status\":\"skipped\",\"reason\":\"no command\"}")
    return 0
  fi

  # ── Pre-validation ──
  if [[ -n "$step_validate" ]]; then
    log "INFO" "Pre-validate: ${step_validate}"
    if [[ -n "$DRY_RUN" ]]; then
      printf '  %s pre-validate: %s\n' "$(_dim 'DRY-RUN')" "$step_validate"
    fi
  fi

  # ── Dry run ──
  if [[ -n "$DRY_RUN" ]]; then
    printf '  %s command: %s\n' "$(_dim 'DRY-RUN')" "$step_cmd"
    if [[ -n "$step_validate" ]]; then
      printf '  %s post-validate: %s\n' "$(_dim 'DRY-RUN')" "$step_validate"
    fi
    if [[ -n "$step_rollback" ]]; then
      printf '  %s rollback: %s\n' "$(_dim 'DRY-RUN')" "$step_rollback"
    fi
    PASSED=$((PASSED + 1))
    STEP_RESULTS+=("{\"step\":${step_num},\"name\":\"${step_name}\",\"status\":\"dry-run\"}")
    return 0
  fi

  # ── Execute ──
  local start_time end_time duration exit_code=0
  start_time="$(date +%s)"
  log "INFO" "Executing: ${step_cmd}"

  local cmd_output
  cmd_output="$(timeout "$step_timeout" bash -c "$step_cmd" 2>&1)" || exit_code=$?

  end_time="$(date +%s)"
  duration=$((end_time - start_time))

  if [[ -n "$cmd_output" ]]; then
    log "DEBUG" "Output: ${cmd_output}"
    if [[ -n "$VERBOSE" ]]; then
      printf '  %s\n' "$(_dim "$cmd_output")"
    fi
  fi

  if [[ $exit_code -ne 0 ]]; then
    log "ERROR" "Step ${step_num} failed (exit=${exit_code}, ${duration}s)"
    printf '  %s %s (exit=%d, %ds)\n' "$(_red 'FAIL')" "$step_name" "$exit_code" "$duration"
    FAILED=$((FAILED + 1))
    STEP_RESULTS+=("{\"step\":${step_num},\"name\":\"${step_name}\",\"status\":\"failed\",\"exit_code\":${exit_code},\"duration\":${duration}}")

    if [[ "$step_continue_on_fail" == "true" ]]; then
      log "INFO" "continue_on_fail=true — proceeding"
      printf '  %s Continuing despite failure (continue_on_fail=true)\n' "$(_yellow 'WARN')"
      return 0
    fi
    return 1
  fi

  # ── Post-validation ──
  if [[ -n "$step_validate" ]]; then
    log "INFO" "Post-validate: ${step_validate}"
    local val_output val_exit=0
    val_output="$(bash -c "$step_validate" 2>&1)" || val_exit=$?
    if [[ $val_exit -ne 0 ]]; then
      log "ERROR" "Validation failed for step ${step_num}: ${val_output}"
      printf '  %s Validation failed: %s\n' "$(_red 'FAIL')" "$val_output"
      FAILED=$((FAILED + 1))
      STEP_RESULTS+=("{\"step\":${step_num},\"name\":\"${step_name}\",\"status\":\"validation-failed\",\"duration\":${duration}}")
      if [[ "$step_continue_on_fail" == "true" ]]; then
        return 0
      fi
      return 1
    fi
    log "INFO" "Validation passed for step ${step_num}"
  fi

  log "INFO" "Step ${step_num} completed (${duration}s)"
  printf '  %s %s (%ds)\n' "$(_green 'PASS')" "$step_name" "$duration"
  PASSED=$((PASSED + 1))
  COMPLETED_STEPS+=("$step_num")
  STEP_RESULTS+=("{\"step\":${step_num},\"name\":\"${step_name}\",\"status\":\"passed\",\"duration\":${duration}}")
  return 0
}

# ── Rollback ─────────────────────────────────────────────────────────────────

rollback_completed_steps() {
  if [[ ${#COMPLETED_STEPS[@]} -eq 0 ]]; then
    log "INFO" "No completed steps to roll back"
    return 0
  fi

  printf '\n%s\n' "$(_bold "═══ Rolling back ${#COMPLETED_STEPS[@]} completed step(s) ═══")"
  log "INFO" "Starting rollback of ${#COMPLETED_STEPS[@]} steps"

  # Reverse order
  local i
  for (( i=${#COMPLETED_STEPS[@]}-1; i>=0; i-- )); do
    local step_num="${COMPLETED_STEPS[$i]}"
    local step_name step_rollback
    step_name="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "name")"
    step_rollback="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "rollback")"

    if [[ -z "$step_rollback" ]]; then
      log "WARN" "Step ${step_num} (${step_name}) has no rollback command — skipping"
      printf '  %s Step %d (%s) — no rollback defined\n' "$(_yellow 'SKIP')" "$step_num" "$step_name"
      continue
    fi

    log "INFO" "Rolling back step ${step_num}: ${step_rollback}"
    printf '  %s Step %d (%s)...\n' "$(_blue 'ROLLBACK')" "$step_num" "$step_name"

    local rb_exit=0
    bash -c "$step_rollback" 2>&1 || rb_exit=$?
    if [[ $rb_exit -ne 0 ]]; then
      log "ERROR" "Rollback failed for step ${step_num} (exit=${rb_exit})"
      printf '  %s Rollback failed for step %d (exit=%d)\n' "$(_red 'ERROR')" "$step_num" "$rb_exit"
    else
      log "INFO" "Rollback succeeded for step ${step_num}"
      printf '  %s Step %d rolled back\n' "$(_green 'OK')" "$step_num"
    fi
  done
}

# ── JSON summary ─────────────────────────────────────────────────────────────

output_json_summary() {
  local runbook_name runbook_desc runbook_version status
  runbook_name="$(yaml_get_value "$RUNBOOK_FILE" "name")"
  runbook_desc="$(yaml_get_value "$RUNBOOK_FILE" "description")"
  runbook_version="$(yaml_get_value "$RUNBOOK_FILE" "version")"

  [[ $FAILED -eq 0 ]] && status="success" || status="failed"

  local json_file="${LOG_DIR}/$(basename "${RUNBOOK_FILE}" .yaml)-${RUN_ID}.json"

  local steps_json="["
  local first=1
  for entry in "${STEP_RESULTS[@]}"; do
    [[ $first -eq 0 ]] && steps_json+=","
    steps_json+="$entry"
    first=0
  done
  steps_json+="]"

  cat > "$json_file" <<ENDJSON
{
  "run_id": "${RUN_ID}",
  "runbook": "${runbook_name}",
  "description": "${runbook_desc}",
  "version": "${runbook_version}",
  "file": "${RUNBOOK_FILE}",
  "status": "${status}",
  "started_at": "${TIMESTAMP}",
  "completed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "dry_run": $([[ -n "$DRY_RUN" ]] && echo "true" || echo "false"),
  "start_step": ${START_STEP},
  "total_steps": ${TOTAL_STEPS},
  "passed": ${PASSED},
  "failed": ${FAILED},
  "skipped": ${SKIPPED},
  "steps": ${steps_json},
  "log_file": "${LOG_FILE}"
}
ENDJSON

  log "INFO" "JSON summary written to ${json_file}"
  printf '\n%s %s\n' "$(_dim 'Summary:')" "$json_file"
}

# ── Main execution ───────────────────────────────────────────────────────────

main() {
  log_init

  local runbook_name runbook_desc runbook_version
  runbook_name="$(yaml_get_value "$RUNBOOK_FILE" "name")"
  runbook_desc="$(yaml_get_value "$RUNBOOK_FILE" "description")"
  runbook_version="$(yaml_get_value "$RUNBOOK_FILE" "version")"

  printf '%s\n' "$(_bold "═══ ${runbook_name:-Unnamed Runbook} ═══")"
  [[ -n "$runbook_desc" ]] && printf '%s\n' "$(_dim "$runbook_desc")"
  [[ -n "$runbook_version" ]] && printf '%s\n' "$(_dim "Version: $runbook_version")"
  [[ -n "$DRY_RUN" ]] && printf '%s\n' "$(_yellow '[DRY RUN MODE]')"

  log "INFO" "Runbook: ${runbook_name} v${runbook_version}"
  log "INFO" "File: ${RUNBOOK_FILE}"
  [[ -n "$DRY_RUN" ]] && log "INFO" "Mode: dry-run"

  # Check dependencies
  if ! check_dependencies; then
    printf '\n%s Dependency check failed — aborting\n' "$(_red 'ERROR')"
    exit 2
  fi

  # Check env vars
  if ! check_env_vars; then
    printf '\n%s Environment check failed — aborting\n' "$(_red 'ERROR')"
    exit 2
  fi

  TOTAL_STEPS="$(yaml_count_steps "$RUNBOOK_FILE")"
  if [[ "$TOTAL_STEPS" -eq 0 ]]; then
    printf '%s No steps found in runbook\n' "$(_red 'ERROR')"
    exit 2
  fi

  log "INFO" "Total steps: ${TOTAL_STEPS}, starting from step ${START_STEP}"
  printf '%s\n' "$(_dim "Steps: ${TOTAL_STEPS} | Starting from: ${START_STEP}")"

  # Validate start step
  if [[ "$START_STEP" -gt "$TOTAL_STEPS" ]]; then
    printf '%s --step %d exceeds total steps (%d)\n' "$(_red 'ERROR')" "$START_STEP" "$TOTAL_STEPS" >&2
    exit 2
  fi

  # Skip steps before START_STEP
  local step_num
  for (( step_num=1; step_num<START_STEP; step_num++ )); do
    SKIPPED=$((SKIPPED + 1))
    local sname
    sname="$(yaml_get_step_field "$RUNBOOK_FILE" "$step_num" "name")"
    STEP_RESULTS+=("{\"step\":${step_num},\"name\":\"${sname}\",\"status\":\"skipped\",\"reason\":\"start_step\"}")
  done

  # Execute steps
  local run_failed=0
  for (( step_num=START_STEP; step_num<=TOTAL_STEPS; step_num++ )); do
    if ! execute_step "$step_num"; then
      run_failed=1
      printf '\n%s Step %d failed.\n' "$(_red 'ERROR')" "$step_num"

      # Offer rollback (in non-dry-run mode)
      if [[ -z "$DRY_RUN" ]] && [[ ${#COMPLETED_STEPS[@]} -gt 0 ]]; then
        log "INFO" "Failure at step ${step_num} — initiating rollback"
        rollback_completed_steps
      fi
      break
    fi
  done

  # Summary
  printf '\n%s\n' "$(_bold '═══ Summary ═══')"
  printf '  Passed:  %s\n' "$(_green "$PASSED")"
  printf '  Failed:  %s\n' "$(_red "$FAILED")"
  printf '  Skipped: %s\n' "$(_dim "$SKIPPED")"
  printf '  Log:     %s\n' "$(_dim "$LOG_FILE")"

  log "INFO" "Run complete — passed=${PASSED} failed=${FAILED} skipped=${SKIPPED}"

  output_json_summary

  [[ $run_failed -ne 0 ]] && exit 1
  exit 0
}

main
