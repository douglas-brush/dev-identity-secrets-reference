#!/usr/bin/env bash

#!/usr/bin/env bash
# rotate_vault_secrets.sh — Vault KV v2 secret rotation orchestrator
# Identifies secrets exceeding max age and flags them for rotation
# Usage: rotate_vault_secrets.sh [--dry-run] [--max-age <days>] [--path <prefix>] [--webhook <url>]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${REPO_ROOT}/logs/vault-rotation-${TIMESTAMP//[:T]/-}.log"

# ── Defaults ──────────────────────────────────────────────────────────────

DRY_RUN=""
VERBOSE=""
MAX_AGE_DAYS=90
PATH_FILTER=""
WEBHOOK_URL=""
EXIT_CODE=0

# Counters
TOTAL_SECRETS=0
STALE_SECRETS=0
ERROR_COUNT=0

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
    STALE) printf '  %s %s\n' "$(_red 'STALE')" "$msg" ;;
  esac

  mkdir -p "$(dirname "$LOG_FILE")"
  echo "$entry" >> "$LOG_FILE"
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'rotate_vault_secrets.sh') — Vault KV v2 secret rotation orchestrator

$(_bold 'USAGE')
  rotate_vault_secrets.sh [OPTIONS]

$(_bold 'OPTIONS')
  --dry-run             Show stale secrets without triggering rotation
  --max-age <days>      Maximum secret age in days before flagging (default: 90)
  --path <prefix>       Only check secrets under this path (e.g. secret/prod)
  --webhook <url>       POST rotation notifications to this URL
  --log-file <path>     Custom log file path
  --verbose             Show additional diagnostic info
  -h, --help            Show this help

$(_bold 'DESCRIPTION')
  Scans Vault KV v2 secret engines for secrets whose last update exceeds
  the configured max age. This tool does NOT generate new secret values —
  that is the application's responsibility. Instead it:

  1. Lists all secrets with their metadata (version, last updated)
  2. Flags secrets exceeding max age as STALE
  3. Optionally sends webhook notifications for stale secrets
  4. Logs all findings for compliance evidence

$(_bold 'ENVIRONMENT')
  VAULT_ADDR            Vault server address (required)
  VAULT_TOKEN           Vault authentication token (required)
  VAULT_SECRET_MAX_AGE  Override default max age (days)

$(_bold 'EXIT CODES')
  0   All secrets within policy
  1   One or more secrets exceed max age
  2   Usage error or missing dependencies

$(_bold 'EXAMPLES')
  rotate_vault_secrets.sh --dry-run                     # Preview stale secrets
  rotate_vault_secrets.sh --max-age 30                  # Stricter 30-day policy
  rotate_vault_secrets.sh --path secret/prod            # Only production secrets
  rotate_vault_secrets.sh --webhook https://hooks.example.com/rotate  # With notification
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)      usage ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --max-age)      MAX_AGE_DAYS="$2"; shift 2 ;;
    --path)         PATH_FILTER="$2"; shift 2 ;;
    --webhook)      WEBHOOK_URL="$2"; shift 2 ;;
    --log-file)     LOG_FILE="$2"; shift 2 ;;
    --verbose)      VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# Override from environment
MAX_AGE_DAYS="${VAULT_SECRET_MAX_AGE:-$MAX_AGE_DAYS}"

# ── Date utilities ────────────────────────────────────────────────────────

days_since() {
  local timestamp="$1"
  local now_epoch then_epoch

  if date --version &>/dev/null 2>&1; then
    # GNU date
    now_epoch=$(date +%s)
    then_epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo "0")
  else
    # BSD date (macOS)
    now_epoch=$(date +%s)
    local clean_ts="${timestamp%%Z*}"
    clean_ts="${clean_ts%%+*}"
    then_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$clean_ts" +%s 2>/dev/null || \
                 date -j -f "%Y-%m-%d" "${clean_ts:0:10}" +%s 2>/dev/null || echo "0")
  fi

  if [[ "$then_epoch" -eq 0 ]]; then
    echo "unknown"
    return
  fi

  local diff=$((now_epoch - then_epoch))
  echo $((diff / 86400))
}

# ── Preflight checks ─────────────────────────────────────────────────────

preflight() {
  printf '\n%s\n\n' "$(_bold '═══ Vault Secret Rotation Orchestrator ═══')"

  if [[ -n "$DRY_RUN" ]]; then
    printf '  %s\n\n' "$(_yellow 'DRY RUN MODE — no rotation actions will be taken')"
  fi

  # Check vault CLI
  if ! command -v vault &>/dev/null; then
    log ERROR "vault CLI not found — install it first"
    exit 2
  fi
  log INFO "vault version: $(vault version 2>/dev/null | head -1)"

  # Check VAULT_ADDR
  if [[ -z "${VAULT_ADDR:-}" ]]; then
    log ERROR "VAULT_ADDR not set"
    exit 2
  fi
  log INFO "Vault address: ${VAULT_ADDR}"

  # Check connectivity and auth
  if ! vault token lookup &>/dev/null 2>&1; then
    log ERROR "Cannot authenticate to Vault — check VAULT_TOKEN"
    exit 2
  fi
  log OK "Vault authentication verified"

  # Check jq
  if ! command -v jq &>/dev/null; then
    log ERROR "jq not found — required for JSON processing"
    exit 2
  fi

  log INFO "Max age policy: ${MAX_AGE_DAYS} days"
  [[ -n "$PATH_FILTER" ]] && log INFO "Path filter: ${PATH_FILTER}"
  log INFO "Log file: ${LOG_FILE}"
}

# ── Discover KV v2 mounts ───────────────────────────────────────────────

discover_kv_mounts() {
  local mounts
  mounts=$(vault secrets list -format=json 2>/dev/null || echo '{}')

  if [[ "$mounts" == "{}" ]]; then
    log ERROR "Cannot list secret engines"
    exit 1
  fi

  local kv_mounts
  kv_mounts=$(echo "$mounts" | jq -r 'to_entries[] | select(.value.type == "kv") | .key' 2>/dev/null || echo "")

  if [[ -z "$kv_mounts" ]]; then
    # Fallback to common path
    kv_mounts="secret/"
  fi

  echo "$kv_mounts"
}

# ── List secrets recursively ─────────────────────────────────────────────

list_secrets_recursive() {
  local mount="$1"
  local prefix="${2:-}"

  local full_path="${mount}${prefix}"
  local list_output
  list_output=$(vault kv list -format=json "${full_path}" 2>/dev/null || echo '[]')

  if [[ "$list_output" == "[]" ]]; then
    return
  fi

  echo "$list_output" | jq -r '.[]' 2>/dev/null | while read -r entry; do
    [[ -z "$entry" ]] && continue

    if [[ "$entry" == */ ]]; then
      # Directory — recurse
      list_secrets_recursive "$mount" "${prefix}${entry}"
    else
      # Secret
      echo "${prefix}${entry}"
    fi
  done
}

# ── Check a single secret's age ──────────────────────────────────────────

check_secret_age() {
  local mount="$1"
  local secret_path="$2"
  local full_path="${mount}${secret_path}"

  TOTAL_SECRETS=$((TOTAL_SECRETS + 1))

  # Get metadata
  local metadata
  metadata=$(vault kv metadata get -format=json "${full_path}" 2>/dev/null || echo '{}')

  if [[ "$metadata" == "{}" ]]; then
    log WARN "Cannot read metadata for: ${full_path}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    return
  fi

  local current_version created_time updated_time
  current_version=$(echo "$metadata" | jq -r '.data.current_version // 0' 2>/dev/null)
  created_time=$(echo "$metadata" | jq -r '.data.created_time // empty' 2>/dev/null || echo "")

  # Get the timestamp of the current (latest) version
  updated_time=$(echo "$metadata" | jq -r \
    ".data.versions[\"${current_version}\"].created_time // empty" 2>/dev/null || echo "")

  local effective_time="${updated_time:-$created_time}"

  if [[ -z "$effective_time" ]]; then
    log WARN "Cannot determine age for: ${full_path}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    return
  fi

  local age_days
  age_days=$(days_since "$effective_time")

  if [[ "$age_days" == "unknown" ]]; then
    log WARN "Cannot parse timestamp for: ${full_path}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    return
  fi

  # Determine status
  if [[ "$age_days" -gt "$MAX_AGE_DAYS" ]]; then
    STALE_SECRETS=$((STALE_SECRETS + 1))
    EXIT_CODE=1

    log STALE "${full_path} — ${age_days} days old (v${current_version}, last updated: ${effective_time})"

    # Trigger webhook notification if configured
    if [[ -n "$WEBHOOK_URL" && -z "$DRY_RUN" ]]; then
      send_webhook "$full_path" "$age_days" "$current_version" "$effective_time"
    fi
  elif [[ "$age_days" -gt $((MAX_AGE_DAYS * 3 / 4)) ]]; then
    log WARN "${full_path} — ${age_days} days old, approaching max age (v${current_version})"
  else
    [[ -n "$VERBOSE" ]] && log OK "${full_path} — ${age_days} days old (v${current_version})"
  fi
}

# ── Webhook notification ─────────────────────────────────────────────────

send_webhook() {
  local path="$1" age="$2" version="$3" last_updated="$4"

  if ! command -v curl &>/dev/null; then
    log WARN "curl not available — cannot send webhook"
    return
  fi

  local payload
  payload=$(cat <<EOF
{
  "event": "secret_rotation_needed",
  "timestamp": "${TIMESTAMP}",
  "secret_path": "${path}",
  "age_days": ${age},
  "max_age_days": ${MAX_AGE_DAYS},
  "current_version": ${version},
  "last_updated": "${last_updated}",
  "vault_addr": "${VAULT_ADDR}"
}
EOF
)

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$payload" \
    --max-time 10 \
    "$WEBHOOK_URL" 2>/dev/null || echo "000")

  if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
    log OK "Webhook sent for: ${path} (HTTP ${http_code})"
  else
    log WARN "Webhook failed for: ${path} (HTTP ${http_code})"
  fi
}

# ── Summary ──────────────────────────────────────────────────────────────

print_summary() {
  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║                    VAULT SECRET ROTATION REPORT                               ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Generated:    %-61s ║\n' "$TIMESTAMP"
  printf '║  Vault:        %-61s ║\n' "${VAULT_ADDR}"
  printf '║  Max age:      %-61s ║\n' "${MAX_AGE_DAYS} days"
  if [[ -n "$PATH_FILTER" ]]; then
    printf '║  Path filter:  %-61s ║\n' "$PATH_FILTER"
  fi
  if [[ -n "$DRY_RUN" ]]; then
    printf '║  Mode:         %-61s ║\n' "DRY RUN"
  fi
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Total secrets scanned:   %-50s ║\n' "$TOTAL_SECRETS"
  printf '║  Stale (exceed max age):  %-50s ║\n' "$(_red "$STALE_SECRETS")"
  printf '║  Errors:                  %-50s ║\n' "$ERROR_COUNT"
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'

  if [[ $STALE_SECRETS -gt 0 ]]; then
    printf '║  %-75s ║\n' "$(_red 'ACTION REQUIRED: Secrets exceeding max age detected.')"
    printf '║  %-75s ║\n' "Applications owning these secrets must generate new values."
    printf '║  %-75s ║\n' "Update via: vault kv put <path> <key>=<new-value>"
  elif [[ $TOTAL_SECRETS -gt 0 ]]; then
    printf '║  %-75s ║\n' "$(_green 'All secrets are within rotation policy.')"
  else
    printf '║  %-75s ║\n' "$(_dim 'No secrets found to evaluate.')"
  fi

  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Log file:     %-61s ║\n' "${LOG_FILE#"$REPO_ROOT"/}"
  _bold '╚═══════════════════════════════════════════════════════════════════════════════╝'
  printf '\n\n'
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  preflight

  printf '\n%s\n' "$(_bold '── Discovering KV v2 mounts ──')"

  local kv_mounts
  kv_mounts=$(discover_kv_mounts)

  if [[ -z "$kv_mounts" ]]; then
    log WARN "No KV secret engines found"
    print_summary
    exit 0
  fi

  for mount in $kv_mounts; do
    mount="${mount%/}"

    # Apply path filter
    if [[ -n "$PATH_FILTER" ]]; then
      # Check if this mount is relevant to the filter
      local filter_mount="${PATH_FILTER%%/*}"
      if [[ "$mount" != "$filter_mount" && "$PATH_FILTER" != "${mount}/"* && "$mount" != "$PATH_FILTER" ]]; then
        [[ -n "$VERBOSE" ]] && log INFO "Skipping mount '${mount}' — does not match path filter"
        continue
      fi
    fi

    printf '\n%s\n' "$(_bold "── Scanning: ${mount}/ ──")"

    local secrets
    if [[ -n "$PATH_FILTER" && "$PATH_FILTER" == *"/"* ]]; then
      # Filter includes a sub-path
      local sub_path="${PATH_FILTER#"${mount}/"}"
      secrets=$(list_secrets_recursive "${mount}/" "${sub_path%/}/")
    else
      secrets=$(list_secrets_recursive "${mount}/")
    fi

    if [[ -z "$secrets" ]]; then
      log INFO "No secrets found under ${mount}/"
      continue
    fi

    local mount_count
    mount_count=$(echo "$secrets" | wc -l | tr -d ' ')
    log INFO "Found ${mount_count} secret(s) under ${mount}/"

    while IFS= read -r secret_path; do
      [[ -z "$secret_path" ]] && continue
      check_secret_age "${mount}/" "$secret_path"
    done <<< "$secrets"
  done

  print_summary

  # Log structured summary
  {
    echo ""
    echo "════════════════════════════════════════"
    echo "ROTATION SUMMARY"
    echo "════════════════════════════════════════"
    echo "Date:           ${TIMESTAMP}"
    echo "Vault:          ${VAULT_ADDR}"
    echo "Max age:        ${MAX_AGE_DAYS} days"
    echo "Total scanned:  ${TOTAL_SECRETS}"
    echo "Stale:          ${STALE_SECRETS}"
    echo "Errors:         ${ERROR_COUNT}"
    [[ -n "$DRY_RUN" ]] && echo "Mode:           DRY RUN"
    [[ -n "$PATH_FILTER" ]] && echo "Path filter:    ${PATH_FILTER}"
    echo "════════════════════════════════════════"
  } >> "$LOG_FILE"

  exit $EXIT_CODE
}

main
