#!/usr/bin/env bash
# vault-diff.sh — Compare KV secrets between two Vault instances (metadata only, never values)
# Usage: vault-diff.sh --source-addr <url> --dest-addr <url> --path <mount/path>
#        [--json] [--no-color] [--verbose] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

SOURCE_ADDR=""
DEST_ADDR=""
SOURCE_TOKEN="${VAULT_SOURCE_TOKEN:-${VAULT_TOKEN:-}}"
DEST_TOKEN="${VAULT_DEST_TOKEN:-${VAULT_TOKEN:-}}"
DIFF_PATH=""
JSON_OUTPUT=""
NO_COLOR="${NO_COLOR:-}"
VERBOSE=""

ADDED_COUNT=0
REMOVED_COUNT=0
CHANGED_COUNT=0
SAME_COUNT=0

# ── Color & output ────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }
_cyan()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;36m%s\033[0m' "$1"; }

log() {
  local level="$1"; shift
  local msg="$*"
  case "$level" in
    INFO)    printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)    printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR)   printf '  %s %s\n' "$(_red 'ERROR')" "$msg" >&2 ;;
    OK)      printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    STEP)    printf '\n%s %s\n' "$(_bold '==>')" "$(_bold "$msg")" ;;
    DEBUG)   [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_dim 'DBG ')" "$msg" || true ;;
  esac
}

die() { log ERROR "$@"; exit 1; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'vault-diff') — Compare secrets between two Vault instances

$(_bold 'USAGE')
  vault-diff.sh --source-addr <url> --dest-addr <url> --path <mount/path> [OPTIONS]

$(_bold 'OPTIONS')
  --source-addr <url>   Source Vault address (required)
  --dest-addr <url>     Destination Vault address (required)
  --path <mount/path>   KV path to compare (required, e.g., secret/ or secret/apps)
  --json                Output results as JSON
  --no-color            Disable colored output
  --verbose             Show detailed debug information
  -h, --help            Show this help

$(_bold 'ENVIRONMENT')
  VAULT_SOURCE_TOKEN    Token for source Vault (falls back to VAULT_TOKEN)
  VAULT_DEST_TOKEN      Token for destination Vault (falls back to VAULT_TOKEN)
  VAULT_TOKEN           Shared token if both use the same auth

$(_bold 'SECURITY')
  Secret values are NEVER displayed or compared. Only metadata is examined:
  - Path existence (added/removed)
  - Version counts
  - Timestamps (created, updated)
  - Custom metadata keys (not values)

$(_bold 'EXAMPLES')
  vault-diff.sh --source-addr https://vault-old:8200 \\
                --dest-addr https://vault-new:8200 \\
                --path secret/
  vault-diff.sh --source-addr https://v1:8200 \\
                --dest-addr https://v2:8200 \\
                --path secret/apps --json

$(_bold 'EXIT CODES')
  0   No differences found
  1   Differences found
  2   Usage or connectivity error
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)          usage ;;
    --source-addr)      SOURCE_ADDR="$2"; shift 2 ;;
    --dest-addr)        DEST_ADDR="$2"; shift 2 ;;
    --path)             DIFF_PATH="$2"; shift 2 ;;
    --json)             JSON_OUTPUT=1; shift ;;
    --no-color)         NO_COLOR=1; shift ;;
    --verbose)          VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run vault-diff.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

[[ -z "$SOURCE_ADDR" ]] && die "Missing required --source-addr"
[[ -z "$DEST_ADDR" ]] && die "Missing required --dest-addr"
[[ -z "$DIFF_PATH" ]] && die "Missing required --path"
[[ -z "$SOURCE_TOKEN" ]] && die "No source token: set VAULT_SOURCE_TOKEN or VAULT_TOKEN"
[[ -z "$DEST_TOKEN" ]] && die "No dest token: set VAULT_DEST_TOKEN or VAULT_TOKEN"

command -v vault >/dev/null 2>&1 || die "vault CLI not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"

# Extract mount and subpath
MOUNT="${DIFF_PATH%%/*}"
SUBPATH="${DIFF_PATH#*/}"
[[ "$MOUNT" == "$SUBPATH" ]] && SUBPATH=""
# Ensure trailing slash is removed for clean paths
SUBPATH="${SUBPATH%/}"

# ── Vault helpers ─────────────────────────────────────────────────────────

vault_src() {
  VAULT_ADDR="$SOURCE_ADDR" VAULT_TOKEN="$SOURCE_TOKEN" vault "$@"
}

vault_dst() {
  VAULT_ADDR="$DEST_ADDR" VAULT_TOKEN="$DEST_TOKEN" vault "$@"
}

list_secrets_recursive() {
  local vault_fn="$1"
  local mount="$2"
  local prefix="$3"

  local keys
  keys=$("$vault_fn" kv list -format=json "${mount}/${prefix}" 2>/dev/null | jq -r '.[]' 2>/dev/null) || return 0

  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    if [[ "$key" == */ ]]; then
      list_secrets_recursive "$vault_fn" "$mount" "${prefix}${key}"
    else
      echo "${prefix}${key}"
    fi
  done <<< "$keys"
}

get_secret_metadata() {
  local vault_fn="$1"
  local mount="$2"
  local path="$3"

  local metadata
  metadata=$("$vault_fn" kv metadata get -format=json "${mount}/${path}" 2>/dev/null) || {
    echo '{"error": true}'
    return
  }

  jq -n \
    --arg cv "$(echo "$metadata" | jq -r '.data.current_version // 0')" \
    --arg ct "$(echo "$metadata" | jq -r '.data.created_time // "unknown"')" \
    --arg ut "$(echo "$metadata" | jq -r '.data.updated_time // "unknown"')" \
    --argjson cm "$(echo "$metadata" | jq '.data.custom_metadata // {}' | jq 'keys')" \
    '{
      current_version: ($cv | tonumber),
      created_time: $ct,
      updated_time: $ut,
      custom_metadata_keys: $cm
    }'
}

# ── Diff logic ────────────────────────────────────────────────────────────

main() {
  [[ -z "$JSON_OUTPUT" ]] && log STEP "Vault KV Diff"
  [[ -z "$JSON_OUTPUT" ]] && log INFO "Source: ${SOURCE_ADDR}"
  [[ -z "$JSON_OUTPUT" ]] && log INFO "Dest:   ${DEST_ADDR}"
  [[ -z "$JSON_OUTPUT" ]] && log INFO "Path:   ${DIFF_PATH}"

  # Connectivity check
  if ! vault_src status >/dev/null 2>&1; then
    die "Cannot connect to source Vault at ${SOURCE_ADDR}"
  fi
  if ! vault_dst status >/dev/null 2>&1; then
    die "Cannot connect to destination Vault at ${DEST_ADDR}"
  fi

  # List secrets from both
  [[ -z "$JSON_OUTPUT" ]] && log STEP "Discovering secrets"

  local src_secrets dst_secrets
  src_secrets=$(list_secrets_recursive vault_src "$MOUNT" "${SUBPATH:+${SUBPATH}/}" | sort)
  dst_secrets=$(list_secrets_recursive vault_dst "$MOUNT" "${SUBPATH:+${SUBPATH}/}" | sort)

  local src_count dst_count
  src_count=$(echo "$src_secrets" | grep -c . || true)
  dst_count=$(echo "$dst_secrets" | grep -c . || true)

  [[ -z "$JSON_OUTPUT" ]] && log INFO "Source secrets: ${src_count}"
  [[ -z "$JSON_OUTPUT" ]] && log INFO "Dest secrets:   ${dst_count}"

  # Compute diff sets
  local only_in_src only_in_dst in_both
  only_in_src=$(comm -23 <(echo "$src_secrets") <(echo "$dst_secrets") | grep . || true)
  only_in_dst=$(comm -13 <(echo "$src_secrets") <(echo "$dst_secrets") | grep . || true)
  in_both=$(comm -12 <(echo "$src_secrets") <(echo "$dst_secrets") | grep . || true)

  # JSON output accumulator
  local json_results='{"added":[],"removed":[],"changed":[],"identical":[]}'

  # Secrets only in destination (added)
  if [[ -n "$only_in_dst" ]]; then
    [[ -z "$JSON_OUTPUT" ]] && log STEP "Added (only in destination)"
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      ADDED_COUNT=$((ADDED_COUNT + 1))

      if [[ -n "$JSON_OUTPUT" ]]; then
        json_results=$(echo "$json_results" | jq --arg p "$path" '.added += [$p]')
      else
        printf '  %s %s\n' "$(_green '+ ADD')" "$path"
      fi
    done <<< "$only_in_dst"
  fi

  # Secrets only in source (removed / not yet migrated)
  if [[ -n "$only_in_src" ]]; then
    [[ -z "$JSON_OUTPUT" ]] && log STEP "Removed (only in source)"
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      REMOVED_COUNT=$((REMOVED_COUNT + 1))

      if [[ -n "$JSON_OUTPUT" ]]; then
        json_results=$(echo "$json_results" | jq --arg p "$path" '.removed += [$p]')
      else
        printf '  %s %s\n' "$(_red '- REM')" "$path"
      fi
    done <<< "$only_in_src"
  fi

  # Secrets in both — compare metadata
  if [[ -n "$in_both" ]]; then
    [[ -z "$JSON_OUTPUT" ]] && log STEP "Comparing shared secrets"
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      log DEBUG "Comparing: ${path}"

      local src_meta dst_meta
      src_meta=$(get_secret_metadata vault_src "$MOUNT" "$path")
      dst_meta=$(get_secret_metadata vault_dst "$MOUNT" "$path")

      local src_ver dst_ver src_updated dst_updated
      src_ver=$(echo "$src_meta" | jq '.current_version')
      dst_ver=$(echo "$dst_meta" | jq '.current_version')
      src_updated=$(echo "$src_meta" | jq -r '.updated_time')
      dst_updated=$(echo "$dst_meta" | jq -r '.updated_time')

      local differs=""
      local diff_reasons=()

      if [[ "$src_ver" != "$dst_ver" ]]; then
        differs=1
        diff_reasons+=("versions: src=${src_ver} dst=${dst_ver}")
      fi

      if [[ "$src_updated" != "$dst_updated" ]]; then
        differs=1
        diff_reasons+=("updated: src=${src_updated} dst=${dst_updated}")
      fi

      local src_meta_keys dst_meta_keys
      src_meta_keys=$(echo "$src_meta" | jq -c '.custom_metadata_keys')
      dst_meta_keys=$(echo "$dst_meta" | jq -c '.custom_metadata_keys')
      if [[ "$src_meta_keys" != "$dst_meta_keys" ]]; then
        differs=1
        diff_reasons+=("metadata_keys differ")
      fi

      if [[ -n "$differs" ]]; then
        CHANGED_COUNT=$((CHANGED_COUNT + 1))
        if [[ -n "$JSON_OUTPUT" ]]; then
          json_results=$(echo "$json_results" | jq \
            --arg p "$path" \
            --argjson sv "$src_ver" \
            --argjson dv "$dst_ver" \
            --arg su "$src_updated" \
            --arg du "$dst_updated" \
            '.changed += [{"path": $p, "source_version": $sv, "dest_version": $dv, "source_updated": $su, "dest_updated": $du}]')
        else
          printf '  %s %s\n' "$(_yellow '~ CHG')" "$path"
          for reason in "${diff_reasons[@]}"; do
            printf '        %s\n' "$(_dim "$reason")"
          done
        fi
      else
        SAME_COUNT=$((SAME_COUNT + 1))
        if [[ -n "$JSON_OUTPUT" ]]; then
          json_results=$(echo "$json_results" | jq --arg p "$path" '.identical += [$p]')
        else
          log DEBUG "Identical: ${path}"
        fi
      fi
    done <<< "$in_both"
  fi

  # ── Summary ─────────────────────────────────────────────────────────────

  if [[ -n "$JSON_OUTPUT" ]]; then
    echo "$json_results" | jq \
      --argjson added "$ADDED_COUNT" \
      --argjson removed "$REMOVED_COUNT" \
      --argjson changed "$CHANGED_COUNT" \
      --argjson identical "$SAME_COUNT" \
      --arg src "$SOURCE_ADDR" \
      --arg dst "$DEST_ADDR" \
      --arg path "$DIFF_PATH" \
      --arg ts "$TIMESTAMP" \
      '{
        diff_metadata: {
          source: $src,
          destination: $dst,
          path: $path,
          timestamp: $ts,
          summary: {
            added: $added,
            removed: $removed,
            changed: $changed,
            identical: $identical
          }
        }
      } + .'
  else
    log STEP "Summary"
    printf '\n'
    printf '  %-12s %s\n' "Added:" "$(_green "${ADDED_COUNT}")"
    printf '  %-12s %s\n' "Removed:" "$(_red "${REMOVED_COUNT}")"
    printf '  %-12s %s\n' "Changed:" "$(_yellow "${CHANGED_COUNT}")"
    printf '  %-12s %s\n' "Identical:" "$(_dim "${SAME_COUNT}")"
    printf '\n'

    local total_diff=$((ADDED_COUNT + REMOVED_COUNT + CHANGED_COUNT))
    if [[ "$total_diff" -eq 0 ]]; then
      log OK "No differences found"
    else
      log WARN "${total_diff} difference(s) found"
    fi
  fi

  # Exit 1 if differences found
  local total_diff=$((ADDED_COUNT + REMOVED_COUNT + CHANGED_COUNT))
  [[ "$total_diff" -gt 0 ]] && exit 1
  exit 0
}

main
