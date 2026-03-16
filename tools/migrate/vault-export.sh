#!/usr/bin/env bash
# vault-export.sh — Export secrets from Vault KV (v1/v2) to SOPS-encrypted JSON/YAML
# Usage: vault-export.sh --mount <mount> [--path <path>] [--output <file>]
#        [--format json|yaml] [--dry-run] [--no-color] [--verbose] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"; export REPO_ROOT
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
MOUNT=""
EXPORT_PATH=""
OUTPUT_FILE=""
OUTPUT_FORMAT="json"
DRY_RUN=""
NO_COLOR="${NO_COLOR:-}"
VERBOSE=""
SOPS_AGE_RECIPIENTS="${SOPS_AGE_RECIPIENTS:-}"
KV_VERSION=""

EXPORT_COUNT=0
ERROR_COUNT=0
SKIP_COUNT=0

# ── Color & output ────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

log() {
  local level="$1"; shift
  local msg="$*"
  case "$level" in
    INFO)    printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)    printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR)   printf '  %s %s\n' "$(_red 'ERROR')" "$msg" >&2 ;;
    OK)      printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    DRY)     printf '  %s %s\n' "$(_yellow ' DRY')" "$msg" ;;
    STEP)    printf '\n%s %s\n' "$(_bold '==>')" "$(_bold "$msg")" ;;
    DEBUG)   [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_dim 'DBG ')" "$msg" || true ;;
  esac
}

die() { log ERROR "$@"; exit 1; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'vault-export') — Export Vault KV secrets to SOPS-encrypted file

$(_bold 'USAGE')
  vault-export.sh --mount <mount> [OPTIONS]

$(_bold 'OPTIONS')
  --mount <mount>       KV mount point (required)
  --path <path>         Export specific path under mount (default: all)
  --output <file>       Output file path (default: vault-export-<timestamp>.<fmt>)
  --format json|yaml    Output format (default: json)
  --kv-version 1|2     Force KV version detection (default: auto-detect)
  --dry-run             Show what would be exported without writing
  --no-color            Disable colored output
  --verbose             Show detailed debug information
  -h, --help            Show this help

$(_bold 'ENVIRONMENT')
  VAULT_ADDR              Vault server address (required)
  VAULT_TOKEN             Vault authentication token (required)
  SOPS_AGE_RECIPIENTS     age public key for SOPS encryption (required unless dry-run)

$(_bold 'EXAMPLES')
  vault-export.sh --mount secret --output backup.json
  vault-export.sh --mount secret --path apps/myapp --format yaml
  vault-export.sh --mount kv --dry-run --verbose
  SOPS_AGE_RECIPIENTS=age1... vault-export.sh --mount secret

$(_bold 'EXIT CODES')
  0   Export completed successfully
  1   Export failed
  2   Usage error
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)        usage ;;
    --mount)          MOUNT="$2"; shift 2 ;;
    --path)           EXPORT_PATH="$2"; shift 2 ;;
    --output)         OUTPUT_FILE="$2"; shift 2 ;;
    --format)         OUTPUT_FORMAT="$2"; shift 2 ;;
    --kv-version)     KV_VERSION="$2"; shift 2 ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --no-color)       NO_COLOR=1; shift ;;
    --verbose)        VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run vault-export.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

[[ -z "$MOUNT" ]] && die "Missing required --mount argument"
[[ -z "$VAULT_ADDR" ]] && die "VAULT_ADDR environment variable is not set"
[[ -z "$VAULT_TOKEN" ]] && die "VAULT_TOKEN environment variable is not set"
[[ "$OUTPUT_FORMAT" =~ ^(json|yaml)$ ]] || die "Invalid --format: ${OUTPUT_FORMAT} (must be json or yaml)"
[[ -n "$KV_VERSION" && ! "$KV_VERSION" =~ ^[12]$ ]] && die "Invalid --kv-version: ${KV_VERSION} (must be 1 or 2)"

command -v vault >/dev/null 2>&1 || die "vault CLI not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"

if [[ -z "$DRY_RUN" ]]; then
  command -v sops >/dev/null 2>&1 || die "sops not found in PATH (required for encryption)"
  [[ -z "$SOPS_AGE_RECIPIENTS" ]] && die "SOPS_AGE_RECIPIENTS must be set for encryption"
fi

# ── KV version detection ─────────────────────────────────────────────────

detect_kv_version() {
  if [[ -n "$KV_VERSION" ]]; then
    log DEBUG "KV version forced to v${KV_VERSION}"
    return
  fi

  log STEP "Detecting KV version for mount '${MOUNT}'"

  local mount_info
  if mount_info=$(vault secrets list -format=json 2>/dev/null | jq -r ".\"${MOUNT}/\".options.version // empty" 2>/dev/null); then
    if [[ "$mount_info" == "2" ]]; then
      KV_VERSION=2
    elif [[ "$mount_info" == "1" ]]; then
      KV_VERSION=1
    fi
  fi

  # Fallback: try a v2 metadata read
  if [[ -z "$KV_VERSION" ]]; then
    if vault kv metadata list "${MOUNT}/" >/dev/null 2>&1; then
      KV_VERSION=2
    else
      KV_VERSION=1
    fi
  fi

  log OK "Detected KV v${KV_VERSION} for mount '${MOUNT}'"
}

# ── Secret listing ────────────────────────────────────────────────────────

list_secrets_recursive() {
  local prefix="$1"
  local keys

  if [[ "$KV_VERSION" == "2" ]]; then
    keys=$(vault kv list -format=json "${MOUNT}/${prefix}" 2>/dev/null | jq -r '.[]' 2>/dev/null) || return 0
  else
    keys=$(vault list -format=json "${MOUNT}/${prefix}" 2>/dev/null | jq -r '.[]' 2>/dev/null) || return 0
  fi

  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    if [[ "$key" == */ ]]; then
      # Directory — recurse
      list_secrets_recursive "${prefix}${key}"
    else
      echo "${prefix}${key}"
    fi
  done <<< "$keys"
}

# ── Secret reading ────────────────────────────────────────────────────────

read_secret_v1() {
  local path="$1"
  local full_path="${MOUNT}/${path}"
  local data

  data=$(vault read -format=json "$full_path" 2>/dev/null) || {
    log WARN "Failed to read: ${full_path}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    return 1
  }

  jq -n \
    --arg path "$path" \
    --arg ts "$TIMESTAMP" \
    --argjson data "$(echo "$data" | jq '.data')" \
    '{
      path: $path,
      kv_version: 1,
      exported_at: $ts,
      data: $data
    }'
}

read_secret_v2() {
  local path="$1"
  local full_path="${MOUNT}/${path}"
  local metadata versions_json all_versions

  # Get metadata
  metadata=$(vault kv metadata get -format=json "${full_path}" 2>/dev/null) || {
    log WARN "Failed to read metadata: ${full_path}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
    return 1
  }

  local current_version created_time updated_time max_versions custom_metadata
  current_version=$(echo "$metadata" | jq -r '.data.current_version')
  created_time=$(echo "$metadata" | jq -r '.data.created_time')
  updated_time=$(echo "$metadata" | jq -r '.data.updated_time')
  max_versions=$(echo "$metadata" | jq -r '.data.max_versions')
  custom_metadata=$(echo "$metadata" | jq '.data.custom_metadata // {}')

  # Get all version numbers
  versions_json=$(echo "$metadata" | jq -r '.data.versions | keys[]' | sort -n)

  all_versions="[]"
  while IFS= read -r ver; do
    [[ -z "$ver" ]] && continue

    local ver_destroyed ver_deleted
    ver_destroyed=$(echo "$metadata" | jq -r ".data.versions.\"${ver}\".destroyed")
    ver_deleted=$(echo "$metadata" | jq -r ".data.versions.\"${ver}\".deletion_time")

    if [[ "$ver_destroyed" == "true" ]]; then
      log DEBUG "  Version ${ver} destroyed, skipping data read"
      all_versions=$(echo "$all_versions" | jq \
        --argjson v "$ver" \
        '. + [{"version": $v, "destroyed": true, "data": null}]')
      continue
    fi

    if [[ -n "$ver_deleted" && "$ver_deleted" != "null" && "$ver_deleted" != "" ]]; then
      log DEBUG "  Version ${ver} soft-deleted, skipping data read"
      all_versions=$(echo "$all_versions" | jq \
        --argjson v "$ver" \
        --arg dt "$ver_deleted" \
        '. + [{"version": $v, "deleted_time": $dt, "data": null}]')
      continue
    fi

    local ver_data
    ver_data=$(vault kv get -format=json -version="$ver" "${full_path}" 2>/dev/null) || {
      log WARN "Failed to read version ${ver} of ${full_path}"
      all_versions=$(echo "$all_versions" | jq \
        --argjson v "$ver" \
        '. + [{"version": $v, "error": "read_failed", "data": null}]')
      continue
    }

    local ver_ts
    ver_ts=$(echo "$ver_data" | jq -r '.data.metadata.created_time // empty')

    all_versions=$(echo "$all_versions" | jq \
      --argjson v "$ver" \
      --arg vts "$ver_ts" \
      --argjson vdata "$(echo "$ver_data" | jq '.data.data')" \
      '. + [{"version": $v, "created_time": $vts, "data": $vdata}]')
  done <<< "$versions_json"

  jq -n \
    --arg path "$path" \
    --arg ts "$TIMESTAMP" \
    --argjson cv "$current_version" \
    --arg ct "$created_time" \
    --arg ut "$updated_time" \
    --argjson mv "$max_versions" \
    --argjson cm "$custom_metadata" \
    --argjson versions "$all_versions" \
    '{
      path: $path,
      kv_version: 2,
      exported_at: $ts,
      metadata: {
        current_version: $cv,
        created_time: $ct,
        updated_time: $ut,
        max_versions: $mv,
        custom_metadata: $cm
      },
      versions: $versions
    }'
}

# ── Export orchestration ──────────────────────────────────────────────────

main() {
  log STEP "Vault KV Export"
  log INFO "Vault: ${VAULT_ADDR}"
  log INFO "Mount: ${MOUNT}"
  [[ -n "$EXPORT_PATH" ]] && log INFO "Path filter: ${EXPORT_PATH}"
  [[ -n "$DRY_RUN" ]] && log INFO "Mode: dry-run (no files written)"

  detect_kv_version

  # Set default output filename
  if [[ -z "$OUTPUT_FILE" ]]; then
    local ts_slug
    ts_slug="$(date -u +%Y%m%d-%H%M%S)"
    OUTPUT_FILE="vault-export-${MOUNT}-${ts_slug}.${OUTPUT_FORMAT}"
  fi

  # List secrets
  log STEP "Discovering secrets"
  local secrets_list
  secrets_list=$(list_secrets_recursive "${EXPORT_PATH}")

  if [[ -z "$secrets_list" ]]; then
    log WARN "No secrets found under ${MOUNT}/${EXPORT_PATH}"
    exit 0
  fi

  local total
  total=$(echo "$secrets_list" | wc -l | tr -d ' ')
  log INFO "Found ${total} secret(s) to export"

  # Export each secret
  log STEP "Reading secrets"
  local export_data="[]"

  while IFS= read -r secret_path; do
    [[ -z "$secret_path" ]] && continue
    log DEBUG "Reading: ${MOUNT}/${secret_path}"

    if [[ -n "$DRY_RUN" ]]; then
      log DRY "Would export: ${MOUNT}/${secret_path}"
      EXPORT_COUNT=$((EXPORT_COUNT + 1))
      continue
    fi

    local secret_json
    if [[ "$KV_VERSION" == "2" ]]; then
      secret_json=$(read_secret_v2 "$secret_path") || { continue; }
    else
      secret_json=$(read_secret_v1 "$secret_path") || { continue; }
    fi

    export_data=$(echo "$export_data" | jq --argjson s "$secret_json" '. + [$s]')
    EXPORT_COUNT=$((EXPORT_COUNT + 1))
  done <<< "$secrets_list"

  if [[ -n "$DRY_RUN" ]]; then
    log STEP "Dry-run summary"
    log OK "Would export ${EXPORT_COUNT} secret(s) to ${OUTPUT_FILE}"
    log INFO "Skipped: ${SKIP_COUNT}, Errors: ${ERROR_COUNT}"
    exit 0
  fi

  # Build final document
  local final_doc
  final_doc=$(jq -n \
    --arg addr "$VAULT_ADDR" \
    --arg mount "$MOUNT" \
    --arg path "$EXPORT_PATH" \
    --argjson kv "$KV_VERSION" \
    --arg ts "$TIMESTAMP" \
    --argjson count "$EXPORT_COUNT" \
    --argjson secrets "$export_data" \
    '{
      export_metadata: {
        vault_addr: $addr,
        mount: $mount,
        path_filter: $path,
        kv_version: $kv,
        exported_at: $ts,
        secret_count: $count
      },
      secrets: $secrets
    }')

  # Write to temp file then encrypt with SOPS
  log STEP "Encrypting export with SOPS"

  local tmp_file
  tmp_file=$(mktemp "/tmp/vault-export-XXXXXX.${OUTPUT_FORMAT}")
  # Ensure temp file is cleaned up
  trap 'rm -f "$tmp_file"' EXIT

  if [[ "$OUTPUT_FORMAT" == "yaml" ]]; then
    command -v yq >/dev/null 2>&1 || die "yq required for YAML output"
    echo "$final_doc" | yq -y '.' > "$tmp_file"
  else
    echo "$final_doc" | jq '.' > "$tmp_file"
  fi

  sops --encrypt \
    --age "$SOPS_AGE_RECIPIENTS" \
    --input-type "$OUTPUT_FORMAT" \
    --output-type "$OUTPUT_FORMAT" \
    "$tmp_file" > "$OUTPUT_FILE"

  rm -f "$tmp_file"
  trap - EXIT

  local file_size
  file_size=$(wc -c < "$OUTPUT_FILE" | tr -d ' ')

  log STEP "Export complete"
  log OK "Exported ${EXPORT_COUNT} secret(s) to ${OUTPUT_FILE} (${file_size} bytes, encrypted)"
  [[ "$ERROR_COUNT" -gt 0 ]] && log WARN "Errors: ${ERROR_COUNT}"
  [[ "$SKIP_COUNT" -gt 0 ]] && log INFO "Skipped: ${SKIP_COUNT}"

  if [[ "$ERROR_COUNT" -gt 0 ]]; then
    exit 1
  fi
}

main
