#!/usr/bin/env bash
# vault-import.sh — Import SOPS-encrypted Vault export into a new Vault instance
# Usage: vault-import.sh --input <file> [--remap-file <file>] [--preserve-versions]
#        [--dry-run] [--no-color] [--verbose] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"; export REPO_ROOT
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; export TIMESTAMP

# ── Defaults ──────────────────────────────────────────────────────────────

VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
INPUT_FILE=""
REMAP_FILE=""
PRESERVE_VERSIONS=""
DRY_RUN=""
NO_COLOR="${NO_COLOR:-}"
VERBOSE=""
TARGET_MOUNT=""

IMPORT_COUNT=0
REMAP_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

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
$(_bold 'vault-import') — Import SOPS-encrypted export into Vault

$(_bold 'USAGE')
  vault-import.sh --input <file> [OPTIONS]

$(_bold 'OPTIONS')
  --input <file>         SOPS-encrypted export file (required)
  --remap-file <file>    JSON file with path remapping rules
  --mount <mount>        Override target mount point (default: from export)
  --preserve-versions    Write each version in order (v2 only)
  --dry-run              Validate and show plan without writing
  --no-color             Disable colored output
  --verbose              Show detailed debug information
  -h, --help             Show this help

$(_bold 'REMAP FILE FORMAT')
  {
    "remaps": [
      {"from": "apps/old-service", "to": "apps/new-service"},
      {"from": "legacy/",          "to": "v2/migrated/"}
    ]
  }

$(_bold 'ENVIRONMENT')
  VAULT_ADDR              Vault server address (required)
  VAULT_TOKEN             Vault authentication token (required)
  SOPS_AGE_KEY_FILE       Path to age private key for SOPS decryption

$(_bold 'EXAMPLES')
  vault-import.sh --input backup.json --dry-run
  vault-import.sh --input backup.json --remap-file remap.json
  vault-import.sh --input backup.json --mount secret-v2 --preserve-versions
  vault-import.sh --input backup.yaml --verbose

$(_bold 'EXIT CODES')
  0   Import completed successfully
  1   Import failed
  2   Usage error
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)              usage ;;
    --input)                INPUT_FILE="$2"; shift 2 ;;
    --remap-file)           REMAP_FILE="$2"; shift 2 ;;
    --mount)                TARGET_MOUNT="$2"; shift 2 ;;
    --preserve-versions)    PRESERVE_VERSIONS=1; shift ;;
    --dry-run)              DRY_RUN=1; shift ;;
    --no-color)             NO_COLOR=1; shift ;;
    --verbose)              VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run vault-import.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

[[ -z "$INPUT_FILE" ]] && die "Missing required --input argument"
[[ ! -f "$INPUT_FILE" ]] && die "Input file not found: ${INPUT_FILE}"
[[ -z "$VAULT_ADDR" ]] && die "VAULT_ADDR environment variable is not set"
[[ -z "$VAULT_TOKEN" ]] && die "VAULT_TOKEN environment variable is not set"

command -v vault >/dev/null 2>&1 || die "vault CLI not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"
command -v sops >/dev/null 2>&1 || die "sops not found in PATH"

if [[ -n "$REMAP_FILE" ]]; then
  [[ ! -f "$REMAP_FILE" ]] && die "Remap file not found: ${REMAP_FILE}"
  # Validate remap JSON structure
  jq -e '.remaps | type == "array"' "$REMAP_FILE" >/dev/null 2>&1 \
    || die "Invalid remap file: must contain a 'remaps' array"
fi

# ── Decrypt export file ───────────────────────────────────────────────────

log STEP "Decrypting export file"
log INFO "Input: ${INPUT_FILE}"

DECRYPTED_DATA=""

# Detect format from extension
INPUT_FORMAT="json"
if [[ "$INPUT_FILE" == *.yaml || "$INPUT_FILE" == *.yml ]]; then
  INPUT_FORMAT="yaml"
fi

DECRYPTED_DATA=$(sops --decrypt --input-type "$INPUT_FORMAT" --output-type json "$INPUT_FILE") || \
  die "Failed to decrypt input file. Check SOPS_AGE_KEY_FILE or key access."

log OK "Decrypted successfully"

# ── Parse export metadata ────────────────────────────────────────────────

SOURCE_ADDR=$(echo "$DECRYPTED_DATA" | jq -r '.export_metadata.vault_addr // "unknown"')
SOURCE_MOUNT=$(echo "$DECRYPTED_DATA" | jq -r '.export_metadata.mount // "secret"')
SOURCE_KV=$(echo "$DECRYPTED_DATA" | jq -r '.export_metadata.kv_version // 2')
EXPORTED_AT=$(echo "$DECRYPTED_DATA" | jq -r '.export_metadata.exported_at // "unknown"')
SECRET_COUNT=$(echo "$DECRYPTED_DATA" | jq '.secrets | length')

MOUNT="${TARGET_MOUNT:-$SOURCE_MOUNT}"

log INFO "Source: ${SOURCE_ADDR} (mount: ${SOURCE_MOUNT}, KV v${SOURCE_KV})"
log INFO "Target: ${VAULT_ADDR} (mount: ${MOUNT})"
log INFO "Exported at: ${EXPORTED_AT}"
log INFO "Secrets to import: ${SECRET_COUNT}"

# ── Path remapping ────────────────────────────────────────────────────────

apply_remap() {
  local path="$1"

  if [[ -z "$REMAP_FILE" ]]; then
    echo "$path"
    return
  fi

  local remapped="$path"
  local remap_count
  remap_count=$(jq '.remaps | length' "$REMAP_FILE")

  for ((i = 0; i < remap_count; i++)); do
    local from to
    from=$(jq -r ".remaps[$i].from" "$REMAP_FILE")
    to=$(jq -r ".remaps[$i].to" "$REMAP_FILE")

    if [[ "$remapped" == "${from}"* ]]; then
      remapped="${to}${remapped#"$from"}"
      log DEBUG "Remapped: ${path} -> ${remapped}"
      REMAP_COUNT=$((REMAP_COUNT + 1))
      break
    fi
  done

  echo "$remapped"
}

# ── Import functions ──────────────────────────────────────────────────────

import_secret_v1() {
  local idx="$1"
  local path target_path data

  path=$(echo "$DECRYPTED_DATA" | jq -r ".secrets[$idx].path")
  target_path=$(apply_remap "$path")
  data=$(echo "$DECRYPTED_DATA" | jq -c ".secrets[$idx].data")

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would write: ${MOUNT}/${target_path}"
    [[ "$path" != "$target_path" ]] && log DRY "  (remapped from ${path})"
    IMPORT_COUNT=$((IMPORT_COUNT + 1))
    return 0
  fi

  # Convert JSON to key=value pairs for vault write
  local kv_args=()
  while IFS= read -r key; do
    local val
    val=$(echo "$data" | jq -r --arg k "$key" '.[$k] // empty')
    kv_args+=("${key}=${val}")
  done < <(echo "$data" | jq -r 'keys[]')

  if vault write "${MOUNT}/${target_path}" "${kv_args[@]}" >/dev/null 2>&1; then
    log OK "Imported: ${MOUNT}/${target_path}"
    IMPORT_COUNT=$((IMPORT_COUNT + 1))
  else
    log ERROR "Failed to write: ${MOUNT}/${target_path}"
    ERROR_COUNT=$((ERROR_COUNT + 1))
  fi
}

import_secret_v2() {
  local idx="$1"
  local path target_path

  path=$(echo "$DECRYPTED_DATA" | jq -r ".secrets[$idx].path")
  target_path=$(apply_remap "$path")

  local version_count
  version_count=$(echo "$DECRYPTED_DATA" | jq ".secrets[$idx].versions | length")

  if [[ -n "$PRESERVE_VERSIONS" ]]; then
    # Write each version in order
    for ((v = 0; v < version_count; v++)); do
      local ver_data ver_destroyed
      ver_destroyed=$(echo "$DECRYPTED_DATA" | jq -r ".secrets[$idx].versions[$v].destroyed // false")

      if [[ "$ver_destroyed" == "true" ]]; then
        log DEBUG "Skipping destroyed version for ${target_path}"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        continue
      fi

      ver_data=$(echo "$DECRYPTED_DATA" | jq -c ".secrets[$idx].versions[$v].data // null")
      if [[ "$ver_data" == "null" ]]; then
        log DEBUG "Skipping null data version for ${target_path}"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        continue
      fi

      if [[ -n "$DRY_RUN" ]]; then
        local ver_num
        ver_num=$(echo "$DECRYPTED_DATA" | jq -r ".secrets[$idx].versions[$v].version")
        log DRY "Would write: ${MOUNT}/${target_path} (version ${ver_num})"
        IMPORT_COUNT=$((IMPORT_COUNT + 1))
        continue
      fi

      # Write using vault kv put with JSON input
      if echo "$ver_data" | vault kv put "${MOUNT}/${target_path}" - >/dev/null 2>&1; then
        log DEBUG "Wrote version to ${MOUNT}/${target_path}"
      else
        # Try key=value format fallback
        local kv_args=()
        while IFS= read -r key; do
          local val
          val=$(echo "$ver_data" | jq -r --arg k "$key" '.[$k] // empty')
          kv_args+=("${key}=${val}")
        done < <(echo "$ver_data" | jq -r 'keys[]')

        if vault kv put "${MOUNT}/${target_path}" "${kv_args[@]}" >/dev/null 2>&1; then
          log DEBUG "Wrote version to ${MOUNT}/${target_path} (kv fallback)"
        else
          log ERROR "Failed to write version to ${MOUNT}/${target_path}"
          ERROR_COUNT=$((ERROR_COUNT + 1))
          continue
        fi
      fi
      IMPORT_COUNT=$((IMPORT_COUNT + 1))
    done
  else
    # Write only the latest version (last in versions array with non-null data)
    local latest_data=""
    for ((v = version_count - 1; v >= 0; v--)); do
      latest_data=$(echo "$DECRYPTED_DATA" | jq -c ".secrets[$idx].versions[$v].data // null")
      [[ "$latest_data" != "null" ]] && break
    done

    if [[ -z "$latest_data" || "$latest_data" == "null" ]]; then
      log WARN "No valid version data for ${target_path}, skipping"
      SKIP_COUNT=$((SKIP_COUNT + 1))
      return 0
    fi

    if [[ -n "$DRY_RUN" ]]; then
      log DRY "Would write: ${MOUNT}/${target_path} (latest version only)"
      [[ "$path" != "$target_path" ]] && log DRY "  (remapped from ${path})"
      IMPORT_COUNT=$((IMPORT_COUNT + 1))
      return 0
    fi

    local kv_args=()
    while IFS= read -r key; do
      local val
      val=$(echo "$latest_data" | jq -r --arg k "$key" '.[$k] // empty')
      kv_args+=("${key}=${val}")
    done < <(echo "$latest_data" | jq -r 'keys[]')

    if vault kv put "${MOUNT}/${target_path}" "${kv_args[@]}" >/dev/null 2>&1; then
      log OK "Imported: ${MOUNT}/${target_path}"
      IMPORT_COUNT=$((IMPORT_COUNT + 1))
    else
      log ERROR "Failed to write: ${MOUNT}/${target_path}"
      ERROR_COUNT=$((ERROR_COUNT + 1))
    fi
  fi

  # Restore custom metadata if present
  local custom_meta
  custom_meta=$(echo "$DECRYPTED_DATA" | jq -c ".secrets[$idx].metadata.custom_metadata // null")
  if [[ "$custom_meta" != "null" && "$custom_meta" != "{}" ]]; then
    if [[ -n "$DRY_RUN" ]]; then
      log DRY "Would set custom metadata on ${MOUNT}/${target_path}"
    else
      local meta_args=()
      while IFS= read -r key; do
        local val
        val=$(echo "$custom_meta" | jq -r --arg k "$key" '.[$k] // empty')
        meta_args+=("custom_metadata=${key}=${val}")
      done < <(echo "$custom_meta" | jq -r 'keys[]')

      vault kv metadata put "${MOUNT}/${target_path}" "${meta_args[@]}" >/dev/null 2>&1 \
        || log WARN "Failed to set custom metadata on ${target_path}"
    fi
  fi
}

# ── Import orchestration ─────────────────────────────────────────────────

main() {
  log STEP "Vault KV Import"
  [[ -n "$DRY_RUN" ]] && log INFO "Mode: dry-run (no changes will be made)"
  [[ -n "$PRESERVE_VERSIONS" ]] && log INFO "Version preservation: enabled"

  # Validate target Vault is accessible
  if ! vault status >/dev/null 2>&1; then
    die "Cannot connect to Vault at ${VAULT_ADDR}"
  fi
  log OK "Target Vault is accessible"

  # Check target mount exists
  if ! vault secrets list -format=json 2>/dev/null | jq -e ".\"${MOUNT}/\"" >/dev/null 2>&1; then
    if [[ -n "$DRY_RUN" ]]; then
      log WARN "Target mount '${MOUNT}' does not exist (would need to be created)"
    else
      die "Target mount '${MOUNT}' does not exist. Create it first with: vault secrets enable -path=${MOUNT} kv-v2"
    fi
  fi

  log STEP "Importing secrets"

  for ((i = 0; i < SECRET_COUNT; i++)); do
    local kv_ver
    kv_ver=$(echo "$DECRYPTED_DATA" | jq -r ".secrets[$i].kv_version // ${SOURCE_KV}")

    if [[ "$kv_ver" == "1" ]]; then
      import_secret_v1 "$i"
    else
      import_secret_v2 "$i"
    fi
  done

  log STEP "Import summary"
  log OK "Imported: ${IMPORT_COUNT}"
  [[ "$REMAP_COUNT" -gt 0 ]] && log INFO "Remapped: ${REMAP_COUNT} path(s)"
  [[ "$SKIP_COUNT" -gt 0 ]] && log INFO "Skipped: ${SKIP_COUNT}"
  [[ "$ERROR_COUNT" -gt 0 ]] && log WARN "Errors: ${ERROR_COUNT}"

  if [[ "$ERROR_COUNT" -gt 0 ]]; then
    exit 1
  fi
}

main
