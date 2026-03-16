#!/usr/bin/env bash
# azure-keyvault-bridge.sh — Sync secrets between HashiCorp Vault and Azure Key Vault
#
# Reference implementation for bidirectional secret synchronization between
# Vault KV v2 and Azure Key Vault. Handles Azure KV versioning (each write
# creates a new immutable version), conflict resolution policies, dry-run
# mode, and mapping files.
#
# Prerequisites:
#   - az CLI in PATH, authenticated (az login)
#   - vault CLI in PATH, VAULT_ADDR / VAULT_TOKEN set
#   - jq in PATH
#
# Usage:
#   ./azure-keyvault-bridge.sh \
#       --direction vault-to-azure \
#       --mapping-file mappings.yaml \
#       --dry-run

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR; export SCRIPT_DIR
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DIRECTION=""
MAPPING_FILE=""
CONFLICT_POLICY="vault-wins"  # vault-wins | azure-wins | newest-wins
DRY_RUN=""
NOTIFY_WEBHOOK=""
AZURE_VAULT_NAME="${AZURE_VAULT_NAME:-}"
VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-secret}"
LOG_FILE="/tmp/azure-bridge-${TIMESTAMP//[:.]/-}.log"
SYNC_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

# ---------------------------------------------------------------------------
# Logging & colors
# ---------------------------------------------------------------------------

log()   { printf '[%s] %s %s\n' "${SCRIPT_NAME}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "${LOG_FILE}" >&2; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*"; }
err()   { log "ERROR $*"; }

NO_COLOR="${NO_COLOR:-}"
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
$(_bold 'azure-keyvault-bridge.sh') — Vault <-> Azure Key Vault Sync

$(_bold 'USAGE')
  ${SCRIPT_NAME} [OPTIONS]

$(_bold 'REQUIRED')
  --direction DIR           Sync direction: vault-to-azure | azure-to-vault | bidirectional
  --mapping-file FILE       YAML/JSON file mapping Vault paths to AKV secret names
  --azure-vault-name NAME   Azure Key Vault name (or set AZURE_VAULT_NAME)

$(_bold 'OPTIONS')
  --conflict-policy POL     Conflict resolution: vault-wins (default) | azure-wins | newest-wins
  --vault-mount MOUNT       Vault KV v2 mount path (default: secret)
  --notify-webhook URL      Webhook URL for sync notifications (Slack-compatible)
  --dry-run                 Show what would be synced without making changes
  --no-color                Disable colored output
  --help                    Show this help message

$(_bold 'AZURE KEY VAULT VERSIONING')
  Azure Key Vault creates immutable versions on every write. This bridge:
  - Always reads the latest (current) version
  - Writes create a new version (old versions are preserved)
  - The version ID is logged for audit purposes
  - Soft-deleted secrets are not synced (use az keyvault secret recover first)

$(_bold 'MAPPING FILE FORMAT') (YAML)
  mappings:
    - vault_path: "myapp/database"
      akv_name: "myapp-database-credentials"
      sync: true
      content_type: "application/json"
    - vault_path: "myapp/api-keys"
      akv_name: "myapp-api-keys"
      sync: true
      tags:
        environment: production
        team: platform

$(_bold 'EXAMPLES')
  # One-way sync from Vault to Azure (dry run)
  ${SCRIPT_NAME} --direction vault-to-azure --mapping-file map.yaml \\
      --azure-vault-name my-kv --dry-run

  # Bidirectional sync with newest-wins
  ${SCRIPT_NAME} --direction bidirectional --mapping-file map.yaml \\
      --azure-vault-name my-kv --conflict-policy newest-wins

EOF
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_deps() {
    local missing=()
    for cmd in vault az jq; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required tools: ${missing[*]}"
        exit 1
    fi

    if ! vault status &>/dev/null; then
        err "Cannot reach Vault at ${VAULT_ADDR:-<unset>}. Check VAULT_ADDR and VAULT_TOKEN."
        exit 1
    fi

    if ! az account show &>/dev/null; then
        err "Not authenticated to Azure. Run 'az login' first."
        exit 1
    fi

    if [[ -z "${AZURE_VAULT_NAME}" ]]; then
        err "Azure Key Vault name not set. Use --azure-vault-name or AZURE_VAULT_NAME."
        exit 1
    fi

    # Verify the Azure Key Vault is accessible
    if ! az keyvault show --name "${AZURE_VAULT_NAME}" &>/dev/null; then
        err "Cannot access Azure Key Vault: ${AZURE_VAULT_NAME}"
        exit 1
    fi

    info "Dependencies OK — Vault: ${VAULT_ADDR:-<unset>}, AKV: ${AZURE_VAULT_NAME}"
}

# ---------------------------------------------------------------------------
# Mapping file parser
# ---------------------------------------------------------------------------

parse_mappings() {
    local file="$1"
    if [[ ! -f "${file}" ]]; then
        err "Mapping file not found: ${file}"
        exit 1
    fi

    case "${file}" in
        *.yaml|*.yml)
            if command -v yq &>/dev/null; then
                yq -o=json '.mappings' "${file}"
            elif command -v python3 &>/dev/null; then
                python3 -c "
import sys, json, yaml
with open('${file}') as f:
    data = yaml.safe_load(f)
json.dump(data.get('mappings', []), sys.stdout)
"
            else
                err "No YAML parser available. Install yq or python3 with PyYAML."
                exit 1
            fi
            ;;
        *.json)
            jq '.mappings' "${file}"
            ;;
        *)
            err "Unsupported mapping file format: ${file}"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

vault_read_secret() {
    local path="$1"
    vault kv get -format=json -mount="${VAULT_KV_MOUNT}" "${path}" 2>/dev/null
}

vault_get_updated_time() {
    local path="$1"
    vault kv metadata get -format=json -mount="${VAULT_KV_MOUNT}" "${path}" 2>/dev/null \
        | jq -r '.data.updated_time // empty'
}

vault_write_secret() {
    local path="$1"
    local data="$2"
    echo "${data}" | vault kv put -mount="${VAULT_KV_MOUNT}" "${path}" -
}

# ---------------------------------------------------------------------------
# Azure Key Vault helpers
# ---------------------------------------------------------------------------

# Read the latest version of a secret from Azure Key Vault.
# Azure KV stores the secret value as a single string — when syncing
# structured data from Vault (JSON objects), we serialize as JSON.
akv_read_secret() {
    local name="$1"
    az keyvault secret show \
        --vault-name "${AZURE_VAULT_NAME}" \
        --name "${name}" \
        --output json 2>/dev/null
}

# Get the last-updated timestamp for an AKV secret.
# Azure returns the 'updated' field under 'attributes'.
akv_get_updated_time() {
    local name="$1"
    az keyvault secret show \
        --vault-name "${AZURE_VAULT_NAME}" \
        --name "${name}" \
        --output json 2>/dev/null \
        | jq -r '.attributes.updated // .attributes.created // empty'
}

# Write a secret to Azure Key Vault. Each write creates a new version.
# Returns the version ID for audit logging.
akv_write_secret() {
    local name="$1"
    local value="$2"
    local content_type="${3:-application/json}"

    local result
    result="$(az keyvault secret set \
        --vault-name "${AZURE_VAULT_NAME}" \
        --name "${name}" \
        --value "${value}" \
        --content-type "${content_type}" \
        --output json 2>/dev/null)"

    local version_id
    version_id="$(echo "${result}" | jq -r '.id' | awk -F'/' '{print $NF}')"
    info "  Azure KV version created: ${version_id}"

    echo "${result}"
}

# Apply tags to an AKV secret (optional metadata for organization).
akv_set_tags() {
    local name="$1"
    local tags_json="$2"  # JSON object of key-value pairs

    if [[ -z "${tags_json}" || "${tags_json}" == "null" ]]; then
        return 0
    fi

    # Convert JSON tags to az CLI format: key=value key2=value2
    local tag_args
    tag_args="$(echo "${tags_json}" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(" ")')"

    if [[ -n "${tag_args}" ]]; then
        # shellcheck disable=SC2086
        az keyvault secret set-attributes \
            --vault-name "${AZURE_VAULT_NAME}" \
            --name "${name}" \
            --tags ${tag_args} \
            --output json &>/dev/null || \
            warn "Failed to set tags on ${name}"
    fi
}

# ---------------------------------------------------------------------------
# Conflict resolution
# ---------------------------------------------------------------------------

resolve_conflict() {
    local vault_time="$1"
    local azure_time="$2"
    local policy="${CONFLICT_POLICY}"

    if [[ -z "${vault_time}" ]]; then echo "azure"; return; fi
    if [[ -z "${azure_time}" ]]; then echo "vault"; return; fi

    case "${policy}" in
        vault-wins)   echo "vault" ;;
        azure-wins)   echo "azure" ;;
        newest-wins)
            if [[ "${vault_time}" > "${azure_time}" ]]; then
                echo "vault"
            elif [[ "${azure_time}" > "${vault_time}" ]]; then
                echo "azure"
            else
                echo "skip"
            fi
            ;;
        *)
            err "Unknown conflict policy: ${policy}"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Sync operations
# ---------------------------------------------------------------------------

sync_vault_to_azure() {
    local vault_path="$1"
    local akv_name="$2"
    local content_type="${3:-application/json}"
    local tags_json="${4:-}"

    info "Syncing Vault → Azure: ${vault_path} → ${akv_name}"

    local vault_data
    vault_data="$(vault_read_secret "${vault_path}")" || {
        warn "Cannot read Vault secret: ${vault_path} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    }

    local secret_value
    secret_value="$(echo "${vault_data}" | jq -c '.data.data')"

    if [[ -n "${DRY_RUN}" ]]; then
        info "[DRY RUN] Would write to AKV: ${akv_name} ($(echo "${secret_value}" | wc -c | tr -d ' ') bytes)"
        return 0
    fi

    akv_write_secret "${akv_name}" "${secret_value}" "${content_type}" || {
        err "Failed to write AKV secret: ${akv_name}"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        return 1
    }

    # Apply tags if provided
    akv_set_tags "${akv_name}" "${tags_json}"

    SYNC_COUNT=$((SYNC_COUNT + 1))
    info "$(_green 'OK') Synced ${vault_path} → ${akv_name}"
}

sync_azure_to_vault() {
    local akv_name="$1"
    local vault_path="$2"

    info "Syncing Azure → Vault: ${akv_name} → ${vault_path}"

    local akv_data
    akv_data="$(akv_read_secret "${akv_name}")" || {
        warn "Cannot read AKV secret: ${akv_name} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    }

    local secret_value
    secret_value="$(echo "${akv_data}" | jq -r '.value')"

    if [[ -n "${DRY_RUN}" ]]; then
        info "[DRY RUN] Would write to Vault: ${vault_path} ($(echo "${secret_value}" | wc -c | tr -d ' ') bytes)"
        return 0
    fi

    vault_write_secret "${vault_path}" "${secret_value}" || {
        err "Failed to write Vault secret: ${vault_path}"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        return 1
    }

    SYNC_COUNT=$((SYNC_COUNT + 1))
    info "$(_green 'OK') Synced ${akv_name} → ${vault_path}"
}

sync_bidirectional() {
    local vault_path="$1"
    local akv_name="$2"
    local content_type="${3:-application/json}"
    local tags_json="${4:-}"

    info "Bidirectional sync: ${vault_path} <-> ${akv_name} (policy: ${CONFLICT_POLICY})"

    local vault_time azure_time winner
    vault_time="$(vault_get_updated_time "${vault_path}" || true)"
    azure_time="$(akv_get_updated_time "${akv_name}" || true)"

    if [[ -z "${vault_time}" && -z "${azure_time}" ]]; then
        warn "Neither side exists for ${vault_path} / ${akv_name} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    fi

    winner="$(resolve_conflict "${vault_time}" "${azure_time}")"

    case "${winner}" in
        vault)
            info "Conflict winner: Vault (${vault_time} vs ${azure_time:-<missing>})"
            sync_vault_to_azure "${vault_path}" "${akv_name}" "${content_type}" "${tags_json}"
            ;;
        azure)
            info "Conflict winner: Azure (${azure_time} vs ${vault_time:-<missing>})"
            sync_azure_to_vault "${akv_name}" "${vault_path}"
            ;;
        skip)
            info "Both sides identical (${vault_time}) — skipping"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------

send_notification() {
    local status="$1"
    if [[ -z "${NOTIFY_WEBHOOK}" ]]; then return 0; fi

    local payload
    payload=$(jq -n \
        --arg status "${status}" \
        --arg direction "${DIRECTION}" \
        --argjson synced "${SYNC_COUNT}" \
        --argjson skipped "${SKIP_COUNT}" \
        --argjson errors "${ERROR_COUNT}" \
        --arg timestamp "${TIMESTAMP}" \
        '{
            text: "Azure KV Bridge \($status): direction=\($direction), synced=\($synced), skipped=\($skipped), errors=\($errors) at \($timestamp)"
        }')

    curl -s -X POST -H "Content-Type: application/json" \
        -d "${payload}" "${NOTIFY_WEBHOOK}" >/dev/null || \
        warn "Failed to send webhook notification"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --direction)         DIRECTION="$2"; shift 2 ;;
            --mapping-file)      MAPPING_FILE="$2"; shift 2 ;;
            --conflict-policy)   CONFLICT_POLICY="$2"; shift 2 ;;
            --azure-vault-name)  AZURE_VAULT_NAME="$2"; shift 2 ;;
            --vault-mount)       VAULT_KV_MOUNT="$2"; shift 2 ;;
            --notify-webhook)    NOTIFY_WEBHOOK="$2"; shift 2 ;;
            --dry-run)           DRY_RUN=1; shift ;;
            --no-color)          NO_COLOR=1; shift ;;
            --help)              usage 0 ;;
            *)                   err "Unknown option: $1"; usage 1 ;;
        esac
    done
}

validate_args() {
    if [[ -z "${DIRECTION}" ]]; then
        err "Missing required option: --direction"
        usage 1
    fi
    if [[ ! "${DIRECTION}" =~ ^(vault-to-azure|azure-to-vault|bidirectional)$ ]]; then
        err "Invalid direction: ${DIRECTION}"
        exit 1
    fi
    if [[ -z "${MAPPING_FILE}" ]]; then
        err "Missing required option: --mapping-file"
        usage 1
    fi
    if [[ ! "${CONFLICT_POLICY}" =~ ^(vault-wins|azure-wins|newest-wins)$ ]]; then
        err "Invalid conflict policy: ${CONFLICT_POLICY}"
        exit 1
    fi
}

main() {
    parse_args "$@"
    validate_args

    if [[ -n "${DRY_RUN}" ]]; then
        info "$(_yellow '[DRY RUN MODE]') — no changes will be made"
    fi

    check_deps

    info "Starting sync: direction=${DIRECTION}, policy=${CONFLICT_POLICY}, akv=${AZURE_VAULT_NAME}"

    local mappings
    mappings="$(parse_mappings "${MAPPING_FILE}")"
    local mapping_count
    mapping_count="$(echo "${mappings}" | jq 'length')"
    info "Loaded ${mapping_count} mapping(s) from ${MAPPING_FILE}"

    local i=0
    while [[ ${i} -lt ${mapping_count} ]]; do
        local vault_path akv_name sync_enabled content_type tags_json
        vault_path="$(echo "${mappings}" | jq -r ".[${i}].vault_path")"
        akv_name="$(echo "${mappings}" | jq -r ".[${i}].akv_name")"
        sync_enabled="$(echo "${mappings}" | jq -r ".[${i}].sync // true")"
        content_type="$(echo "${mappings}" | jq -r ".[${i}].content_type // \"application/json\"")"
        tags_json="$(echo "${mappings}" | jq -c ".[${i}].tags // null")"

        if [[ "${sync_enabled}" == "false" ]]; then
            info "Skipping disabled mapping: ${vault_path} <-> ${akv_name}"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            i=$((i + 1))
            continue
        fi

        vault_path="${vault_path#"${VAULT_KV_MOUNT}/data/"}"
        vault_path="${vault_path#"${VAULT_KV_MOUNT}/"}"

        case "${DIRECTION}" in
            vault-to-azure)  sync_vault_to_azure "${vault_path}" "${akv_name}" "${content_type}" "${tags_json}" ;;
            azure-to-vault)  sync_azure_to_vault "${akv_name}" "${vault_path}" ;;
            bidirectional)   sync_bidirectional "${vault_path}" "${akv_name}" "${content_type}" "${tags_json}" ;;
        esac

        i=$((i + 1))
    done

    echo ""
    info "$(_bold 'Sync complete')"
    info "  Synced:  ${SYNC_COUNT}"
    info "  Skipped: ${SKIP_COUNT}"
    info "  Errors:  ${ERROR_COUNT}"
    info "  Log:     ${LOG_FILE}"

    local status="success"
    [[ ${ERROR_COUNT} -gt 0 ]] && status="partial-failure"
    send_notification "${status}"

    [[ ${ERROR_COUNT} -gt 0 ]] && exit 1
    exit 0
}

main "$@"
