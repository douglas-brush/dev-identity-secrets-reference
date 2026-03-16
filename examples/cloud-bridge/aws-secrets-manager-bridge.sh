#!/usr/bin/env bash
# aws-secrets-manager-bridge.sh — Sync secrets between HashiCorp Vault and AWS Secrets Manager
#
# Reference implementation for bidirectional secret synchronization between
# Vault KV v2 and AWS Secrets Manager (ASM). Supports conflict resolution
# policies (vault-wins, aws-wins, newest-wins), dry-run mode, and mapping
# files that declare which Vault paths correspond to which ASM secret names.
#
# Prerequisites:
#   - aws CLI v2 in PATH
#   - vault CLI in PATH, VAULT_ADDR / VAULT_TOKEN set
#   - jq in PATH
#
# Usage:
#   ./aws-secrets-manager-bridge.sh \
#       --direction vault-to-aws \
#       --mapping-file mappings.yaml \
#       --dry-run
#
#   ./aws-secrets-manager-bridge.sh \
#       --direction bidirectional \
#       --mapping-file mappings.yaml \
#       --conflict-policy newest-wins \
#       --notify-webhook https://hooks.slack.com/...

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly TIMESTAMP

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DIRECTION=""
MAPPING_FILE=""
CONFLICT_POLICY="vault-wins"  # vault-wins | aws-wins | newest-wins
DRY_RUN=""
NOTIFY_WEBHOOK=""
AWS_REGION="${AWS_REGION:-us-east-1}"
VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-secret}"
LOG_FILE="/tmp/aws-bridge-${TIMESTAMP//[:.]/-}.log"
SYNC_COUNT=0
SKIP_COUNT=0
ERROR_COUNT=0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log()   { printf '[%s] %s %s\n' "${SCRIPT_NAME}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "${LOG_FILE}" >&2; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*"; }
err()   { log "ERROR $*"; }

# ---------------------------------------------------------------------------
# Color helpers (for terminal output)
# ---------------------------------------------------------------------------

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
$(_bold 'aws-secrets-manager-bridge.sh') — Vault <-> AWS Secrets Manager Sync

$(_bold 'USAGE')
  ${SCRIPT_NAME} [OPTIONS]

$(_bold 'REQUIRED')
  --direction DIR        Sync direction: vault-to-aws | aws-to-vault | bidirectional
  --mapping-file FILE    YAML/JSON file mapping Vault paths to ASM secret names

$(_bold 'OPTIONS')
  --conflict-policy POL  Conflict resolution: vault-wins (default) | aws-wins | newest-wins
  --aws-region REGION    AWS region (default: \$AWS_REGION or us-east-1)
  --vault-mount MOUNT    Vault KV v2 mount path (default: secret)
  --notify-webhook URL   Webhook URL for sync notifications (Slack-compatible)
  --dry-run              Show what would be synced without making changes
  --no-color             Disable colored output
  --help                 Show this help message

$(_bold 'ENVIRONMENT')
  VAULT_ADDR             Vault server address
  VAULT_TOKEN            Vault authentication token
  AWS_REGION             AWS region (overridden by --aws-region)
  AWS_PROFILE            AWS CLI profile
  VAULT_KV_MOUNT         Vault KV mount (overridden by --vault-mount)

$(_bold 'MAPPING FILE FORMAT') (YAML)
  mappings:
    - vault_path: "secret/data/myapp/database"
      asm_name: "prod/myapp/db-credentials"
      sync: true
      rotation_days: 30
    - vault_path: "secret/data/myapp/api-keys"
      asm_name: "prod/myapp/api-keys"
      sync: true

$(_bold 'EXAMPLES')
  # One-way sync from Vault to AWS (dry run)
  ${SCRIPT_NAME} --direction vault-to-aws --mapping-file map.yaml --dry-run

  # Bidirectional sync with newest-wins conflict policy
  ${SCRIPT_NAME} --direction bidirectional --mapping-file map.yaml \\
      --conflict-policy newest-wins

EOF
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_deps() {
    local missing=()
    for cmd in vault aws jq; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing required tools: ${missing[*]}"
        exit 1
    fi

    # Validate Vault connectivity
    if ! vault status &>/dev/null; then
        err "Cannot reach Vault at ${VAULT_ADDR:-<unset>}. Check VAULT_ADDR and VAULT_TOKEN."
        exit 1
    fi

    # Validate AWS connectivity
    if ! aws sts get-caller-identity --region "${AWS_REGION}" &>/dev/null; then
        err "Cannot authenticate to AWS. Check credentials and region (${AWS_REGION})."
        exit 1
    fi

    info "Dependencies OK — Vault: ${VAULT_ADDR:-<unset>}, AWS region: ${AWS_REGION}"
}

# ---------------------------------------------------------------------------
# Mapping file parser
# ---------------------------------------------------------------------------
# Supports both YAML (via yq or python fallback) and JSON mapping files.
# Returns JSON array of mapping objects on stdout.

parse_mappings() {
    local file="$1"
    if [[ ! -f "${file}" ]]; then
        err "Mapping file not found: ${file}"
        exit 1
    fi

    case "${file}" in
        *.yaml|*.yml)
            # Try yq first, fall back to Python
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
            err "Unsupported mapping file format: ${file} (use .yaml, .yml, or .json)"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

# Read a secret from Vault KV v2, returning the data payload as JSON.
vault_read_secret() {
    local path="$1"
    vault kv get -format=json -mount="${VAULT_KV_MOUNT}" "${path}" 2>/dev/null
}

# Get the last-updated timestamp from Vault KV v2 metadata.
vault_get_updated_time() {
    local path="$1"
    vault kv metadata get -format=json -mount="${VAULT_KV_MOUNT}" "${path}" 2>/dev/null \
        | jq -r '.data.updated_time // empty'
}

# Write a secret to Vault KV v2.
vault_write_secret() {
    local path="$1"
    local data="$2"  # JSON string
    echo "${data}" | vault kv put -mount="${VAULT_KV_MOUNT}" "${path}" -
}

# ---------------------------------------------------------------------------
# AWS Secrets Manager helpers
# ---------------------------------------------------------------------------

# Read a secret from ASM, returning the full JSON response.
asm_read_secret() {
    local name="$1"
    aws secretsmanager get-secret-value \
        --secret-id "${name}" \
        --region "${AWS_REGION}" \
        --output json 2>/dev/null
}

# Get the last-modified date from ASM (ISO 8601).
asm_get_updated_time() {
    local name="$1"
    aws secretsmanager describe-secret \
        --secret-id "${name}" \
        --region "${AWS_REGION}" \
        --output json 2>/dev/null \
        | jq -r '.LastChangedDate // .CreatedDate // empty'
}

# Create or update a secret in ASM. Creates if the secret does not exist.
asm_write_secret() {
    local name="$1"
    local value="$2"  # plaintext string or JSON

    if aws secretsmanager describe-secret --secret-id "${name}" --region "${AWS_REGION}" &>/dev/null; then
        aws secretsmanager put-secret-value \
            --secret-id "${name}" \
            --secret-string "${value}" \
            --region "${AWS_REGION}" \
            --output json
    else
        aws secretsmanager create-secret \
            --name "${name}" \
            --secret-string "${value}" \
            --region "${AWS_REGION}" \
            --output json
    fi
}

# Configure rotation on an ASM secret.
asm_configure_rotation() {
    local name="$1"
    local rotation_days="$2"
    local rotation_lambda="${3:-}"

    if [[ -z "${rotation_lambda}" ]]; then
        warn "No rotation Lambda ARN provided for ${name} — skipping rotation config"
        return 0
    fi

    aws secretsmanager rotate-secret \
        --secret-id "${name}" \
        --rotation-lambda-arn "${rotation_lambda}" \
        --rotation-rules "{\"AutomaticallyAfterDays\": ${rotation_days}}" \
        --region "${AWS_REGION}" \
        --output json
}

# ---------------------------------------------------------------------------
# Conflict resolution
# ---------------------------------------------------------------------------
# Compares timestamps from Vault and ASM and returns the winner based on
# the configured conflict policy.
#
# Returns: "vault" | "aws" | "skip" (if identical)

resolve_conflict() {
    local vault_time="$1"
    local aws_time="$2"
    local policy="${CONFLICT_POLICY}"

    # If either side has no timestamp, the other side wins
    if [[ -z "${vault_time}" ]]; then
        echo "aws"
        return
    fi
    if [[ -z "${aws_time}" ]]; then
        echo "vault"
        return
    fi

    case "${policy}" in
        vault-wins)
            echo "vault"
            ;;
        aws-wins)
            echo "aws"
            ;;
        newest-wins)
            # Compare ISO timestamps lexicographically (works for ISO 8601)
            if [[ "${vault_time}" > "${aws_time}" ]]; then
                echo "vault"
            elif [[ "${aws_time}" > "${vault_time}" ]]; then
                echo "aws"
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

# Sync a single secret from Vault to AWS Secrets Manager.
sync_vault_to_aws() {
    local vault_path="$1"
    local asm_name="$2"
    local rotation_days="${3:-0}"

    info "Syncing Vault → AWS: ${vault_path} → ${asm_name}"

    local vault_data
    vault_data="$(vault_read_secret "${vault_path}")" || {
        warn "Cannot read Vault secret: ${vault_path} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    }

    # Extract the data payload (KV v2 nests under .data.data)
    local secret_value
    secret_value="$(echo "${vault_data}" | jq -c '.data.data')"

    if [[ -n "${DRY_RUN}" ]]; then
        info "[DRY RUN] Would write to ASM: ${asm_name} ($(echo "${secret_value}" | wc -c | tr -d ' ') bytes)"
        return 0
    fi

    asm_write_secret "${asm_name}" "${secret_value}" || {
        err "Failed to write ASM secret: ${asm_name}"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        return 1
    }

    # Configure rotation if specified
    if [[ "${rotation_days}" -gt 0 ]]; then
        info "Configuring ${rotation_days}-day rotation on ${asm_name}"
        asm_configure_rotation "${asm_name}" "${rotation_days}" || true
    fi

    SYNC_COUNT=$((SYNC_COUNT + 1))
    info "$(_green 'OK') Synced ${vault_path} → ${asm_name}"
}

# Sync a single secret from AWS Secrets Manager to Vault.
sync_aws_to_vault() {
    local asm_name="$1"
    local vault_path="$2"

    info "Syncing AWS → Vault: ${asm_name} → ${vault_path}"

    local asm_data
    asm_data="$(asm_read_secret "${asm_name}")" || {
        warn "Cannot read ASM secret: ${asm_name} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    }

    local secret_value
    secret_value="$(echo "${asm_data}" | jq -r '.SecretString')"

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
    info "$(_green 'OK') Synced ${asm_name} → ${vault_path}"
}

# Bidirectional sync with conflict resolution.
sync_bidirectional() {
    local vault_path="$1"
    local asm_name="$2"
    local rotation_days="${3:-0}"

    info "Bidirectional sync: ${vault_path} <-> ${asm_name} (policy: ${CONFLICT_POLICY})"

    local vault_time asm_time winner
    vault_time="$(vault_get_updated_time "${vault_path}" || true)"
    asm_time="$(asm_get_updated_time "${asm_name}" || true)"

    # If one side doesn't exist, sync from the side that does
    if [[ -z "${vault_time}" && -z "${asm_time}" ]]; then
        warn "Neither side exists for ${vault_path} / ${asm_name} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    fi

    winner="$(resolve_conflict "${vault_time}" "${asm_time}")"

    case "${winner}" in
        vault)
            info "Conflict winner: Vault (${vault_time} vs ${asm_time:-<missing>})"
            sync_vault_to_aws "${vault_path}" "${asm_name}" "${rotation_days}"
            ;;
        aws)
            info "Conflict winner: AWS (${asm_time} vs ${vault_time:-<missing>})"
            sync_aws_to_vault "${asm_name}" "${vault_path}"
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
    if [[ -z "${NOTIFY_WEBHOOK}" ]]; then
        return 0
    fi

    local payload
    payload=$(jq -n \
        --arg status "${status}" \
        --arg direction "${DIRECTION}" \
        --argjson synced "${SYNC_COUNT}" \
        --argjson skipped "${SKIP_COUNT}" \
        --argjson errors "${ERROR_COUNT}" \
        --arg timestamp "${TIMESTAMP}" \
        '{
            text: "AWS Secrets Bridge \($status): direction=\($direction), synced=\($synced), skipped=\($skipped), errors=\($errors) at \($timestamp)"
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
            --direction)       DIRECTION="$2"; shift 2 ;;
            --mapping-file)    MAPPING_FILE="$2"; shift 2 ;;
            --conflict-policy) CONFLICT_POLICY="$2"; shift 2 ;;
            --aws-region)      AWS_REGION="$2"; shift 2 ;;
            --vault-mount)     VAULT_KV_MOUNT="$2"; shift 2 ;;
            --notify-webhook)  NOTIFY_WEBHOOK="$2"; shift 2 ;;
            --dry-run)         DRY_RUN=1; shift ;;
            --no-color)        NO_COLOR=1; shift ;;
            --help)            usage 0 ;;
            *)                 err "Unknown option: $1"; usage 1 ;;
        esac
    done
}

validate_args() {
    if [[ -z "${DIRECTION}" ]]; then
        err "Missing required option: --direction"
        usage 1
    fi
    if [[ ! "${DIRECTION}" =~ ^(vault-to-aws|aws-to-vault|bidirectional)$ ]]; then
        err "Invalid direction: ${DIRECTION} (must be vault-to-aws, aws-to-vault, or bidirectional)"
        exit 1
    fi
    if [[ -z "${MAPPING_FILE}" ]]; then
        err "Missing required option: --mapping-file"
        usage 1
    fi
    if [[ ! "${CONFLICT_POLICY}" =~ ^(vault-wins|aws-wins|newest-wins)$ ]]; then
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

    info "Starting sync: direction=${DIRECTION}, policy=${CONFLICT_POLICY}, mapping=${MAPPING_FILE}"

    # Parse the mapping file into a JSON array
    local mappings
    mappings="$(parse_mappings "${MAPPING_FILE}")"
    local mapping_count
    mapping_count="$(echo "${mappings}" | jq 'length')"
    info "Loaded ${mapping_count} mapping(s) from ${MAPPING_FILE}"

    # Iterate over each mapping entry
    local i=0
    while [[ ${i} -lt ${mapping_count} ]]; do
        local vault_path asm_name sync_enabled rotation_days
        vault_path="$(echo "${mappings}" | jq -r ".[${i}].vault_path")"
        asm_name="$(echo "${mappings}" | jq -r ".[${i}].asm_name")"
        sync_enabled="$(echo "${mappings}" | jq -r ".[${i}].sync // true")"
        rotation_days="$(echo "${mappings}" | jq -r ".[${i}].rotation_days // 0")"

        if [[ "${sync_enabled}" == "false" ]]; then
            info "Skipping disabled mapping: ${vault_path} <-> ${asm_name}"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            i=$((i + 1))
            continue
        fi

        # Strip the mount prefix from vault_path if the user included it
        # e.g., "secret/data/myapp/db" -> "myapp/db"
        vault_path="${vault_path#"${VAULT_KV_MOUNT}/data/"}"
        vault_path="${vault_path#"${VAULT_KV_MOUNT}/"}"

        case "${DIRECTION}" in
            vault-to-aws)   sync_vault_to_aws "${vault_path}" "${asm_name}" "${rotation_days}" ;;
            aws-to-vault)   sync_aws_to_vault "${asm_name}" "${vault_path}" ;;
            bidirectional)  sync_bidirectional "${vault_path}" "${asm_name}" "${rotation_days}" ;;
        esac

        i=$((i + 1))
    done

    # Summary
    echo ""
    info "$(_bold 'Sync complete')"
    info "  Synced:  ${SYNC_COUNT}"
    info "  Skipped: ${SKIP_COUNT}"
    info "  Errors:  ${ERROR_COUNT}"
    info "  Log:     ${LOG_FILE}"

    # Send notification
    local status="success"
    [[ ${ERROR_COUNT} -gt 0 ]] && status="partial-failure"
    send_notification "${status}"

    # Exit with error if any syncs failed
    [[ ${ERROR_COUNT} -gt 0 ]] && exit 1
    exit 0
}

main "$@"
