#!/usr/bin/env bash
# gcp-secret-manager-bridge.sh — Sync secrets between HashiCorp Vault and GCP Secret Manager
#
# Reference implementation for bidirectional secret synchronization between
# Vault KV v2 and GCP Secret Manager. Handles GCP's version-based model,
# IAM condition bindings for access control, conflict resolution policies,
# dry-run mode, and mapping files.
#
# Prerequisites:
#   - gcloud CLI in PATH, authenticated (gcloud auth application-default login)
#   - vault CLI in PATH, VAULT_ADDR / VAULT_TOKEN set
#   - jq in PATH
#
# Usage:
#   ./gcp-secret-manager-bridge.sh \
#       --direction vault-to-gcp \
#       --mapping-file mappings.yaml \
#       --gcp-project my-project-id \
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
CONFLICT_POLICY="vault-wins"  # vault-wins | gcp-wins | newest-wins
DRY_RUN=""
NOTIFY_WEBHOOK=""
GCP_PROJECT="${GCP_PROJECT:-}"
VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-secret}"
LOG_FILE="/tmp/gcp-bridge-${TIMESTAMP//[:.]/-}.log"
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
$(_bold 'gcp-secret-manager-bridge.sh') — Vault <-> GCP Secret Manager Sync

$(_bold 'USAGE')
  ${SCRIPT_NAME} [OPTIONS]

$(_bold 'REQUIRED')
  --direction DIR        Sync direction: vault-to-gcp | gcp-to-vault | bidirectional
  --mapping-file FILE    YAML/JSON file mapping Vault paths to GCP secret names
  --gcp-project ID       GCP project ID (or set GCP_PROJECT)

$(_bold 'OPTIONS')
  --conflict-policy POL  Conflict resolution: vault-wins (default) | gcp-wins | newest-wins
  --vault-mount MOUNT    Vault KV v2 mount path (default: secret)
  --notify-webhook URL   Webhook URL for sync notifications (Slack-compatible)
  --dry-run              Show what would be synced without making changes
  --no-color             Disable colored output
  --help                 Show this help message

$(_bold 'GCP SECRET MANAGER NOTES')
  GCP Secret Manager uses a two-level model:
  - A "secret" is the top-level resource (holds metadata, IAM policies, labels)
  - A "secret version" holds the actual payload (immutable, can be enabled/disabled/destroyed)

  This bridge:
  - Always reads the latest enabled version
  - Writes create a new version (old versions are preserved)
  - Can apply IAM condition bindings for time-limited or attribute-based access
  - Labels are synced from the mapping file

$(_bold 'MAPPING FILE FORMAT') (YAML)
  mappings:
    - vault_path: "myapp/database"
      gcp_name: "myapp-database-credentials"
      sync: true
      labels:
        environment: production
        team: platform
      iam_conditions:
        - role: "roles/secretmanager.secretAccessor"
          member: "serviceAccount:myapp@project.iam.gserviceaccount.com"
          condition:
            title: "expires-2024"
            expression: "request.time < timestamp('2024-12-31T23:59:59Z')"

$(_bold 'EXAMPLES')
  # One-way sync from Vault to GCP (dry run)
  ${SCRIPT_NAME} --direction vault-to-gcp --mapping-file map.yaml \\
      --gcp-project my-project --dry-run

  # Bidirectional sync with newest-wins
  ${SCRIPT_NAME} --direction bidirectional --mapping-file map.yaml \\
      --gcp-project my-project --conflict-policy newest-wins

EOF
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_deps() {
    local missing=()
    for cmd in vault gcloud jq; do
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

    if ! gcloud auth print-access-token &>/dev/null; then
        err "Not authenticated to GCP. Run 'gcloud auth application-default login'."
        exit 1
    fi

    if [[ -z "${GCP_PROJECT}" ]]; then
        err "GCP project not set. Use --gcp-project or set GCP_PROJECT."
        exit 1
    fi

    # Verify the project is accessible and Secret Manager API is enabled
    if ! gcloud secrets list --project="${GCP_PROJECT}" --limit=1 &>/dev/null; then
        err "Cannot access GCP Secret Manager in project: ${GCP_PROJECT}"
        err "Ensure the Secret Manager API is enabled: gcloud services enable secretmanager.googleapis.com"
        exit 1
    fi

    info "Dependencies OK — Vault: ${VAULT_ADDR:-<unset>}, GCP project: ${GCP_PROJECT}"
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
# GCP Secret Manager helpers
# ---------------------------------------------------------------------------

# Check if a GCP secret (top-level resource) exists.
gcp_secret_exists() {
    local name="$1"
    gcloud secrets describe "${name}" --project="${GCP_PROJECT}" &>/dev/null
}

# Create the top-level GCP secret resource (without a version).
gcp_create_secret() {
    local name="$1"
    local labels="${2:-}"

    local label_args=""
    if [[ -n "${labels}" && "${labels}" != "null" ]]; then
        # Convert JSON labels to gcloud format: key=value,key2=value2
        label_args="$(echo "${labels}" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")')"
    fi

    if [[ -n "${label_args}" ]]; then
        gcloud secrets create "${name}" \
            --project="${GCP_PROJECT}" \
            --labels="${label_args}" \
            --replication-policy="automatic" \
            --format=json 2>/dev/null
    else
        gcloud secrets create "${name}" \
            --project="${GCP_PROJECT}" \
            --replication-policy="automatic" \
            --format=json 2>/dev/null
    fi
}

# Read the latest enabled version of a GCP secret.
gcp_read_secret() {
    local name="$1"
    gcloud secrets versions access latest \
        --secret="${name}" \
        --project="${GCP_PROJECT}" 2>/dev/null
}

# Get the creation time of the latest version (used for conflict resolution).
gcp_get_updated_time() {
    local name="$1"
    gcloud secrets versions list "${name}" \
        --project="${GCP_PROJECT}" \
        --filter="state=ENABLED" \
        --sort-by="~createTime" \
        --limit=1 \
        --format="value(createTime)" 2>/dev/null
}

# Add a new secret version to GCP Secret Manager.
gcp_write_secret_version() {
    local name="$1"
    local value="$2"

    # Create the secret resource if it doesn't exist
    if ! gcp_secret_exists "${name}"; then
        info "  Creating GCP secret resource: ${name}"
        gcp_create_secret "${name}" || {
            err "Failed to create GCP secret: ${name}"
            return 1
        }
    fi

    # Add a new version
    local version_info
    version_info="$(echo -n "${value}" | gcloud secrets versions add "${name}" \
        --project="${GCP_PROJECT}" \
        --data-file=- \
        --format=json 2>/dev/null)"

    local version_name
    version_name="$(echo "${version_info}" | jq -r '.name' | awk -F'/' '{print $NF}')"
    info "  GCP Secret Manager version created: ${version_name}"

    echo "${version_info}"
}

# Update labels on a GCP secret.
gcp_set_labels() {
    local name="$1"
    local labels_json="$2"

    if [[ -z "${labels_json}" || "${labels_json}" == "null" ]]; then
        return 0
    fi

    local label_args
    label_args="$(echo "${labels_json}" | jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")')"

    if [[ -n "${label_args}" ]]; then
        gcloud secrets update "${name}" \
            --project="${GCP_PROJECT}" \
            --update-labels="${label_args}" \
            --format=json &>/dev/null || \
            warn "Failed to set labels on ${name}"
    fi
}

# Apply IAM condition bindings to a GCP secret.
# IAM conditions allow time-bounded or attribute-based access — a key GCP
# differentiator for secrets access control.
gcp_apply_iam_conditions() {
    local name="$1"
    local iam_conditions_json="$2"  # JSON array of condition bindings

    if [[ -z "${iam_conditions_json}" || "${iam_conditions_json}" == "null" ]]; then
        return 0
    fi

    local count
    count="$(echo "${iam_conditions_json}" | jq 'length')"

    local j=0
    while [[ ${j} -lt ${count} ]]; do
        local role member cond_title cond_expression
        role="$(echo "${iam_conditions_json}" | jq -r ".[${j}].role")"
        member="$(echo "${iam_conditions_json}" | jq -r ".[${j}].member")"
        cond_title="$(echo "${iam_conditions_json}" | jq -r ".[${j}].condition.title // empty")"
        cond_expression="$(echo "${iam_conditions_json}" | jq -r ".[${j}].condition.expression // empty")"

        info "  Applying IAM binding: ${role} -> ${member}"

        if [[ -n "${cond_title}" && -n "${cond_expression}" ]]; then
            gcloud secrets add-iam-policy-binding "${name}" \
                --project="${GCP_PROJECT}" \
                --role="${role}" \
                --member="${member}" \
                --condition="title=${cond_title},expression=${cond_expression}" \
                --format=json &>/dev/null || \
                warn "Failed to apply IAM condition for ${member} on ${name}"
        else
            gcloud secrets add-iam-policy-binding "${name}" \
                --project="${GCP_PROJECT}" \
                --role="${role}" \
                --member="${member}" \
                --format=json &>/dev/null || \
                warn "Failed to apply IAM binding for ${member} on ${name}"
        fi

        j=$((j + 1))
    done
}

# ---------------------------------------------------------------------------
# Conflict resolution
# ---------------------------------------------------------------------------

resolve_conflict() {
    local vault_time="$1"
    local gcp_time="$2"
    local policy="${CONFLICT_POLICY}"

    if [[ -z "${vault_time}" ]]; then echo "gcp"; return; fi
    if [[ -z "${gcp_time}" ]]; then echo "vault"; return; fi

    case "${policy}" in
        vault-wins)  echo "vault" ;;
        gcp-wins)    echo "gcp" ;;
        newest-wins)
            if [[ "${vault_time}" > "${gcp_time}" ]]; then
                echo "vault"
            elif [[ "${gcp_time}" > "${vault_time}" ]]; then
                echo "gcp"
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

sync_vault_to_gcp() {
    local vault_path="$1"
    local gcp_name="$2"
    local labels_json="${3:-}"
    local iam_conditions_json="${4:-}"

    info "Syncing Vault → GCP: ${vault_path} → ${gcp_name}"

    local vault_data
    vault_data="$(vault_read_secret "${vault_path}")" || {
        warn "Cannot read Vault secret: ${vault_path} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    }

    local secret_value
    secret_value="$(echo "${vault_data}" | jq -c '.data.data')"

    if [[ -n "${DRY_RUN}" ]]; then
        info "[DRY RUN] Would write to GCP: ${gcp_name} ($(echo "${secret_value}" | wc -c | tr -d ' ') bytes)"
        return 0
    fi

    gcp_write_secret_version "${gcp_name}" "${secret_value}" || {
        err "Failed to write GCP secret: ${gcp_name}"
        ERROR_COUNT=$((ERROR_COUNT + 1))
        return 1
    }

    # Apply labels and IAM conditions
    gcp_set_labels "${gcp_name}" "${labels_json}"
    gcp_apply_iam_conditions "${gcp_name}" "${iam_conditions_json}"

    SYNC_COUNT=$((SYNC_COUNT + 1))
    info "$(_green 'OK') Synced ${vault_path} → ${gcp_name}"
}

sync_gcp_to_vault() {
    local gcp_name="$1"
    local vault_path="$2"

    info "Syncing GCP → Vault: ${gcp_name} → ${vault_path}"

    local secret_value
    secret_value="$(gcp_read_secret "${gcp_name}")" || {
        warn "Cannot read GCP secret: ${gcp_name} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    }

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
    info "$(_green 'OK') Synced ${gcp_name} → ${vault_path}"
}

sync_bidirectional() {
    local vault_path="$1"
    local gcp_name="$2"
    local labels_json="${3:-}"
    local iam_conditions_json="${4:-}"

    info "Bidirectional sync: ${vault_path} <-> ${gcp_name} (policy: ${CONFLICT_POLICY})"

    local vault_time gcp_time winner
    vault_time="$(vault_get_updated_time "${vault_path}" || true)"
    gcp_time="$(gcp_get_updated_time "${gcp_name}" || true)"

    if [[ -z "${vault_time}" && -z "${gcp_time}" ]]; then
        warn "Neither side exists for ${vault_path} / ${gcp_name} — skipping"
        SKIP_COUNT=$((SKIP_COUNT + 1))
        return 0
    fi

    winner="$(resolve_conflict "${vault_time}" "${gcp_time}")"

    case "${winner}" in
        vault)
            info "Conflict winner: Vault (${vault_time} vs ${gcp_time:-<missing>})"
            sync_vault_to_gcp "${vault_path}" "${gcp_name}" "${labels_json}" "${iam_conditions_json}"
            ;;
        gcp)
            info "Conflict winner: GCP (${gcp_time} vs ${vault_time:-<missing>})"
            sync_gcp_to_vault "${gcp_name}" "${vault_path}"
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
            text: "GCP SM Bridge \($status): direction=\($direction), synced=\($synced), skipped=\($skipped), errors=\($errors) at \($timestamp)"
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
            --gcp-project)     GCP_PROJECT="$2"; shift 2 ;;
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
    if [[ ! "${DIRECTION}" =~ ^(vault-to-gcp|gcp-to-vault|bidirectional)$ ]]; then
        err "Invalid direction: ${DIRECTION}"
        exit 1
    fi
    if [[ -z "${MAPPING_FILE}" ]]; then
        err "Missing required option: --mapping-file"
        usage 1
    fi
    if [[ ! "${CONFLICT_POLICY}" =~ ^(vault-wins|gcp-wins|newest-wins)$ ]]; then
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

    info "Starting sync: direction=${DIRECTION}, policy=${CONFLICT_POLICY}, project=${GCP_PROJECT}"

    local mappings
    mappings="$(parse_mappings "${MAPPING_FILE}")"
    local mapping_count
    mapping_count="$(echo "${mappings}" | jq 'length')"
    info "Loaded ${mapping_count} mapping(s) from ${MAPPING_FILE}"

    local i=0
    while [[ ${i} -lt ${mapping_count} ]]; do
        local vault_path gcp_name sync_enabled labels_json iam_conditions_json
        vault_path="$(echo "${mappings}" | jq -r ".[${i}].vault_path")"
        gcp_name="$(echo "${mappings}" | jq -r ".[${i}].gcp_name")"
        sync_enabled="$(echo "${mappings}" | jq -r ".[${i}].sync // true")"
        labels_json="$(echo "${mappings}" | jq -c ".[${i}].labels // null")"
        iam_conditions_json="$(echo "${mappings}" | jq -c ".[${i}].iam_conditions // null")"

        if [[ "${sync_enabled}" == "false" ]]; then
            info "Skipping disabled mapping: ${vault_path} <-> ${gcp_name}"
            SKIP_COUNT=$((SKIP_COUNT + 1))
            i=$((i + 1))
            continue
        fi

        vault_path="${vault_path#"${VAULT_KV_MOUNT}/data/"}"
        vault_path="${vault_path#"${VAULT_KV_MOUNT}/"}"

        case "${DIRECTION}" in
            vault-to-gcp)  sync_vault_to_gcp "${vault_path}" "${gcp_name}" "${labels_json}" "${iam_conditions_json}" ;;
            gcp-to-vault)  sync_gcp_to_vault "${gcp_name}" "${vault_path}" ;;
            bidirectional) sync_bidirectional "${vault_path}" "${gcp_name}" "${labels_json}" "${iam_conditions_json}" ;;
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
