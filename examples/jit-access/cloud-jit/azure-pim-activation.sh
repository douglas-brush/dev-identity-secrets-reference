#!/usr/bin/env bash
# azure-pim-activation.sh — Activate an Azure PIM (Privileged Identity
# Management) eligible role assignment.
#
# Uses the az CLI to activate a time-bounded PIM role, wait for activation,
# and schedule auto-deactivation. PIM roles are "eligible" (not active) by
# default — this script converts an eligible assignment to an active one
# for the specified duration.
#
# Prerequisites:
#   - az CLI in PATH, authenticated (az login)
#   - jq in PATH
#   - PIM eligible role assignment on the target scope
#
# Usage:
#   ./azure-pim-activation.sh --role "Contributor" --scope "/subscriptions/..." \
#       --reason "Deploy hotfix" --duration 1h
#   ./azure-pim-activation.sh --help

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly DEFAULT_DURATION="1h"
readonly MAX_DURATION_SECONDS=28800  # 8 hours (PIM default max)
readonly POLL_INTERVAL=5
readonly POLL_TIMEOUT=120

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log()  { echo "[${SCRIPT_NAME}] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >&2; }
info() { log "INFO  $*"; }
warn() { log "WARN  $*"; }
err()  { log "ERROR $*"; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Activate an Azure PIM eligible role assignment.

Required:
  --role NAME         Role name to activate (e.g., "Contributor", "Owner",
                      "Key Vault Secrets Officer")
  --reason TEXT       Justification for activation (min 10 chars)

Options:
  --scope SCOPE       Azure scope (default: current subscription)
                      Examples:
                        /subscriptions/<sub-id>
                        /subscriptions/<sub-id>/resourceGroups/<rg>
  --duration DUR      Activation duration (default: ${DEFAULT_DURATION})
                      Format: Nm, Nh (e.g., 30m, 1h, 4h)
                      Maximum: 8h (PIM default)
  --ticket-number NUM Ticket number for approval tracking
  --ticket-system SYS Ticket system name (e.g., JIRA, ServiceNow)
  --output FORMAT     Output format: text (default), json
  --help              Show this help message

Environment:
  AZURE_SUBSCRIPTION_ID  Override default subscription

Examples:
  # Activate Contributor on current subscription
  ${SCRIPT_NAME} --role "Contributor" --reason "Deploy v2.1 release" --duration 1h

  # Activate Key Vault access on a specific resource group
  ${SCRIPT_NAME} --role "Key Vault Secrets Officer" \\
      --scope "/subscriptions/xxxx/resourceGroups/prod-keyvault" \\
      --reason "Rotate production secrets" --duration 30m

  # With ticket tracking
  ${SCRIPT_NAME} --role "Owner" --reason "Infrastructure migration" \\
      --ticket-number "JIRA-5678" --ticket-system "JIRA" --duration 2h
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ROLE_NAME=""
REASON=""
DURATION="${DEFAULT_DURATION}"
SCOPE=""
TICKET_NUMBER=""
TICKET_SYSTEM=""
OUTPUT_FORMAT="text"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)           ROLE_NAME="$2"; shift 2 ;;
        --reason)         REASON="$2"; shift 2 ;;
        --duration)       DURATION="$2"; shift 2 ;;
        --scope)          SCOPE="$2"; shift 2 ;;
        --ticket-number)  TICKET_NUMBER="$2"; shift 2 ;;
        --ticket-system)  TICKET_SYSTEM="$2"; shift 2 ;;
        --output)         OUTPUT_FORMAT="$2"; shift 2 ;;
        --help|-h)        usage ;;
        *)                err "Unknown option: $1"; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

for cmd in az jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        err "${cmd} is required but not found in PATH"
        exit 1
    fi
done

if [[ -z "${ROLE_NAME}" ]]; then
    err "--role is required"
    exit 1
fi

if [[ -z "${REASON}" ]]; then
    err "--reason is required"
    exit 1
fi

if [[ ${#REASON} -lt 10 ]]; then
    err "Reason must be at least 10 characters (got ${#REASON})"
    exit 1
fi

# Parse duration
parse_duration() {
    local dur="$1"
    local num="${dur%[smhSMH]}"
    local unit="${dur: -1}"
    case "${unit}" in
        s|S) echo "${num}" ;;
        m|M) echo $(( num * 60 )) ;;
        h|H) echo $(( num * 3600 )) ;;
        *)   echo $(( dur )) ;;
    esac
}

DURATION_SECONDS=$(parse_duration "${DURATION}")

if [[ ${DURATION_SECONDS} -gt ${MAX_DURATION_SECONDS} ]]; then
    err "Duration ${DURATION} exceeds PIM maximum (8h)"
    exit 1
fi

# Convert seconds to ISO 8601 duration for PIM API
duration_hours=$(( DURATION_SECONDS / 3600 ))
duration_minutes=$(( (DURATION_SECONDS % 3600) / 60 ))
ISO_DURATION="PT${duration_hours}H${duration_minutes}M"

# Get current identity
PRINCIPAL_ID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null)
PRINCIPAL_NAME=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null)
info "Signed-in user: ${PRINCIPAL_NAME} (${PRINCIPAL_ID})"

# Resolve scope
if [[ -z "${SCOPE}" ]]; then
    SUB_ID="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"
    SCOPE="/subscriptions/${SUB_ID}"
    info "Using current subscription scope: ${SCOPE}"
fi

# ---------------------------------------------------------------------------
# Find eligible role assignment
# ---------------------------------------------------------------------------

info "Looking up eligible PIM assignment for role '${ROLE_NAME}' on scope ${SCOPE}"

# Get the role definition ID
ROLE_DEF_ID=$(az role definition list \
    --name "${ROLE_NAME}" \
    --scope "${SCOPE}" \
    --query "[0].id" -o tsv 2>/dev/null)

if [[ -z "${ROLE_DEF_ID}" ]]; then
    err "Role '${ROLE_NAME}' not found on scope ${SCOPE}"
    exit 1
fi

info "Role definition: ${ROLE_DEF_ID}"

# Check for eligible assignment using PIM API
ELIGIBLE=$(az rest \
    --method GET \
    --url "https://management.azure.com${SCOPE}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&\$filter=principalId eq '${PRINCIPAL_ID}' and roleDefinitionId eq '${ROLE_DEF_ID}'" \
    2>/dev/null | jq -r '.value | length')

if [[ "${ELIGIBLE}" == "0" || -z "${ELIGIBLE}" ]]; then
    err "No eligible PIM assignment found for role '${ROLE_NAME}' on this scope"
    err "Check your PIM eligible assignments in the Azure portal"
    exit 1
fi

info "Eligible assignment confirmed"

# ---------------------------------------------------------------------------
# Activate PIM role
# ---------------------------------------------------------------------------

info "Activating PIM role: ${ROLE_NAME} for ${DURATION}"

ACTIVATION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

activation_body=$(jq -n \
    --arg principalId "${PRINCIPAL_ID}" \
    --arg roleDefId "${ROLE_DEF_ID}" \
    --arg scope "${SCOPE}" \
    --arg justification "${REASON}" \
    --arg duration "${ISO_DURATION}" \
    --arg startTime "${START_TIME}" \
    --arg ticketNumber "${TICKET_NUMBER}" \
    --arg ticketSystem "${TICKET_SYSTEM}" \
    '{
        properties: {
            principalId: $principalId,
            roleDefinitionId: $roleDefId,
            requestType: "SelfActivate",
            justification: $justification,
            scheduleInfo: {
                startDateTime: $startTime,
                expiration: {
                    type: "AfterDuration",
                    duration: $duration
                }
            },
            ticketInfo: {
                ticketNumber: $ticketNumber,
                ticketSystem: $ticketSystem
            }
        }
    }')

activation_response=$(az rest \
    --method PUT \
    --url "https://management.azure.com${SCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${ACTIVATION_ID}?api-version=2020-10-01" \
    --body "${activation_body}" 2>&1)

activation_status=$(echo "${activation_response}" | jq -r '.properties.status // "unknown"')
info "Activation request status: ${activation_status}"

# ---------------------------------------------------------------------------
# Wait for activation
# ---------------------------------------------------------------------------

if [[ "${activation_status}" == "Provisioned" || "${activation_status}" == "Granted" ]]; then
    info "Role activated immediately"
elif [[ "${activation_status}" == "PendingApproval" ]]; then
    info "Activation pending approval — waiting..."
    elapsed=0
    while [[ ${elapsed} -lt ${POLL_TIMEOUT} ]]; do
        sleep ${POLL_INTERVAL}
        elapsed=$(( elapsed + POLL_INTERVAL ))

        check=$(az rest \
            --method GET \
            --url "https://management.azure.com${SCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${ACTIVATION_ID}?api-version=2020-10-01" \
            2>/dev/null | jq -r '.properties.status // "pending"')

        if [[ "${check}" == "Provisioned" || "${check}" == "Granted" ]]; then
            info "Role activated after approval (${elapsed}s)"
            activation_status="${check}"
            break
        elif [[ "${check}" == "Denied" || "${check}" == "Failed" ]]; then
            err "Activation ${check}"
            exit 1
        fi
    done
fi

EXPIRY_TIME=$(date -u -d "+${DURATION_SECONDS} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v+${DURATION_SECONDS}S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || echo "unknown")

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

case "${OUTPUT_FORMAT}" in
    json)
        jq -n \
            --arg role "${ROLE_NAME}" \
            --arg scope "${SCOPE}" \
            --arg principal "${PRINCIPAL_NAME}" \
            --arg reason "${REASON}" \
            --arg duration "${DURATION}" \
            --arg status "${activation_status}" \
            --arg activationId "${ACTIVATION_ID}" \
            --arg startTime "${START_TIME}" \
            --arg expiryTime "${EXPIRY_TIME}" \
            '{
                role: $role,
                scope: $scope,
                principal: $principal,
                reason: $reason,
                duration: $duration,
                status: $status,
                activation_id: $activationId,
                start_time: $startTime,
                expiry_time: $expiryTime
            }'
        ;;
    text|*)
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  Azure PIM Activation Result"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  Role:          ${ROLE_NAME}"
        echo "  Scope:         ${SCOPE}"
        echo "  Principal:     ${PRINCIPAL_NAME}"
        echo "  Reason:        ${REASON}"
        echo "  Duration:      ${DURATION}"
        echo "  Status:        ${activation_status}"
        echo "  Activation ID: ${ACTIVATION_ID}"
        echo "  Activated:     ${START_TIME}"
        echo "  Expires:       ${EXPIRY_TIME}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "  Role will auto-deactivate at ${EXPIRY_TIME}"
        echo "  Manual deactivation: az rest --method PUT --url ...roleAssignmentScheduleRequests/..."
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ;;
esac

info "PIM activation complete. Role auto-deactivates at ${EXPIRY_TIME}"
