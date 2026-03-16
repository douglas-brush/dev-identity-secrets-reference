#!/usr/bin/env bash
# gcp-iam-binding.sh — Create a time-bounded IAM binding on GCP.
#
# Uses IAM Conditions to grant a role with an automatic expiry. The binding
# includes a time-based condition expression that GCP enforces server-side,
# so access is revoked even if cleanup fails locally.
#
# Prerequisites:
#   - gcloud CLI in PATH, authenticated (gcloud auth login)
#   - jq in PATH
#   - IAM admin permissions on the target project/resource
#
# Usage:
#   ./gcp-iam-binding.sh --role roles/editor --project my-project \
#       --reason "Deploy hotfix" --duration 1h
#   ./gcp-iam-binding.sh --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly DEFAULT_DURATION="1h"
readonly MAX_DURATION_SECONDS=28800  # 8 hours

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

Create a time-bounded IAM role binding on GCP using IAM Conditions.

Required:
  --role ROLE         GCP IAM role (e.g., roles/editor, roles/cloudsql.admin)
  --reason TEXT       Reason for elevation (min 10 chars, stored in condition title)

Options:
  --project PROJECT   GCP project ID (default: current gcloud project)
  --member MEMBER     IAM member (default: current authenticated user)
                      Format: user:email, serviceAccount:email, group:email
  --duration DUR      Binding duration (default: ${DEFAULT_DURATION})
                      Format: Nm, Nh (e.g., 30m, 1h, 4h)
                      Maximum: 8h
  --resource TYPE     Resource level: project (default), folder, org
  --resource-id ID    Resource ID (folder or org number, if --resource is not project)
  --output FORMAT     Output format: text (default), json
  --cleanup           Remove expired JIT bindings from the project
  --help              Show this help message

Environment:
  CLOUDSDK_CORE_PROJECT  Override default GCP project

Examples:
  # Grant Editor on current project for 1 hour
  ${SCRIPT_NAME} --role roles/editor --reason "Deploy v2.1 release" --duration 1h

  # Grant Cloud SQL admin on a specific project for 30 minutes
  ${SCRIPT_NAME} --role roles/cloudsql.admin --project prod-db-project \\
      --reason "Emergency database migration" --duration 30m

  # Clean up expired JIT bindings
  ${SCRIPT_NAME} --cleanup --project my-project
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ROLE=""
REASON=""
DURATION="${DEFAULT_DURATION}"
PROJECT=""
MEMBER=""
export RESOURCE_TYPE="project"
export RESOURCE_ID=""
OUTPUT_FORMAT="text"
CLEANUP_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)         ROLE="$2"; shift 2 ;;
        --reason)       REASON="$2"; shift 2 ;;
        --duration)     DURATION="$2"; shift 2 ;;
        --project)      PROJECT="$2"; shift 2 ;;
        --member)       MEMBER="$2"; shift 2 ;;
        --resource)     RESOURCE_TYPE="$2"; shift 2 ;;
        --resource-id)  RESOURCE_ID="$2"; shift 2 ;;
        --output)       OUTPUT_FORMAT="$2"; shift 2 ;;
        --cleanup)      CLEANUP_MODE=true; shift ;;
        --help|-h)      usage ;;
        *)              err "Unknown option: $1"; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

for cmd in gcloud jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        err "${cmd} is required but not found in PATH"
        exit 1
    fi
done

# Resolve project
if [[ -z "${PROJECT}" ]]; then
    PROJECT="${CLOUDSDK_CORE_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
fi

if [[ -z "${PROJECT}" ]]; then
    err "No project specified. Use --project or set CLOUDSDK_CORE_PROJECT"
    exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup mode — remove expired JIT bindings
# ---------------------------------------------------------------------------

cleanup_expired_bindings() {
    info "Scanning for expired JIT bindings in project ${PROJECT}"

    local policy
    policy=$(gcloud projects get-iam-policy "${PROJECT}" --format=json 2>/dev/null)

    local now_epoch
    now_epoch=$(date +%s)
    local removed=0

    # Find bindings with JIT condition titles
    echo "${policy}" | jq -c '.bindings[] | select(.condition.title != null) | select(.condition.title | startswith("jit-access-"))' | while IFS= read -r binding; do
        local title
        title=$(echo "${binding}" | jq -r '.condition.title')

        # Extract expiry from the condition expression
        local expiry_str
        expiry_str=$(echo "${binding}" | jq -r '.condition.expression' | grep -oP 'timestamp\("\K[^"]+' | tail -1 || true)

        if [[ -n "${expiry_str}" ]]; then
            local expiry_epoch
            expiry_epoch=$(date -d "${expiry_str}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${expiry_str}" +%s 2>/dev/null || echo 0)

            if [[ ${expiry_epoch} -lt ${now_epoch} && ${expiry_epoch} -gt 0 ]]; then
                local role member
                role=$(echo "${binding}" | jq -r '.role')
                member=$(echo "${binding}" | jq -r '.members[0]')
                info "Removing expired binding: ${role} -> ${member} (expired: ${expiry_str})"

                gcloud projects remove-iam-policy-binding "${PROJECT}" \
                    --role="${role}" \
                    --member="${member}" \
                    --condition="title=${title},expression=$(echo "${binding}" | jq -r '.condition.expression')" \
                    --quiet 2>/dev/null || warn "Failed to remove binding: ${title}"

                removed=$((removed + 1))
            fi
        fi
    done

    info "Cleanup complete: removed ${removed} expired binding(s)"
    exit 0
}

if ${CLEANUP_MODE}; then
    cleanup_expired_bindings
fi

# Validate remaining required args
if [[ -z "${ROLE}" ]]; then
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
    err "Duration ${DURATION} exceeds maximum (8h)"
    exit 1
fi

# Resolve member
if [[ -z "${MEMBER}" ]]; then
    MEMBER="user:$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -1)"
fi

info "Authenticated member: ${MEMBER}"

# ---------------------------------------------------------------------------
# Create time-bounded IAM binding
# ---------------------------------------------------------------------------

# Calculate expiry timestamp in RFC 3339
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EXPIRY_TIME=$(date -u -d "+${DURATION_SECONDS} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v+"${DURATION_SECONDS}"S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)

if [[ -z "${EXPIRY_TIME}" ]]; then
    err "Failed to calculate expiry time"
    exit 1
fi

# IAM Condition expression — enforces time-bounded access server-side
# GCP evaluates this on every API call, so access is denied after expiry
# even if the binding is not cleaned up
CONDITION_TITLE="jit-access-$(date -u +%Y%m%d%H%M%S)-${RANDOM}"
CONDITION_EXPRESSION="request.time < timestamp(\"${EXPIRY_TIME}\")"
CONDITION_DESCRIPTION="JIT access: ${REASON} (expires ${EXPIRY_TIME})"

info "Creating time-bounded IAM binding: role=${ROLE} member=${MEMBER} expires=${EXPIRY_TIME}"

gcloud_args=(
    projects add-iam-policy-binding "${PROJECT}"
    --role="${ROLE}"
    --member="${MEMBER}"
    --condition="title=${CONDITION_TITLE},description=${CONDITION_DESCRIPTION},expression=${CONDITION_EXPRESSION}"
    --quiet
    --format=json
)

if ! binding_result=$(gcloud "${gcloud_args[@]}" 2>&1); then
    err "Failed to create IAM binding"
    err "${binding_result}"
    exit 1
fi

info "IAM binding created: ${CONDITION_TITLE}"

# ---------------------------------------------------------------------------
# Schedule cleanup (best-effort — IAM Condition enforces the hard deadline)
# ---------------------------------------------------------------------------

(
    sleep "${DURATION_SECONDS}"
    info "Auto-cleanup: removing expired JIT binding ${CONDITION_TITLE}"
    gcloud projects remove-iam-policy-binding "${PROJECT}" \
        --role="${ROLE}" \
        --member="${MEMBER}" \
        --condition="title=${CONDITION_TITLE},expression=${CONDITION_EXPRESSION}" \
        --quiet 2>/dev/null || warn "Cleanup removal failed (binding may already be expired)"
    info "Auto-cleanup complete"
) &
CLEANUP_PID=$!
disown "${CLEANUP_PID}" 2>/dev/null || true

info "Cleanup scheduled (PID ${CLEANUP_PID}, fires in ${DURATION_SECONDS}s)"
info "Note: IAM Condition enforces expiry server-side even if cleanup fails"

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

case "${OUTPUT_FORMAT}" in
    json)
        jq -n \
            --arg role "${ROLE}" \
            --arg project "${PROJECT}" \
            --arg member "${MEMBER}" \
            --arg reason "${REASON}" \
            --arg duration "${DURATION}" \
            --arg conditionTitle "${CONDITION_TITLE}" \
            --arg startTime "${START_TIME}" \
            --arg expiryTime "${EXPIRY_TIME}" \
            '{
                role: $role,
                project: $project,
                member: $member,
                reason: $reason,
                duration: $duration,
                condition_title: $conditionTitle,
                start_time: $startTime,
                expiry_time: $expiryTime,
                enforcement: "server-side IAM Condition"
            }'
        ;;
    text|*)
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  GCP IAM JIT Binding Result"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  Role:       ${ROLE}"
        echo "  Project:    ${PROJECT}"
        echo "  Member:     ${MEMBER}"
        echo "  Reason:     ${REASON}"
        echo "  Duration:   ${DURATION}"
        echo "  Condition:  ${CONDITION_TITLE}"
        echo "  Granted:    ${START_TIME}"
        echo "  Expires:    ${EXPIRY_TIME}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "  Access enforced server-side by IAM Condition."
        echo "  Binding auto-expires at ${EXPIRY_TIME} regardless of cleanup."
        echo ""
        echo "  Manual cleanup:"
        echo "    ${SCRIPT_NAME} --cleanup --project ${PROJECT}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ;;
esac
