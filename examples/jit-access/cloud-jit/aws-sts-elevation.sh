#!/usr/bin/env bash
# aws-sts-elevation.sh — Request temporary AWS role assumption via STS.
#
# Uses AWS STS AssumeRole to obtain time-bounded credentials for a
# privileged IAM role. Credentials are exported as environment variables
# and automatically cleaned up when the duration expires.
#
# Prerequisites:
#   - aws CLI v2 in PATH
#   - jq in PATH
#   - Valid AWS credentials (base role with sts:AssumeRole permission)
#
# Usage:
#   ./aws-sts-elevation.sh --role arn:aws:iam::123456789012:role/ProdAdmin \
#       --reason "Deploy hotfix JIRA-1234" --duration 1h
#   eval $(./aws-sts-elevation.sh --role ... --reason ... --output env)

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly DEFAULT_DURATION="1h"
readonly MAX_DURATION_SECONDS=43200  # 12 hours (STS max)

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

Request temporary AWS credentials via STS AssumeRole.

Required:
  --role ARN          IAM role ARN to assume
  --reason TEXT       Reason for elevation (min 10 chars, used as session name suffix)

Options:
  --duration DUR      Session duration (default: ${DEFAULT_DURATION})
                      Format: Ns, Nm, Nh (e.g., 30m, 1h, 4h)
                      Maximum: 12h (STS limit)
  --external-id ID    External ID for cross-account assumption (optional)
  --session-name NAME Custom session name (default: jit-<user>-<timestamp>)
  --mfa-serial ARN    MFA device ARN if MFA is required
  --mfa-code CODE     MFA token code
  --output FORMAT     Output format: text (default), json, env
  --help              Show this help message

Environment:
  AWS_PROFILE         AWS CLI profile to use for the base credentials
  AWS_REGION          AWS region (default: us-east-1)

Examples:
  # Assume a production admin role for 30 minutes
  ${SCRIPT_NAME} --role arn:aws:iam::123456789012:role/ProdAdmin \\
      --reason "Deploy hotfix JIRA-1234" --duration 30m

  # Export credentials for use in current shell
  eval \$(${SCRIPT_NAME} --role arn:aws:iam::123456789012:role/ProdReadOnly \\
      --reason "Investigate alert" --output env)

  # Cross-account with MFA
  ${SCRIPT_NAME} --role arn:aws:iam::987654321098:role/AuditRole \\
      --reason "Quarterly access review" --external-id myorg-audit \\
      --mfa-serial arn:aws:iam::123456789012:mfa/engineer --mfa-code 123456
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

ROLE_ARN=""
REASON=""
DURATION="${DEFAULT_DURATION}"
EXTERNAL_ID=""
SESSION_NAME=""
MFA_SERIAL=""
MFA_CODE=""
OUTPUT_FORMAT="text"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)          ROLE_ARN="$2"; shift 2 ;;
        --reason)        REASON="$2"; shift 2 ;;
        --duration)      DURATION="$2"; shift 2 ;;
        --external-id)   EXTERNAL_ID="$2"; shift 2 ;;
        --session-name)  SESSION_NAME="$2"; shift 2 ;;
        --mfa-serial)    MFA_SERIAL="$2"; shift 2 ;;
        --mfa-code)      MFA_CODE="$2"; shift 2 ;;
        --output)        OUTPUT_FORMAT="$2"; shift 2 ;;
        --help|-h)       usage ;;
        *)               err "Unknown option: $1"; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

for cmd in aws jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        err "${cmd} is required but not found in PATH"
        exit 1
    fi
done

if [[ -z "${ROLE_ARN}" ]]; then
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

# Parse duration to seconds
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
    err "Duration ${DURATION} exceeds STS maximum (12h)"
    exit 1
fi

if [[ ${DURATION_SECONDS} -lt 900 ]]; then
    err "Duration must be at least 15 minutes (900s) for STS"
    exit 1
fi

# Generate session name
if [[ -z "${SESSION_NAME}" ]]; then
    local_user=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null | rev | cut -d'/' -f1 | rev || echo "unknown")
    SESSION_NAME="jit-${local_user}-$(date -u +%Y%m%dT%H%M%SZ)"
fi

# Truncate session name to 64 chars (STS limit)
SESSION_NAME="${SESSION_NAME:0:64}"

# ---------------------------------------------------------------------------
# STS AssumeRole
# ---------------------------------------------------------------------------

info "Requesting STS AssumeRole: role=${ROLE_ARN} duration=${DURATION} reason='${REASON}'"

assume_args=(
    sts assume-role
    --role-arn "${ROLE_ARN}"
    --role-session-name "${SESSION_NAME}"
    --duration-seconds "${DURATION_SECONDS}"
    --output json
)

# Add session tags for audit trail
assume_args+=(
    --tags "Key=jit-reason,Value=${REASON:0:256}"
    --tags "Key=jit-timestamp,Value=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
)

if [[ -n "${EXTERNAL_ID}" ]]; then
    assume_args+=(--external-id "${EXTERNAL_ID}")
fi

if [[ -n "${MFA_SERIAL}" ]]; then
    : "${MFA_CODE:?--mfa-code is required when --mfa-serial is provided}"
    assume_args+=(--serial-number "${MFA_SERIAL}" --token-code "${MFA_CODE}")
fi

response=$(aws "${assume_args[@]}")

access_key=$(echo "${response}" | jq -r '.Credentials.AccessKeyId')
secret_key=$(echo "${response}" | jq -r '.Credentials.SecretAccessKey')
session_token=$(echo "${response}" | jq -r '.Credentials.SessionToken')
expiration=$(echo "${response}" | jq -r '.Credentials.Expiration')

info "STS credentials obtained: session=${SESSION_NAME} expires=${expiration}"

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

case "${OUTPUT_FORMAT}" in
    json)
        jq -n \
            --arg role "${ROLE_ARN}" \
            --arg session "${SESSION_NAME}" \
            --arg reason "${REASON}" \
            --arg duration "${DURATION}" \
            --arg expires "${expiration}" \
            --arg access_key "${access_key}" \
            --arg secret_key "${secret_key}" \
            --arg session_token "${session_token}" \
            '{
                role: $role,
                session_name: $session,
                reason: $reason,
                duration: $duration,
                expires: $expires,
                credentials: {
                    access_key_id: $access_key,
                    secret_access_key: $secret_key,
                    session_token: $session_token
                }
            }'
        ;;
    env)
        echo "export AWS_ACCESS_KEY_ID=${access_key}"
        echo "export AWS_SECRET_ACCESS_KEY=${secret_key}"
        echo "export AWS_SESSION_TOKEN=${session_token}"
        echo "export AWS_STS_EXPIRATION=${expiration}"
        echo "export AWS_STS_SESSION_NAME=${SESSION_NAME}"
        ;;
    text|*)
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  AWS STS Elevation Result"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  Role:        ${ROLE_ARN}"
        echo "  Session:     ${SESSION_NAME}"
        echo "  Reason:      ${REASON}"
        echo "  Duration:    ${DURATION}"
        echo "  Expires:     ${expiration}"
        echo "  Access Key:  ${access_key}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "  To use: eval \$(${SCRIPT_NAME} ... --output env)"
        echo ""
        echo "  Credentials expire automatically at ${expiration}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ;;
esac

# ---------------------------------------------------------------------------
# Cleanup scheduler
# ---------------------------------------------------------------------------

info "Credentials will auto-expire at ${expiration} (enforced by AWS STS)"
info "No local cleanup needed — STS credentials are inherently time-bounded"
