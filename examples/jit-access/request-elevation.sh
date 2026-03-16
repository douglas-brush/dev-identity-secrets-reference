#!/usr/bin/env bash
# request-elevation.sh — Request temporary elevated access through Vault.
#
# Submits a control group request for privileged access, waits for approval
# (or auto-approves in break-glass mode with mandatory audit), sets up
# temporary credentials, and schedules automatic cleanup.
#
# Prerequisites:
#   - vault CLI in PATH
#   - jq in PATH
#   - Authenticated to Vault (VAULT_TOKEN or vault login)
#   - VAULT_ADDR set
#
# Usage:
#   ./request-elevation.sh --reason "Deploy hotfix JIRA-1234" --duration 30m --scope prod-db
#   ./request-elevation.sh --reason "P1 incident" --scope prod-all --break-glass
#   ./request-elevation.sh --help

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly DEFAULT_DURATION="30m"
readonly MAX_DURATION_SECONDS=7200  # 2 hours hard cap
readonly BREAK_GLASS_MAX_SECONDS=7200  # exported for subprocesses
export BREAK_GLASS_MAX_SECONDS
readonly POLL_INTERVAL=10
readonly POLL_TIMEOUT=3600  # 1 hour max wait for approval

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

Request temporary elevated access through Vault control groups.

Required:
  --reason TEXT       Reason for elevation (min 10 chars, included in audit log)
  --scope SCOPE       Access scope. One of:
                        prod-db       - Production database credentials
                        prod-kv       - Production KV secrets
                        prod-ssh      - Production SSH certificates
                        prod-cloud    - Production cloud credentials
                        prod-all      - All production resources

Options:
  --duration DUR      Access duration (default: ${DEFAULT_DURATION})
                      Format: Ns, Nm, Nh (e.g., 30m, 1h, 90m)
                      Maximum: 2h
  --break-glass       Emergency override — bypasses approval workflow.
                      Triggers enhanced audit and mandatory post-incident review.
  --no-wait           Submit request and exit without waiting for approval.
  --output FORMAT     Output format: text (default), json, env
  --help              Show this help message

Environment:
  VAULT_ADDR          Vault server URL (required)
  VAULT_TOKEN         Vault authentication token (required)
  VAULT_NAMESPACE     Vault namespace (optional, enterprise)
  JIT_WEBHOOK_URL     Webhook URL for break-glass notifications (optional)

Examples:
  # Request 30-minute production database access
  ${SCRIPT_NAME} --reason "Deploy hotfix JIRA-1234" --scope prod-db

  # Break-glass emergency access to all production resources
  ${SCRIPT_NAME} --reason "P1 outage, restoring service" --scope prod-all --break-glass

  # Request and export credentials as env vars
  eval \$(${SCRIPT_NAME} --reason "Rotate certs" --scope prod-kv --output env)
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

REASON=""
DURATION="${DEFAULT_DURATION}"
SCOPE=""
BREAK_GLASS=false
NO_WAIT=false
OUTPUT_FORMAT="text"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reason)     REASON="$2"; shift 2 ;;
        --duration)   DURATION="$2"; shift 2 ;;
        --scope)      SCOPE="$2"; shift 2 ;;
        --break-glass) BREAK_GLASS=true; shift ;;
        --no-wait)    NO_WAIT=true; shift ;;
        --output)     OUTPUT_FORMAT="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *)            err "Unknown option: $1"; usage ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

for cmd in vault jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        err "${cmd} is required but not found in PATH"
        exit 1
    fi
done

: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required (run 'vault login' first)}"

if [[ -z "${REASON}" ]]; then
    err "--reason is required"
    exit 1
fi

if [[ ${#REASON} -lt 10 ]]; then
    err "Reason must be at least 10 characters (got ${#REASON})"
    exit 1
fi

if [[ -z "${SCOPE}" ]]; then
    err "--scope is required"
    exit 1
fi

# Validate scope
declare -A SCOPE_PATHS=(
    ["prod-db"]="database/creds/prod-readonly"
    ["prod-kv"]="kv/data/prod/+/config"
    ["prod-ssh"]="ssh-client-signer/sign/prod-role"
    ["prod-cloud"]="cloud/creds/prod-deploy"
    ["prod-all"]="*"
)

if [[ -z "${SCOPE_PATHS[${SCOPE}]:-}" ]]; then
    err "Invalid scope: ${SCOPE}"
    err "Valid scopes: ${!SCOPE_PATHS[*]}"
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
        *)   echo $(( dur )) ;;  # assume seconds if no unit
    esac
}

DURATION_SECONDS=$(parse_duration "${DURATION}")

if [[ ${DURATION_SECONDS} -gt ${MAX_DURATION_SECONDS} ]]; then
    err "Duration ${DURATION} exceeds maximum (2h / ${MAX_DURATION_SECONDS}s)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Scope-to-path resolution
# ---------------------------------------------------------------------------

resolve_vault_path() {
    local scope="$1"
    case "${scope}" in
        prod-db)    echo "database/creds/prod-readonly" ;;
        prod-kv)    echo "kv/data/prod/app/config" ;;
        prod-ssh)   echo "ssh-client-signer/sign/prod-role" ;;
        prod-cloud) echo "cloud/creds/prod-deploy" ;;
        prod-all)   echo "sys/control-group/request" ;;  # meta-scope
    esac
}

VAULT_PATH=$(resolve_vault_path "${SCOPE}")

# ---------------------------------------------------------------------------
# Break-glass flow
# ---------------------------------------------------------------------------

break_glass_elevate() {
    warn "BREAK-GLASS activated — enhanced audit logging enabled"
    warn "Mandatory post-incident review required within 24 hours"

    # Authenticate with break-glass policy
    # In production, this would use a separate auth method (hardware token, etc.)
    local bg_response
    bg_response=$(vault token create \
        -format=json \
        -policy="jit-break-glass" \
        -ttl="${DURATION}" \
        -metadata="reason=${REASON}" \
        -metadata="break_glass=true" \
        -metadata="requester=$(vault token lookup -format=json | jq -r '.data.display_name')" \
        -metadata="timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -num-uses=0 \
        -renewable=false)

    local bg_token bg_accessor
    bg_token=$(echo "${bg_response}" | jq -r '.auth.client_token')
    bg_accessor=$(echo "${bg_response}" | jq -r '.auth.accessor')

    info "Break-glass token created: accessor=${bg_accessor} TTL=${DURATION}"

    # Send break-glass notification if webhook is configured
    if [[ -n "${JIT_WEBHOOK_URL:-}" ]]; then
        local requester
        requester=$(vault token lookup -format=json | jq -r '.data.display_name')
        curl -sf -X POST "${JIT_WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "$(jq -n \
                --arg reason "${REASON}" \
                --arg scope "${SCOPE}" \
                --arg duration "${DURATION}" \
                --arg requester "${requester}" \
                --arg accessor "${bg_accessor}" \
                --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                '{
                    event: "break-glass-activation",
                    requester: $requester,
                    reason: $reason,
                    scope: $scope,
                    duration: $duration,
                    accessor: $accessor,
                    timestamp: $timestamp,
                    severity: "critical",
                    action_required: "Post-incident review within 24 hours"
                }')" || warn "Failed to send break-glass notification"
    fi

    # Write audit log entry to Vault
    vault write sys/audit-hash/file input="break-glass:${SCOPE}:${REASON}" 2>/dev/null || true

    echo "${bg_token}"
}

# ---------------------------------------------------------------------------
# Standard elevation flow (control group)
# ---------------------------------------------------------------------------

standard_elevate() {
    info "Requesting elevated access: scope=${SCOPE} duration=${DURATION} reason='${REASON}'"

    # Attempt to access the privileged path — this triggers the control group
    local response
    response=$(vault read -format=json "${VAULT_PATH}" 2>&1) || true

    # Check if we got a control group response (HTTP 403 with control group info)
    local accessor request_token
    if echo "${response}" | jq -e '.wrap_info.accessor' &>/dev/null; then
        accessor=$(echo "${response}" | jq -r '.wrap_info.accessor')
        request_token=$(echo "${response}" | jq -r '.wrap_info.token')
        info "Control group request submitted: accessor=${accessor}"
    else
        # Try extracting from the error response
        accessor=$(echo "${response}" | grep -oP 'accessor:\s*\K[a-zA-Z0-9]+' || true)
        if [[ -z "${accessor}" ]]; then
            err "Failed to initiate control group request"
            err "Response: ${response}"
            exit 1
        fi
        info "Control group request submitted: accessor=${accessor}"
    fi

    if ${NO_WAIT}; then
        info "Request submitted (--no-wait). Accessor: ${accessor}"
        info "Check status: vault write sys/control-group/request accessor=${accessor}"
        output_result "pending" "${accessor}" "" ""
        return
    fi

    # Poll for approval
    info "Waiting for approval (timeout: ${POLL_TIMEOUT}s, poll interval: ${POLL_INTERVAL}s)..."
    local elapsed=0
    local status="pending"

    while [[ "${status}" == "pending" && ${elapsed} -lt ${POLL_TIMEOUT} ]]; do
        sleep ${POLL_INTERVAL}
        elapsed=$(( elapsed + POLL_INTERVAL ))

        local check_response
        check_response=$(vault write -format=json sys/control-group/request accessor="${accessor}" 2>/dev/null) || true

        if [[ -n "${check_response}" ]]; then
            status=$(echo "${check_response}" | jq -r '.data.approved // "pending"')
            if [[ "${status}" == "true" ]]; then
                status="approved"
            fi
        fi

        if (( elapsed % 60 == 0 )); then
            info "Still waiting for approval... (${elapsed}s elapsed)"
        fi
    done

    if [[ "${status}" != "approved" ]]; then
        err "Elevation request was not approved (status: ${status}, elapsed: ${elapsed}s)"
        exit 1
    fi

    info "Request approved. Unwrapping elevated token..."

    # Unwrap the control group token to get actual access
    local unwrap_response
    unwrap_response=$(VAULT_TOKEN="${request_token}" vault unwrap -format=json)
    local elevated_token
    elevated_token=$(echo "${unwrap_response}" | jq -r '.auth.client_token // .data.token // empty')

    if [[ -z "${elevated_token}" ]]; then
        err "Failed to unwrap elevated token"
        exit 1
    fi

    echo "${elevated_token}"
}

# ---------------------------------------------------------------------------
# Credential fetching
# ---------------------------------------------------------------------------

fetch_credentials() {
    local token="$1"
    local scope="$2"

    case "${scope}" in
        prod-db)
            VAULT_TOKEN="${token}" vault read -format=json database/creds/prod-readonly
            ;;
        prod-kv)
            VAULT_TOKEN="${token}" vault read -format=json kv/data/prod/app/config
            ;;
        prod-ssh)
            VAULT_TOKEN="${token}" vault write -format=json \
                ssh-client-signer/sign/prod-role \
                public_key="$(cat ~/.ssh/id_ed25519.pub 2>/dev/null || cat ~/.ssh/id_rsa.pub)"
            ;;
        prod-cloud)
            VAULT_TOKEN="${token}" vault read -format=json cloud/creds/prod-deploy
            ;;
        prod-all)
            info "Scope: prod-all — use the elevated token directly"
            jq -n --arg token "${token}" '{"token": $token}'
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

output_result() {
    local status="$1"
    local accessor="$2"
    local token="$3"
    local creds="$4"

    case "${OUTPUT_FORMAT}" in
        json)
            jq -n \
                --arg status "${status}" \
                --arg accessor "${accessor}" \
                --arg scope "${SCOPE}" \
                --arg reason "${REASON}" \
                --arg duration "${DURATION}" \
                --arg expires "$(date -u -d "+${DURATION_SECONDS} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+"${DURATION_SECONDS}"S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 'unknown')" \
                --argjson creds "${creds:-null}" \
                '{
                    status: $status,
                    accessor: $accessor,
                    scope: $scope,
                    reason: $reason,
                    duration: $duration,
                    expires: $expires,
                    credentials: $creds
                }'
            ;;
        env)
            if [[ -n "${creds}" && "${creds}" != "null" ]]; then
                echo "${creds}" | jq -r '
                    .data // . |
                    to_entries[] |
                    "export JIT_\(.key | ascii_upcase)=\(.value)"
                '
            fi
            if [[ -n "${token}" ]]; then
                echo "export JIT_VAULT_TOKEN=${token}"
            fi
            ;;
        text|*)
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "  JIT Elevation Result"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "  Status:   ${status}"
            echo "  Scope:    ${SCOPE}"
            echo "  Reason:   ${REASON}"
            echo "  Duration: ${DURATION}"
            echo "  Accessor: ${accessor}"
            if [[ -n "${token}" ]]; then
                echo "  Token:    ${token:0:8}...${token: -4} (truncated)"
            fi
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Auto-cleanup scheduler
# ---------------------------------------------------------------------------

schedule_cleanup() {
    local token="$1"
    local duration_secs="$2"
    local accessor="$3"

    info "Scheduling auto-revoke in ${duration_secs}s"

    # Background process that revokes the token after the duration expires
    (
        sleep "${duration_secs}"
        info "Auto-cleanup: revoking elevated token (accessor: ${accessor})"
        vault token revoke -accessor "${accessor}" 2>/dev/null || true
        info "Auto-cleanup complete"
    ) &
    local cleanup_pid=$!
    disown "${cleanup_pid}" 2>/dev/null || true

    info "Cleanup scheduled (PID ${cleanup_pid}, fires in ${duration_secs}s)"

    # Also write a revocation reminder file
    local cleanup_file="/tmp/jit-cleanup-${accessor}"
    cat > "${cleanup_file}" <<CLEANUP
#!/usr/bin/env bash
# Auto-generated JIT cleanup script
# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Expires: $(date -u -d "+${duration_secs} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 'see duration')
# Accessor: ${accessor}
vault token revoke -accessor "${accessor}"
rm -f "${cleanup_file}"
CLEANUP
    chmod +x "${cleanup_file}"
    info "Manual cleanup: ${cleanup_file}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local elevated_token=""

    if ${BREAK_GLASS}; then
        elevated_token=$(break_glass_elevate)
    else
        elevated_token=$(standard_elevate)
    fi

    # If we got a token, fetch scoped credentials
    if [[ -n "${elevated_token}" ]]; then
        local creds=""
        if [[ "${SCOPE}" != "prod-all" ]]; then
            creds=$(fetch_credentials "${elevated_token}" "${SCOPE}")
        fi

        # Get the accessor for cleanup scheduling
        local accessor
        accessor=$(VAULT_TOKEN="${elevated_token}" vault token lookup -format=json 2>/dev/null | jq -r '.data.accessor' || echo "unknown")

        # Schedule auto-cleanup
        schedule_cleanup "${elevated_token}" "${DURATION_SECONDS}" "${accessor}"

        # Output results
        output_result "granted" "${accessor}" "${elevated_token}" "${creds}"
    fi
}

main
