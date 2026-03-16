#!/usr/bin/env bash

#!/usr/bin/env bash
# vault-env.sh — Authenticate to Vault, fetch secrets, export as env vars,
# then exec the wrapped command with those secrets available.
#
# Usage:
#   ./vault-env.sh my-app --flag1 --flag2
#   VAULT_AUTH_METHOD=oidc ./vault-env.sh python app.py
#
# Environment variables:
#   VAULT_ADDR          - Vault server URL (required)
#   VAULT_AUTH_METHOD   - "oidc" or "approle" (default: approle)
#   VAULT_ROLE          - Vault role name (default: myapp)
#   VAULT_ROLE_ID       - AppRole role ID (required if approle)
#   VAULT_SECRET_ID     - AppRole secret ID (required if approle)
#   VAULT_OIDC_TOKEN    - Pre-obtained OIDC JWT (required if oidc)
#   VAULT_KV_PATH       - KV v2 secret path (default: kv/data/dev/apps/myapp/config)
#   VAULT_DB_ROLE       - Database role (default: myapp-db)
#   VAULT_NAMESPACE     - Vault namespace (optional, enterprise)
#   VAULT_ENV_PREFIX    - Env var prefix (default: APP_)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${VAULT_AUTH_METHOD:=approle}"
: "${VAULT_ROLE:=myapp}"
: "${VAULT_KV_PATH:=kv/data/dev/apps/myapp/config}"
: "${VAULT_DB_ROLE:=myapp-db}"
: "${VAULT_ENV_PREFIX:=APP_}"

RENEWAL_PID=""

log() { echo "[vault-env] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >&2; }

cleanup() {
    if [[ -n "${RENEWAL_PID}" ]]; then
        kill "${RENEWAL_PID}" 2>/dev/null || true
        wait "${RENEWAL_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

authenticate() {
    case "${VAULT_AUTH_METHOD}" in
        approle)
            : "${VAULT_ROLE_ID:?VAULT_ROLE_ID required for AppRole auth}"
            : "${VAULT_SECRET_ID:?VAULT_SECRET_ID required for AppRole auth}"

            local response
            response=$(vault write -format=json auth/approle/login \
                role_id="${VAULT_ROLE_ID}" \
                secret_id="${VAULT_SECRET_ID}")

            VAULT_TOKEN=$(echo "${response}" | jq -r '.auth.client_token')
            TOKEN_TTL=$(echo "${response}" | jq -r '.auth.lease_duration')
            export VAULT_TOKEN
            log "Authenticated via AppRole, TTL ${TOKEN_TTL}s"
            ;;

        oidc)
            : "${VAULT_OIDC_TOKEN:?VAULT_OIDC_TOKEN required for OIDC auth}"

            local response
            response=$(vault write -format=json auth/oidc/login \
                role="${VAULT_ROLE}" \
                jwt="${VAULT_OIDC_TOKEN}")

            VAULT_TOKEN=$(echo "${response}" | jq -r '.auth.client_token')
            TOKEN_TTL=$(echo "${response}" | jq -r '.auth.lease_duration')
            export VAULT_TOKEN
            log "Authenticated via OIDC, TTL ${TOKEN_TTL}s"
            ;;

        *)
            log "ERROR: Unsupported auth method: ${VAULT_AUTH_METHOD}"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Secret fetching
# ---------------------------------------------------------------------------

fetch_kv_secrets() {
    local kv_json
    kv_json=$(vault read -format=json "${VAULT_KV_PATH}")

    # KV v2 nests data under .data.data
    local keys
    keys=$(echo "${kv_json}" | jq -r '.data.data | keys[]')

    local count=0
    while IFS= read -r key; do
        local value
        value=$(echo "${kv_json}" | jq -r ".data.data[\"${key}\"]")
        local env_key="${VAULT_ENV_PREFIX}${key^^}"
        export "${env_key}=${value}"
        count=$((count + 1))
    done <<< "${keys}"

    log "Exported ${count} KV secrets with prefix ${VAULT_ENV_PREFIX}"
}

fetch_db_credentials() {
    local db_json
    db_json=$(vault read -format=json "database/creds/${VAULT_DB_ROLE}")

    local username password lease_id lease_duration
    username=$(echo "${db_json}" | jq -r '.data.username')
    password=$(echo "${db_json}" | jq -r '.data.password')
    lease_id=$(echo "${db_json}" | jq -r '.lease_id')
    lease_duration=$(echo "${db_json}" | jq -r '.lease_duration')

    export "${VAULT_ENV_PREFIX}DB_USERNAME=${username}"
    export "${VAULT_ENV_PREFIX}DB_PASSWORD=${password}"
    DB_LEASE_ID="${lease_id}"
    export DB_LEASE_TTL="${lease_duration}"

    log "DB creds acquired: user=${username} TTL=${lease_duration}s"
}

# ---------------------------------------------------------------------------
# Background token / lease renewal
# ---------------------------------------------------------------------------

# Renewal runs at 2/3 of the TTL. On failure, retries 3 times then
# triggers full re-authentication. This runs as a background subprocess.
start_renewal() {
    (
        local failures=0
        local sleep_secs=$(( TOKEN_TTL * 2 / 3 ))
        [[ ${sleep_secs} -lt 5 ]] && sleep_secs=5

        while true; do
            sleep "${sleep_secs}"

            # Renew auth token
            if vault token renew -format=json > /dev/null 2>&1; then
                local new_ttl
                new_ttl=$(vault token lookup -format=json | jq -r '.data.ttl')
                sleep_secs=$(( new_ttl * 2 / 3 ))
                [[ ${sleep_secs} -lt 5 ]] && sleep_secs=5
                failures=0
            else
                failures=$((failures + 1))
                log "Token renewal failed (attempt ${failures})"

                if [[ ${failures} -ge 3 ]]; then
                    log "3 failures — re-authenticating"
                    authenticate || log "Re-auth failed"
                    failures=0
                fi
                sleep_secs=5
            fi

            # Renew DB lease if tracked
            if [[ -n "${DB_LEASE_ID:-}" ]]; then
                if ! vault lease renew "${DB_LEASE_ID}" > /dev/null 2>&1; then
                    log "DB lease renewal failed — credentials may expire"
                fi
            fi
        done
    ) &
    RENEWAL_PID=$!
    log "Renewal loop started (PID ${RENEWAL_PID})"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <command> [args...]" >&2
    echo "  Authenticates to Vault, fetches secrets, exports as env vars," >&2
    echo "  then execs the given command with those secrets available." >&2
    exit 1
fi

# Verify prerequisites
for cmd in vault jq; do
    if ! command -v "${cmd}" &>/dev/null; then
        log "ERROR: ${cmd} is required but not found in PATH"
        exit 1
    fi
done

# Set namespace header if configured
if [[ -n "${VAULT_NAMESPACE:-}" ]]; then
    export VAULT_NAMESPACE
fi

# Step 1: Authenticate
authenticate

# Step 2: Fetch secrets
fetch_kv_secrets
fetch_db_credentials

# Step 3: Start background renewal
start_renewal

# Step 4: Exec the wrapped command — replaces this shell process
# but the background renewal subprocess continues until the child exits
log "Executing: $*"
exec "$@"
