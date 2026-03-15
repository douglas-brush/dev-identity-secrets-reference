#!/usr/bin/env bash
# vault-pki-mtls.sh — Set up a Vault PKI backend for mTLS certificate issuance.
#
# Demonstrates:
#   1. Creating a root CA in Vault
#   2. Creating an intermediate CA signed by the root
#   3. Configuring PKI roles for server and client certificates
#   4. Issuing server and client certificates
#   5. Certificate rotation pattern
#
# Prerequisites:
#   - vault CLI in PATH
#   - jq in PATH
#   - Authenticated Vault session (VAULT_TOKEN set or logged in)
#
# Environment variables:
#   VAULT_ADDR          - Vault server URL (required)
#   VAULT_NAMESPACE     - Vault namespace (optional, enterprise)
#   PKI_DOMAIN          - Base domain for certificates (default: internal)
#   PKI_ORG             - Organization name in certificates (default: Example Corp)
#   ROOT_TTL            - Root CA TTL (default: 87600h / 10 years)
#   INTERMEDIATE_TTL    - Intermediate CA TTL (default: 43800h / 5 years)
#   LEAF_TTL            - Default leaf certificate TTL (default: 24h)
#   LEAF_MAX_TTL        - Maximum leaf certificate TTL (default: 72h)
#   CERT_OUTPUT_DIR     - Directory for issued certificates (default: ./certs)
#   SERVICE_NAME        - Service name for certificate issuance (default: web-api)
#   CLIENT_NAME         - Client name for certificate issuance (default: api-client)
#
# Usage:
#   ./vault-pki-mtls.sh setup         — Full PKI setup (root CA + intermediate + roles)
#   ./vault-pki-mtls.sh issue-server  — Issue a server certificate
#   ./vault-pki-mtls.sh issue-client  — Issue a client certificate
#   ./vault-pki-mtls.sh issue-both    — Issue server + client certificates
#   ./vault-pki-mtls.sh rotate        — Rotate (re-issue) server + client certificates
#   ./vault-pki-mtls.sh verify        — Verify issued certificates against the CA chain
#   ./vault-pki-mtls.sh test-mtls     — Start a test server and client to verify mTLS
#   ./vault-pki-mtls.sh --help        — Show this help

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${PKI_DOMAIN:=internal}"
: "${PKI_ORG:=Example Corp}"
: "${ROOT_TTL:=87600h}"
: "${INTERMEDIATE_TTL:=43800h}"
: "${LEAF_TTL:=24h}"
: "${LEAF_MAX_TTL:=72h}"
: "${CERT_OUTPUT_DIR:=./certs}"
: "${SERVICE_NAME:=web-api}"
: "${CLIENT_NAME:=api-client}"

ROOT_PKI_PATH="pki"
INTERMEDIATE_PKI_PATH="pki_int"

log() { echo "[vault-pki-mtls] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >&2; }

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

show_help() {
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//'
    echo ""
    echo "Environment variables:"
    sed -n '/^# Environment variables:/,/^#$/p' "$0" | sed 's/^# \?//'
    exit 0
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

check_prereqs() {
    for cmd in vault jq openssl; do
        if ! command -v "${cmd}" &>/dev/null; then
            log "ERROR: ${cmd} is required but not found in PATH"
            exit 1
        fi
    done
}

# ---------------------------------------------------------------------------
# PKI setup — Root CA
# ---------------------------------------------------------------------------

setup_root_ca() {
    log "Enabling root PKI engine at ${ROOT_PKI_PATH}/"

    # Enable the PKI engine (idempotent — ignore "already mounted" errors)
    vault secrets enable -path="${ROOT_PKI_PATH}" pki 2>/dev/null || true

    # Tune the max lease TTL to match the root CA TTL
    vault secrets tune -max-lease-ttl="${ROOT_TTL}" "${ROOT_PKI_PATH}/"

    # Generate the root CA certificate
    log "Generating root CA certificate (TTL: ${ROOT_TTL})"
    vault write -format=json "${ROOT_PKI_PATH}/root/generate/internal" \
        common_name="${PKI_ORG} Root CA" \
        organization="${PKI_ORG}" \
        ttl="${ROOT_TTL}" \
        key_type=ec \
        key_bits=384 \
        | jq -r '.data.certificate' > "${CERT_OUTPUT_DIR}/root-ca.pem"

    # Configure the CA and CRL URLs
    vault write "${ROOT_PKI_PATH}/config/urls" \
        issuing_certificates="${VAULT_ADDR}/v1/${ROOT_PKI_PATH}/ca" \
        crl_distribution_points="${VAULT_ADDR}/v1/${ROOT_PKI_PATH}/crl"

    log "Root CA certificate saved to ${CERT_OUTPUT_DIR}/root-ca.pem"
}

# ---------------------------------------------------------------------------
# PKI setup — Intermediate CA
# ---------------------------------------------------------------------------

setup_intermediate_ca() {
    log "Enabling intermediate PKI engine at ${INTERMEDIATE_PKI_PATH}/"

    vault secrets enable -path="${INTERMEDIATE_PKI_PATH}" pki 2>/dev/null || true
    vault secrets tune -max-lease-ttl="${INTERMEDIATE_TTL}" "${INTERMEDIATE_PKI_PATH}/"

    # Generate intermediate CSR
    log "Generating intermediate CA CSR"
    local csr
    csr=$(vault write -format=json "${INTERMEDIATE_PKI_PATH}/intermediate/generate/internal" \
        common_name="${PKI_ORG} Intermediate CA" \
        organization="${PKI_ORG}" \
        key_type=ec \
        key_bits=384 \
        | jq -r '.data.csr')

    # Sign the intermediate CSR with the root CA
    log "Signing intermediate CA with root CA"
    local signed_cert
    signed_cert=$(vault write -format=json "${ROOT_PKI_PATH}/root/sign-intermediate" \
        csr="${csr}" \
        format=pem_bundle \
        ttl="${INTERMEDIATE_TTL}" \
        | jq -r '.data.certificate')

    # Import the signed intermediate certificate
    vault write "${INTERMEDIATE_PKI_PATH}/intermediate/set-signed" \
        certificate="${signed_cert}"

    # Configure URLs for the intermediate
    vault write "${INTERMEDIATE_PKI_PATH}/config/urls" \
        issuing_certificates="${VAULT_ADDR}/v1/${INTERMEDIATE_PKI_PATH}/ca" \
        crl_distribution_points="${VAULT_ADDR}/v1/${INTERMEDIATE_PKI_PATH}/crl"

    log "Intermediate CA configured and signed by root"
}

# ---------------------------------------------------------------------------
# PKI roles — constrain what certificates can be issued
# ---------------------------------------------------------------------------

setup_roles() {
    # Server certificate role — allows SANs under the configured domain
    log "Creating server certificate role: server-${PKI_DOMAIN}"
    vault write "${INTERMEDIATE_PKI_PATH}/roles/server-${PKI_DOMAIN}" \
        allowed_domains="${PKI_DOMAIN}" \
        allow_subdomains=true \
        allow_bare_domains=false \
        enforce_hostnames=true \
        server_flag=true \
        client_flag=false \
        key_type=ec \
        key_bits=256 \
        max_ttl="${LEAF_MAX_TTL}" \
        ttl="${LEAF_TTL}" \
        require_cn=true \
        organization="${PKI_ORG}"

    # Client certificate role — for services authenticating as clients
    log "Creating client certificate role: client-${PKI_DOMAIN}"
    vault write "${INTERMEDIATE_PKI_PATH}/roles/client-${PKI_DOMAIN}" \
        allowed_domains="${PKI_DOMAIN}" \
        allow_subdomains=true \
        allow_bare_domains=false \
        enforce_hostnames=true \
        server_flag=false \
        client_flag=true \
        key_type=ec \
        key_bits=256 \
        max_ttl="${LEAF_MAX_TTL}" \
        ttl="${LEAF_TTL}" \
        require_cn=true \
        organization="${PKI_ORG}"

    log "PKI roles created"
}

# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------

issue_certificate() {
    local role="$1"
    local cn="$2"
    local output_prefix="$3"
    local alt_names="${4:-}"

    log "Issuing certificate: CN=${cn}, role=${role}"

    local issue_args=(
        "${INTERMEDIATE_PKI_PATH}/issue/${role}"
        "common_name=${cn}"
        "ttl=${LEAF_TTL}"
    )

    if [[ -n "${alt_names}" ]]; then
        issue_args+=("alt_names=${alt_names}")
    fi

    local response
    response=$(vault write -format=json "${issue_args[@]}")

    # Extract and save certificate components
    echo "${response}" | jq -r '.data.certificate'     > "${CERT_OUTPUT_DIR}/${output_prefix}.pem"
    echo "${response}" | jq -r '.data.private_key'     > "${CERT_OUTPUT_DIR}/${output_prefix}-key.pem"
    echo "${response}" | jq -r '.data.ca_chain[]'      > "${CERT_OUTPUT_DIR}/${output_prefix}-ca-chain.pem"
    echo "${response}" | jq -r '.data.serial_number'   > "${CERT_OUTPUT_DIR}/${output_prefix}-serial.txt"

    # Restrict private key permissions
    chmod 600 "${CERT_OUTPUT_DIR}/${output_prefix}-key.pem"

    # Build a full chain file (leaf + intermediates + root)
    cat "${CERT_OUTPUT_DIR}/${output_prefix}.pem" \
        "${CERT_OUTPUT_DIR}/${output_prefix}-ca-chain.pem" \
        > "${CERT_OUTPUT_DIR}/${output_prefix}-fullchain.pem"

    local serial expiry
    serial=$(cat "${CERT_OUTPUT_DIR}/${output_prefix}-serial.txt")
    expiry=$(echo "${response}" | jq -r '.data.expiration')

    log "Certificate issued: serial=${serial}, expires=$(date -r "${expiry}" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -d "@${expiry}" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "${expiry}")"
    log "Files: ${CERT_OUTPUT_DIR}/${output_prefix}.pem, ${CERT_OUTPUT_DIR}/${output_prefix}-key.pem"
}

issue_server_cert() {
    local cn="${SERVICE_NAME}.${PKI_DOMAIN}"
    local alt_names="localhost,127.0.0.1"
    issue_certificate "server-${PKI_DOMAIN}" "${cn}" "server" "${alt_names}"
}

issue_client_cert() {
    local cn="${CLIENT_NAME}.${PKI_DOMAIN}"
    issue_certificate "client-${PKI_DOMAIN}" "${cn}" "client"
}

# ---------------------------------------------------------------------------
# Certificate verification
# ---------------------------------------------------------------------------

verify_certificates() {
    log "Verifying certificate chain"

    # Build the CA bundle (root + intermediate)
    cat "${CERT_OUTPUT_DIR}/root-ca.pem" \
        "${CERT_OUTPUT_DIR}/server-ca-chain.pem" \
        > "${CERT_OUTPUT_DIR}/ca-bundle.pem" 2>/dev/null || true

    local exit_code=0

    if [[ -f "${CERT_OUTPUT_DIR}/server.pem" ]]; then
        log "Verifying server certificate..."
        if openssl verify -CAfile "${CERT_OUTPUT_DIR}/ca-bundle.pem" "${CERT_OUTPUT_DIR}/server.pem"; then
            log "Server certificate: VALID"
        else
            log "Server certificate: INVALID"
            exit_code=1
        fi

        log "Server certificate details:"
        openssl x509 -in "${CERT_OUTPUT_DIR}/server.pem" -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true
    fi

    if [[ -f "${CERT_OUTPUT_DIR}/client.pem" ]]; then
        log "Verifying client certificate..."
        if openssl verify -CAfile "${CERT_OUTPUT_DIR}/ca-bundle.pem" "${CERT_OUTPUT_DIR}/client.pem"; then
            log "Client certificate: VALID"
        else
            log "Client certificate: INVALID"
            exit_code=1
        fi

        log "Client certificate details:"
        openssl x509 -in "${CERT_OUTPUT_DIR}/client.pem" -noout -subject -issuer -dates 2>/dev/null || true
    fi

    return ${exit_code}
}

# ---------------------------------------------------------------------------
# Certificate rotation
# ---------------------------------------------------------------------------

rotate_certificates() {
    log "Rotating certificates — issuing new server and client certs"

    # Archive existing certificates
    local archive_dir="${CERT_OUTPUT_DIR}/archive/$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "${archive_dir}"

    for f in server.pem server-key.pem client.pem client-key.pem; do
        if [[ -f "${CERT_OUTPUT_DIR}/${f}" ]]; then
            cp "${CERT_OUTPUT_DIR}/${f}" "${archive_dir}/"
        fi
    done
    log "Archived previous certificates to ${archive_dir}/"

    # Issue fresh certificates
    issue_server_cert
    issue_client_cert

    log "Rotation complete — applications must reload TLS configuration"
    log "Rotation strategies:"
    log "  - Vault Agent template: watches lease and re-renders cert files"
    log "  - Application reload: send SIGHUP or call reload endpoint"
    log "  - Sidecar (Envoy SDS): automatic, no application changes needed"
}

# ---------------------------------------------------------------------------
# mTLS test — start server and client to verify mutual authentication
# ---------------------------------------------------------------------------

test_mtls() {
    log "Testing mTLS with openssl s_server and s_client"

    if [[ ! -f "${CERT_OUTPUT_DIR}/server.pem" ]] || [[ ! -f "${CERT_OUTPUT_DIR}/client.pem" ]]; then
        log "ERROR: server and client certificates must be issued first"
        log "Run: $0 issue-both"
        exit 1
    fi

    local ca_bundle="${CERT_OUTPUT_DIR}/ca-bundle.pem"
    if [[ ! -f "${ca_bundle}" ]]; then
        cat "${CERT_OUTPUT_DIR}/root-ca.pem" "${CERT_OUTPUT_DIR}/server-ca-chain.pem" > "${ca_bundle}"
    fi

    local test_port=8443
    local server_pid=""

    cleanup_test() {
        if [[ -n "${server_pid}" ]]; then
            kill "${server_pid}" 2>/dev/null || true
            wait "${server_pid}" 2>/dev/null || true
        fi
    }
    trap cleanup_test EXIT

    # Start TLS server requiring client certificates
    log "Starting mTLS test server on port ${test_port}..."
    openssl s_server \
        -cert "${CERT_OUTPUT_DIR}/server.pem" \
        -key "${CERT_OUTPUT_DIR}/server-key.pem" \
        -CAfile "${ca_bundle}" \
        -Verify 1 \
        -accept "${test_port}" \
        -www \
        &>/dev/null &
    server_pid=$!
    sleep 1

    # Connect with client certificate
    log "Connecting with client certificate..."
    local result
    if result=$(echo "QUIT" | openssl s_client \
        -cert "${CERT_OUTPUT_DIR}/client.pem" \
        -key "${CERT_OUTPUT_DIR}/client-key.pem" \
        -CAfile "${ca_bundle}" \
        -connect "127.0.0.1:${test_port}" \
        -verify_return_error \
        2>&1); then
        log "mTLS test PASSED — mutual authentication successful"
    else
        log "mTLS test FAILED"
        echo "${result}" >&2
        exit 1
    fi

    # Test without client certificate — should fail
    log "Testing connection WITHOUT client certificate (should fail)..."
    if echo "QUIT" | openssl s_client \
        -CAfile "${ca_bundle}" \
        -connect "127.0.0.1:${test_port}" \
        -verify_return_error \
        2>&1 | grep -q "alert"; then
        log "Correctly rejected connection without client certificate"
    else
        log "WARNING: Server may have accepted connection without client cert"
    fi

    cleanup_test
    trap - EXIT
    log "mTLS test complete"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

check_prereqs

mkdir -p "${CERT_OUTPUT_DIR}"

case "${1:-}" in
    setup)
        setup_root_ca
        setup_intermediate_ca
        setup_roles
        log "PKI setup complete. Next: $0 issue-both"
        ;;
    issue-server)
        issue_server_cert
        ;;
    issue-client)
        issue_client_cert
        ;;
    issue-both)
        issue_server_cert
        issue_client_cert
        log "Both certificates issued. Verify with: $0 verify"
        ;;
    rotate)
        rotate_certificates
        ;;
    verify)
        verify_certificates
        ;;
    test-mtls)
        test_mtls
        ;;
    --help|-h|help)
        show_help
        ;;
    *)
        echo "Usage: $0 {setup|issue-server|issue-client|issue-both|rotate|verify|test-mtls|--help}" >&2
        exit 1
        ;;
esac
