#!/usr/bin/env bash
# import_to_vault.sh — Import ceremony output into HashiCorp Vault PKI backend
# Usage: import_to_vault.sh [--vault-mount <path>] [--cert-dir <path>]
#        [--crl-url <url>] [--ocsp-url <url>] [--dry-run] [--no-color] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

VAULT_MOUNT="pki"
VAULT_INT_MOUNT="pki_int"
CERT_DIR=""
CRL_URL=""
OCSP_URL=""
DRY_RUN=""
NO_COLOR="${NO_COLOR:-}"
MAX_LEASE_TTL="87600h"        # 10 years for root
INT_MAX_LEASE_TTL="43800h"    # 5 years for intermediate

# ── Color & output ────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

LOG_ENTRIES=()

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  LOG_ENTRIES+=("${ts} [${level}] ${msg}")

  case "$level" in
    INFO)   printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)   printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR)  printf '  %s %s\n' "$(_red 'ERROR')" "$msg" ;;
    OK)     printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    DRY)    printf '  %s %s\n' "$(_yellow ' DRY')" "$msg" ;;
    STEP)   printf '\n%s %s\n' "$(_bold '==>')" "$(_bold "$msg")" ;;
    HASH)   printf '  %s %s\n' "$(_dim 'HASH')" "$msg" ;;
  esac
}

hash_file() {
  local file="$1"
  sha256sum "$file" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$file" | awk '{print $1}'
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'import_to_vault.sh') — Import ceremony certificates into Vault PKI backend

$(_bold 'USAGE')
  import_to_vault.sh [OPTIONS]

$(_bold 'OPTIONS')
  --vault-mount <path>      Root PKI mount path (default: pki)
  --vault-int-mount <path>  Intermediate PKI mount path (default: pki_int)
  --cert-dir <path>         Directory containing ceremony certs (required)
  --crl-url <url>           CRL distribution point URL
  --ocsp-url <url>          OCSP responder URL
  --max-lease-ttl <ttl>     Root PKI max lease TTL (default: 87600h)
  --int-max-lease-ttl <ttl> Intermediate PKI max lease TTL (default: 43800h)
  --dry-run                 Show what would be done without executing
  --no-color                Disable color output
  --help                    Show this help

$(_bold 'PREREQUISITES')
  - vault CLI authenticated and configured (VAULT_ADDR, VAULT_TOKEN)
  - Certificate files from ceremony:
    - root-ca.pem         (root CA certificate)
    - intermediate-ca.pem (intermediate CA certificate)
    - intermediate-ca.key (intermediate CA private key)
    - ca-chain.pem        (certificate chain bundle)

$(_bold 'ENVIRONMENT')
  VAULT_ADDR    Vault server address (required)
  VAULT_TOKEN   Vault authentication token (required)

$(_bold 'EXAMPLES')
  # Import ceremony output into Vault
  import_to_vault.sh --cert-dir ./ceremony-output/certs \\
    --crl-url https://pki.example.com/crl \\
    --ocsp-url https://pki.example.com/ocsp

  # Dry run with custom mount paths
  import_to_vault.sh --cert-dir ./certs \\
    --vault-mount pki_root --vault-int-mount pki_intermediate \\
    --dry-run
EOF
  exit 0
}

# ── Argument parsing ─────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-mount)       VAULT_MOUNT="$2"; shift 2 ;;
    --vault-int-mount)   VAULT_INT_MOUNT="$2"; shift 2 ;;
    --cert-dir)          CERT_DIR="$2"; shift 2 ;;
    --crl-url)           CRL_URL="$2"; shift 2 ;;
    --ocsp-url)          OCSP_URL="$2"; shift 2 ;;
    --max-lease-ttl)     MAX_LEASE_TTL="$2"; shift 2 ;;
    --int-max-lease-ttl) INT_MAX_LEASE_TTL="$2"; shift 2 ;;
    --dry-run)           DRY_RUN=true; shift ;;
    --no-color)          NO_COLOR=1; shift ;;
    --help|-h)           usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

if [[ -z "$CERT_DIR" ]]; then
  log ERROR "--cert-dir is required"
  exit 1
fi

# ── Prerequisite checks ──────────────────────────────────────────────────

check_prereqs() {
  log STEP "Checking prerequisites"

  # Check vault CLI
  if command -v vault &>/dev/null; then
    log OK "vault CLI found: $(command -v vault)"
    log INFO "Vault version: $(vault version 2>/dev/null || echo 'unknown')"
  else
    log ERROR "vault CLI not found — install HashiCorp Vault"
    exit 1
  fi

  # Check environment
  if [[ -z "${VAULT_ADDR:-}" ]]; then
    log ERROR "VAULT_ADDR not set — export VAULT_ADDR=https://vault.example.com:8200"
    exit 1
  fi
  log OK "VAULT_ADDR: ${VAULT_ADDR}"

  if [[ -z "${VAULT_TOKEN:-}" ]] && [[ -z "$DRY_RUN" ]]; then
    log WARN "VAULT_TOKEN not set — vault CLI must be otherwise authenticated"
  fi

  # Verify vault connectivity
  if [[ -z "$DRY_RUN" ]]; then
    if vault status &>/dev/null; then
      log OK "Vault is reachable and unsealed"
    else
      log ERROR "Cannot connect to Vault at ${VAULT_ADDR}"
      exit 1
    fi
  fi
}

# ── Validate certificate files ────────────────────────────────────────────

validate_certs() {
  log STEP "Validating certificate files"

  local root_cert="${CERT_DIR}/root-ca.pem"
  local int_cert="${CERT_DIR}/intermediate-ca.pem"
  local int_key="${CERT_DIR}/../keys/intermediate-ca.key"
  local chain="${CERT_DIR}/ca-chain.pem"

  # Check for cert files, also try parent keys dir for the key
  if [[ ! -f "$int_key" ]]; then
    int_key="${CERT_DIR}/intermediate-ca.key"
  fi

  for f in "$root_cert" "$int_cert" "$chain"; do
    if [[ -f "$f" ]]; then
      local fhash
      fhash="$(hash_file "$f")"
      log OK "Found: $(basename "$f")"
      log HASH "SHA-256: ${fhash}"
    elif [[ -z "$DRY_RUN" ]]; then
      log ERROR "Missing: $f"
      exit 1
    else
      log DRY "Would check: $f"
    fi
  done

  if [[ -f "$int_key" ]]; then
    log OK "Found: intermediate CA key"
  elif [[ -z "$DRY_RUN" ]]; then
    log WARN "Intermediate CA key not found — will import cert-only (key managed externally)"
  fi

  # Verify chain
  if [[ -z "$DRY_RUN" ]] && [[ -f "$root_cert" ]] && [[ -f "$int_cert" ]]; then
    if openssl verify -CAfile "$root_cert" "$int_cert" &>/dev/null; then
      log OK "Certificate chain valid (intermediate signed by root)"
    else
      log ERROR "Certificate chain verification FAILED"
      exit 1
    fi
  fi
}

# ── Enable and configure root PKI mount ──────────────────────────────────

setup_root_pki() {
  log STEP "Configuring root PKI mount: ${VAULT_MOUNT}"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would enable secrets engine at ${VAULT_MOUNT}"
    log DRY "Would set max_lease_ttl=${MAX_LEASE_TTL}"
    log DRY "Would import root CA certificate"
    return
  fi

  # Enable PKI mount if not already enabled
  if vault secrets list -format=json 2>/dev/null | grep -q "\"${VAULT_MOUNT}/\""; then
    log INFO "PKI mount ${VAULT_MOUNT}/ already enabled"
  else
    vault secrets enable -path="${VAULT_MOUNT}" \
      -max-lease-ttl="${MAX_LEASE_TTL}" \
      pki
    log OK "PKI mount ${VAULT_MOUNT}/ enabled"
  fi

  # Tune the mount
  vault secrets tune -max-lease-ttl="${MAX_LEASE_TTL}" "${VAULT_MOUNT}/"
  log OK "Max lease TTL set to ${MAX_LEASE_TTL}"

  # Import root CA certificate as trusted root
  local root_cert="${CERT_DIR}/root-ca.pem"
  local root_pem
  root_pem="$(cat "$root_cert")"

  vault write "${VAULT_MOUNT}/config/ca" pem_bundle="$root_pem"
  log OK "Root CA certificate imported into ${VAULT_MOUNT}/config/ca"
}

# ── Enable and configure intermediate PKI mount ──────────────────────────

setup_intermediate_pki() {
  log STEP "Configuring intermediate PKI mount: ${VAULT_INT_MOUNT}"

  local int_cert="${CERT_DIR}/intermediate-ca.pem"
  local int_key="${CERT_DIR}/../keys/intermediate-ca.key"
  local chain="${CERT_DIR}/ca-chain.pem"

  if [[ ! -f "$int_key" ]]; then
    int_key="${CERT_DIR}/intermediate-ca.key"
  fi

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would enable secrets engine at ${VAULT_INT_MOUNT}"
    log DRY "Would set max_lease_ttl=${INT_MAX_LEASE_TTL}"
    log DRY "Would import intermediate CA certificate + key"
    log DRY "Would set CA chain"
    return
  fi

  # Enable intermediate PKI mount if not already enabled
  if vault secrets list -format=json 2>/dev/null | grep -q "\"${VAULT_INT_MOUNT}/\""; then
    log INFO "PKI mount ${VAULT_INT_MOUNT}/ already enabled"
  else
    vault secrets enable -path="${VAULT_INT_MOUNT}" \
      -max-lease-ttl="${INT_MAX_LEASE_TTL}" \
      pki
    log OK "PKI mount ${VAULT_INT_MOUNT}/ enabled"
  fi

  # Tune the mount
  vault secrets tune -max-lease-ttl="${INT_MAX_LEASE_TTL}" "${VAULT_INT_MOUNT}/"
  log OK "Max lease TTL set to ${INT_MAX_LEASE_TTL}"

  # Build PEM bundle: key + cert + chain
  local pem_bundle=""
  if [[ -f "$int_key" ]]; then
    pem_bundle="$(cat "$int_key")"$'\n'
  fi
  pem_bundle+="$(cat "$int_cert")"$'\n'
  pem_bundle+="$(cat "${CERT_DIR}/root-ca.pem")"

  vault write "${VAULT_INT_MOUNT}/config/ca" pem_bundle="$pem_bundle"
  log OK "Intermediate CA certificate + key imported into ${VAULT_INT_MOUNT}/config/ca"

  # Set the CA chain
  vault write "${VAULT_INT_MOUNT}/config/ca" pem_bundle="$(cat "$chain")"
  log OK "CA chain bundle set"
}

# ── Configure CRL and OCSP URLs ──────────────────────────────────────────

configure_urls() {
  log STEP "Configuring CRL and OCSP URLs"

  if [[ -z "$CRL_URL" ]] && [[ -z "$OCSP_URL" ]]; then
    log WARN "No CRL or OCSP URLs specified — skipping URL configuration"
    log INFO "Use --crl-url and --ocsp-url to configure distribution points"
    return
  fi

  if [[ -n "$DRY_RUN" ]]; then
    [[ -n "$CRL_URL" ]] && log DRY "Would set CRL URL: ${CRL_URL}"
    [[ -n "$OCSP_URL" ]] && log DRY "Would set OCSP URL: ${OCSP_URL}"
    return
  fi

  local url_args=()
  [[ -n "$CRL_URL" ]] && url_args+=(crl_distribution_points="$CRL_URL")
  [[ -n "$OCSP_URL" ]] && url_args+=(ocsp_servers="$OCSP_URL")

  # Configure on intermediate mount (the issuing CA)
  vault write "${VAULT_INT_MOUNT}/config/urls" \
    issuing_certificates="${VAULT_ADDR}/v1/${VAULT_INT_MOUNT}/ca" \
    "${url_args[@]}"

  [[ -n "$CRL_URL" ]] && log OK "CRL distribution point: ${CRL_URL}"
  [[ -n "$OCSP_URL" ]] && log OK "OCSP responder: ${OCSP_URL}"
  log OK "Issuing certificate URL: ${VAULT_ADDR}/v1/${VAULT_INT_MOUNT}/ca"
}

# ── Verify import ─────────────────────────────────────────────────────────

verify_import() {
  log STEP "Verifying Vault PKI configuration"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would verify root CA in ${VAULT_MOUNT}"
    log DRY "Would verify intermediate CA in ${VAULT_INT_MOUNT}"
    log DRY "Would verify chain of trust"
    return
  fi

  # Read back root CA
  local root_ca_vault
  root_ca_vault="$(vault read -field=certificate "${VAULT_MOUNT}/cert/ca" 2>/dev/null || true)"
  if [[ -n "$root_ca_vault" ]]; then
    local vault_root_serial
    vault_root_serial="$(echo "$root_ca_vault" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)"
    log OK "Root CA in Vault — serial: ${vault_root_serial}"
  else
    log ERROR "Root CA not found in Vault at ${VAULT_MOUNT}/cert/ca"
  fi

  # Read back intermediate CA
  local int_ca_vault
  int_ca_vault="$(vault read -field=certificate "${VAULT_INT_MOUNT}/cert/ca" 2>/dev/null || true)"
  if [[ -n "$int_ca_vault" ]]; then
    local vault_int_serial vault_int_issuer
    vault_int_serial="$(echo "$int_ca_vault" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)"
    vault_int_issuer="$(echo "$int_ca_vault" | openssl x509 -noout -issuer 2>/dev/null)"
    log OK "Intermediate CA in Vault — serial: ${vault_int_serial}"
    log INFO "Issuer: ${vault_int_issuer}"
  else
    log ERROR "Intermediate CA not found in Vault at ${VAULT_INT_MOUNT}/cert/ca"
  fi

  # Verify chain: intermediate should be signed by root
  if [[ -n "$root_ca_vault" ]] && [[ -n "$int_ca_vault" ]]; then
    local tmp_root tmp_int
    tmp_root="$(mktemp)"
    tmp_int="$(mktemp)"
    echo "$root_ca_vault" > "$tmp_root"
    echo "$int_ca_vault" > "$tmp_int"

    if openssl verify -CAfile "$tmp_root" "$tmp_int" &>/dev/null; then
      log OK "Chain of trust verified in Vault"
    else
      log ERROR "Chain of trust verification FAILED in Vault"
    fi

    rm -f "$tmp_root" "$tmp_int"
  fi

  # Check URLs
  local urls
  urls="$(vault read -format=json "${VAULT_INT_MOUNT}/config/urls" 2>/dev/null || true)"
  if [[ -n "$urls" ]]; then
    log OK "URL configuration present on ${VAULT_INT_MOUNT}"
  fi
}

# ── Summary ───────────────────────────────────────────────────────────────

print_summary() {
  printf '\n'
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
  printf '%s\n' "$(_bold '  VAULT PKI IMPORT COMPLETE')"
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
  printf '\n'
  printf '  Root PKI Mount:         %s/\n' "$VAULT_MOUNT"
  printf '  Intermediate PKI Mount: %s/\n' "$VAULT_INT_MOUNT"
  printf '  Vault Address:          %s\n' "${VAULT_ADDR:-not set}"
  printf '\n'

  if [[ -z "$DRY_RUN" ]]; then
    printf '  %s\n' "$(_bold 'Vault Endpoints:')"
    printf '    Root CA:         %s/v1/%s/ca\n' "${VAULT_ADDR}" "$VAULT_MOUNT"
    printf '    Intermediate CA: %s/v1/%s/ca\n' "${VAULT_ADDR}" "$VAULT_INT_MOUNT"
    printf '    CRL:             %s/v1/%s/crl\n' "${VAULT_ADDR}" "$VAULT_INT_MOUNT"
    printf '\n'
    printf '  %s\n' "$(_yellow 'NEXT STEPS:')"
    printf '    1. Create PKI roles: vault write %s/roles/<name> ...\n' "$VAULT_INT_MOUNT"
    printf '    2. Test certificate issuance from the intermediate CA\n'
    printf '    3. Configure applications to use Vault-issued certificates\n'
    printf '    4. Set up CRL rotation: vault write %s/config/crl expiry=72h\n' "$VAULT_INT_MOUNT"
  else
    printf '  %s\n' "$(_yellow 'DRY RUN — no Vault changes were made')"
  fi

  printf '\n'
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  printf '\n'
  printf '%s\n' "$(_bold '  Vault PKI Import')"
  printf '%s\n' "$(_dim "  ${TIMESTAMP}")"
  printf '\n'

  if [[ -n "$DRY_RUN" ]]; then
    log WARN "DRY RUN MODE — no Vault changes will be made"
  fi

  check_prereqs
  validate_certs
  setup_root_pki
  setup_intermediate_pki
  configure_urls
  verify_import

  print_summary
}

main
