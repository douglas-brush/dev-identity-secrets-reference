#!/usr/bin/env bash
# intermediate_ca_ceremony.sh — Intermediate CA ceremony with Shamir share reconstruction
# Usage: intermediate_ca_ceremony.sh [--algorithm rsa4096|ecdsap384] [--root-cert <path>]
#        [--shares-dir <path>] [--threshold M] [--output-dir <path>] [--path-length <N>]
#        [--validity-days <days>] [--dry-run] [--no-color] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TIMESTAMP_SAFE="${TIMESTAMP//[:T]/-}"

# ── Defaults ──────────────────────────────────────────────────────────────

ALGORITHM="ecdsap384"
ROOT_CERT=""
SHARES_DIR=""
THRESHOLD=3
PATH_LENGTH=0
VALIDITY_DAYS=1825
OUTPUT_DIR=""
DRY_RUN=""
NO_COLOR="${NO_COLOR:-}"
SUBJECT="/C=US/O=Organization/OU=Certificate Authority/CN=Intermediate CA"
CEREMONY_ID="intermediate-$(date -u +%Y%m%d-%H%M%S)-$$"

# ── Color & output ────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

# ── Logging ───────────────────────────────────────────────────────────────

LOG_ENTRIES=()
JSON_EVENTS=()

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} [${level}] ${msg}"
  LOG_ENTRIES+=("$entry")

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

log_json_event() {
  local action="$1" detail="$2" hash="${3:-}" ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local json="{\"timestamp\":\"${ts}\",\"ceremony_id\":\"${CEREMONY_ID}\",\"action\":\"${action}\",\"detail\":\"${detail}\""
  [[ -n "$hash" ]] && json="${json},\"sha256\":\"${hash}\""
  json="${json},\"operator\":\"$(whoami)@$(hostname -s)\",\"dry_run\":${DRY_RUN:-false}}"
  JSON_EVENTS+=("$json")
}

hash_file() {
  local file="$1"
  sha256sum "$file" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$file" | awk '{print $1}'
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'intermediate_ca_ceremony.sh') — Intermediate CA ceremony with Shamir reconstruction

$(_bold 'USAGE')
  intermediate_ca_ceremony.sh [OPTIONS]

$(_bold 'OPTIONS')
  --algorithm <algo>     Key algorithm: rsa4096, ecdsap384 (default: ecdsap384)
  --root-cert <path>     Path to root CA certificate (required)
  --shares-dir <path>    Directory containing Shamir shares (required)
  --threshold <M>        Shares required to reconstruct root key (default: 3)
  --path-length <N>      pathLenConstraint for intermediate cert (default: 0)
  --validity-days <D>    Intermediate cert validity in days (default: 1825)
  --subject <dn>         Certificate subject DN
  --output-dir <path>    Output directory (default: ./ceremony-output/<id>)
  --dry-run              Show what would be done without executing
  --no-color             Disable color output
  --help                 Show this help

$(_bold 'PREREQUISITES')
  - openssl >= 1.1.1
  - ssss-combine (for Shamir reconstruction)
  - Root CA certificate from root CA ceremony
  - M-of-N Shamir shares from key custodians

$(_bold 'EXAMPLES')
  # Sign intermediate CA using reconstructed root key
  intermediate_ca_ceremony.sh \\
    --root-cert ./ceremony-output/root/certs/root-ca.pem \\
    --shares-dir ./collected-shares/ \\
    --threshold 3

  # Dry run
  intermediate_ca_ceremony.sh --root-cert root-ca.pem --shares-dir ./shares --dry-run
EOF
  exit 0
}

# ── Argument parsing ─────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --algorithm)     ALGORITHM="$2"; shift 2 ;;
    --root-cert)     ROOT_CERT="$2"; shift 2 ;;
    --shares-dir)    SHARES_DIR="$2"; shift 2 ;;
    --threshold)     THRESHOLD="$2"; shift 2 ;;
    --path-length)   PATH_LENGTH="$2"; shift 2 ;;
    --validity-days) VALIDITY_DAYS="$2"; shift 2 ;;
    --subject)       SUBJECT="$2"; shift 2 ;;
    --output-dir)    OUTPUT_DIR="$2"; shift 2 ;;
    --dry-run)       DRY_RUN=true; shift ;;
    --no-color)      NO_COLOR=1; shift ;;
    --help|-h)       usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

if [[ -z "$ROOT_CERT" ]]; then
  log ERROR "--root-cert is required (path to root CA certificate)"
  exit 1
fi

if [[ ! -f "$ROOT_CERT" ]] && [[ -z "$DRY_RUN" ]]; then
  log ERROR "Root CA certificate not found: ${ROOT_CERT}"
  exit 1
fi

if [[ -z "$SHARES_DIR" ]]; then
  log ERROR "--shares-dir is required (directory with Shamir shares)"
  exit 1
fi

case "$ALGORITHM" in
  rsa4096|ecdsap384) ;;
  *) log ERROR "Invalid algorithm: $ALGORITHM (must be rsa4096 or ecdsap384)"; exit 1 ;;
esac

# ── Prerequisite checks ──────────────────────────────────────────────────

check_prereqs() {
  log STEP "Checking prerequisites"

  for cmd in openssl; do
    if command -v "$cmd" &>/dev/null; then
      log OK "$cmd found: $(command -v "$cmd")"
    else
      log ERROR "$cmd not found — install before proceeding"; exit 1
    fi
  done

  if ! command -v ssss-combine &>/dev/null; then
    log WARN "ssss-combine not found — will use fallback reconstruction"
    USE_SSSS=false
  else
    log OK "ssss-combine found: $(command -v ssss-combine)"
    USE_SSSS=true
  fi

  log_json_event "prereq_check" "openssl=$(openssl version), ssss=${USE_SSSS:-false}"
}

# ── Setup output directory ────────────────────────────────────────────────

setup_output() {
  log STEP "Setting up ceremony output directory"

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="${SCRIPT_DIR}/ceremony-output/${CEREMONY_ID}"
  fi

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would create directory: ${OUTPUT_DIR}"
    return
  fi

  mkdir -p "${OUTPUT_DIR}"/{keys,certs,csr,logs}
  chmod 700 "${OUTPUT_DIR}/keys"
  log OK "Output directory: ${OUTPUT_DIR}"
  log_json_event "setup" "output_dir=${OUTPUT_DIR}"
}

# ── Validate and count shares ────────────────────────────────────────────

validate_shares() {
  log STEP "Validating collected Shamir shares"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would validate shares in: ${SHARES_DIR}"
    log DRY "Would require at least ${THRESHOLD} valid shares"
    return
  fi

  if [[ ! -d "$SHARES_DIR" ]]; then
    log ERROR "Shares directory not found: ${SHARES_DIR}"
    exit 1
  fi

  local share_count=0
  for f in "${SHARES_DIR}"/share-*; do
    if [[ -f "$f" ]]; then
      share_count=$((share_count + 1))
      local share_hash
      share_hash="$(hash_file "$f")"
      log INFO "Found share: $(basename "$f")"
      log HASH "SHA-256: ${share_hash}"
      log_json_event "validate_share" "file=$(basename "$f")" "$share_hash"
    fi
  done

  if [[ "$share_count" -lt "$THRESHOLD" ]]; then
    log ERROR "Insufficient shares: found ${share_count}, need ${THRESHOLD}"
    exit 1
  fi

  log OK "Found ${share_count} shares (threshold: ${THRESHOLD})"
}

# ── Reconstruct root key from shares ─────────────────────────────────────

reconstruct_root_key() {
  log STEP "Reconstructing root CA key from Shamir shares"

  local reconstructed_key="${OUTPUT_DIR}/keys/root-ca-reconstructed.key"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would reconstruct root key using ${THRESHOLD} shares"
    return
  fi

  if [[ "${USE_SSSS:-false}" == "true" ]]; then
    # Collect threshold number of shares
    local shares_input=""
    local count=0
    for f in "${SHARES_DIR}"/share-*.txt; do
      [[ -f "$f" ]] || continue
      if [[ "$count" -lt "$THRESHOLD" ]]; then
        shares_input+="$(cat "$f")"$'\n'
        count=$((count + 1))
      fi
    done

    local hex_key
    hex_key="$(echo "$shares_input" | ssss-combine -t "$THRESHOLD" -q 2>/dev/null)"
    echo "$hex_key" | xxd -r -p > "$reconstructed_key"
    log OK "Root key reconstructed using ssss-combine"
  else
    log WARN "ssss-combine not available — manual key reconstruction required"
    log INFO "In production, provide the reconstructed root key manually"
    log INFO "Expecting reconstructed key at: ${reconstructed_key}"

    # For ceremony flow: prompt operator to provide reconstructed key
    if [[ -t 0 ]]; then
      printf '\n'
      printf '  %s\n' "$(_yellow 'Manual key reconstruction required')"
      printf '  Place the reconstructed root CA private key at:\n'
      printf '    %s\n' "$reconstructed_key"
      printf '\n'
      read -rp "  Press Enter when the reconstructed key is in place..."
    else
      log ERROR "Non-interactive mode: cannot prompt for manual reconstruction"
      log ERROR "Either install ssss or provide key at: ${reconstructed_key}"
      exit 1
    fi
  fi

  if [[ ! -f "$reconstructed_key" ]]; then
    log ERROR "Reconstructed key not found at: ${reconstructed_key}"
    exit 1
  fi

  chmod 400 "$reconstructed_key"
  local key_hash
  key_hash="$(hash_file "$reconstructed_key")"
  log OK "Reconstructed root key ready"
  log HASH "SHA-256: ${key_hash}"
  log_json_event "reconstruct_key" "method=${USE_SSSS:-manual}" "$key_hash"
}

# ── Generate intermediate CA key ──────────────────────────────────────────

generate_intermediate_key() {
  log STEP "Generating intermediate CA private key (${ALGORITHM})"

  local key_file="${OUTPUT_DIR}/keys/intermediate-ca.key"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would generate ${ALGORITHM} key at ${key_file}"
    return
  fi

  case "$ALGORITHM" in
    rsa4096)
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
        -out "$key_file" 2>/dev/null
      ;;
    ecdsap384)
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
        -out "$key_file" 2>/dev/null
      ;;
  esac

  chmod 400 "$key_file"
  local key_hash
  key_hash="$(hash_file "$key_file")"
  log OK "Intermediate CA key generated: ${key_file}"
  log HASH "SHA-256: ${key_hash}"
  log_json_event "generate_intermediate_key" "algorithm=${ALGORITHM}, file=${key_file}" "$key_hash"
}

# ── Create intermediate CSR ──────────────────────────────────────────────

create_intermediate_csr() {
  log STEP "Creating intermediate CA certificate signing request"

  local key_file="${OUTPUT_DIR}/keys/intermediate-ca.key"
  local csr_file="${OUTPUT_DIR}/csr/intermediate-ca.csr"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would create CSR with subject: ${SUBJECT}"
    return
  fi

  openssl req -new \
    -key "$key_file" \
    -out "$csr_file" \
    -subj "$SUBJECT" \
    -sha384

  local csr_hash
  csr_hash="$(hash_file "$csr_file")"
  log OK "CSR created: ${csr_file}"
  log HASH "SHA-256: ${csr_hash}"
  log_json_event "create_csr" "subject=${SUBJECT}, file=${csr_file}" "$csr_hash"

  # Display CSR details for witness verification
  log INFO "CSR Subject: $(openssl req -in "$csr_file" -noout -subject)"
}

# ── Sign intermediate cert with root CA ───────────────────────────────────

sign_intermediate_cert() {
  log STEP "Signing intermediate CA certificate with root CA"

  local root_key="${OUTPUT_DIR}/keys/root-ca-reconstructed.key"
  local csr_file="${OUTPUT_DIR}/csr/intermediate-ca.csr"
  local cert_file="${OUTPUT_DIR}/certs/intermediate-ca.pem"
  local ext_file="${OUTPUT_DIR}/keys/intermediate-ext.cnf"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would sign intermediate cert using reconstructed root key"
    log DRY "Validity: ${VALIDITY_DAYS} days, pathLenConstraint: ${PATH_LENGTH}"
    return
  fi

  # Write extensions config for intermediate CA
  cat > "$ext_file" <<EXTCNF
[intermediate_ext]
basicConstraints = critical, CA:TRUE, pathlen:${PATH_LENGTH}
keyUsage = critical, keyCertSign, cRLSign, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EXTCNF

  openssl x509 -req \
    -in "$csr_file" \
    -CA "$ROOT_CERT" \
    -CAkey "$root_key" \
    -CAcreateserial \
    -out "$cert_file" \
    -days "$VALIDITY_DAYS" \
    -sha384 \
    -extfile "$ext_file" \
    -extensions intermediate_ext

  chmod 444 "$cert_file"
  local cert_hash
  cert_hash="$(hash_file "$cert_file")"

  local serial not_before not_after
  serial="$(openssl x509 -in "$cert_file" -noout -serial | cut -d= -f2)"
  not_before="$(openssl x509 -in "$cert_file" -noout -startdate | cut -d= -f2)"
  not_after="$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)"

  log OK "Intermediate CA certificate signed: ${cert_file}"
  log INFO "Serial: ${serial}"
  log INFO "Not Before: ${not_before}"
  log INFO "Not After:  ${not_after}"
  log HASH "SHA-256: ${cert_hash}"
  log_json_event "sign_cert" "serial=${serial}, validity=${VALIDITY_DAYS}d, pathlen=${PATH_LENGTH}" "$cert_hash"

  # Verify extensions
  openssl x509 -in "$cert_file" -noout -text | grep -q "CA:TRUE" \
    && log OK "CA:TRUE extension verified" \
    || { log ERROR "CA:TRUE extension missing!"; exit 1; }

  if openssl x509 -in "$cert_file" -noout -text | grep -q "Path Length Constraint"; then
    log OK "pathLenConstraint: ${PATH_LENGTH} verified"
  fi
}

# ── Build certificate chain bundle ───────────────────────────────────────

build_chain_bundle() {
  log STEP "Building certificate chain bundle"

  local cert_file="${OUTPUT_DIR}/certs/intermediate-ca.pem"
  local chain_file="${OUTPUT_DIR}/certs/ca-chain.pem"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would create chain: intermediate + root -> ${chain_file}"
    return
  fi

  cat "$cert_file" "$ROOT_CERT" > "$chain_file"
  chmod 444 "$chain_file"

  local chain_hash
  chain_hash="$(hash_file "$chain_file")"
  log OK "Chain bundle created: ${chain_file}"
  log HASH "SHA-256: ${chain_hash}"
  log_json_event "build_chain" "file=${chain_file}" "$chain_hash"

  # Verify the chain
  if openssl verify -CAfile "$ROOT_CERT" "$cert_file" &>/dev/null; then
    log OK "Certificate chain verified successfully"
    log_json_event "verify_chain" "status=valid"
  else
    log ERROR "Certificate chain verification FAILED"
    log_json_event "verify_chain" "status=FAILED"
    exit 1
  fi
}

# ── Secure cleanup of reconstructed root key ──────────────────────────────

cleanup_reconstructed_key() {
  log STEP "Securely removing reconstructed root CA key"

  local root_key="${OUTPUT_DIR}/keys/root-ca-reconstructed.key"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would securely delete: ${root_key}"
    return
  fi

  if [[ ! -f "$root_key" ]]; then
    log WARN "Reconstructed key not found — may have already been removed"
    return
  fi

  local key_hash
  key_hash="$(hash_file "$root_key")"

  local filesize
  filesize="$(wc -c < "$root_key")"
  dd if=/dev/urandom of="$root_key" bs=1 count="$filesize" conv=notrunc 2>/dev/null
  sync
  rm -f "$root_key"

  log OK "Reconstructed root key securely deleted (hash was: ${key_hash})"
  log_json_event "secure_delete" "file=root-ca-reconstructed.key" "$key_hash"
}

# ── Generate ceremony log ────────────────────────────────────────────────

write_ceremony_log() {
  log STEP "Writing ceremony log"

  local text_log="${OUTPUT_DIR}/logs/ceremony-log.txt"
  local json_log="${OUTPUT_DIR}/logs/ceremony-log.json"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would write ceremony logs"
    return
  fi

  # Text log
  {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  INTERMEDIATE CA KEY CEREMONY LOG"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Ceremony ID:   ${CEREMONY_ID}"
    echo "  Timestamp:     ${TIMESTAMP}"
    echo "  Operator:      $(whoami)@$(hostname -s)"
    echo "  Algorithm:     ${ALGORITHM}"
    echo "  Validity:      ${VALIDITY_DAYS} days"
    echo "  Path Length:   ${PATH_LENGTH}"
    echo "  Root CA Cert:  ${ROOT_CERT}"
    echo "  Shares Used:   ${THRESHOLD} shares from ${SHARES_DIR}"
    echo "  Output Dir:    ${OUTPUT_DIR}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  EVENT LOG"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    for entry in "${LOG_ENTRIES[@]}"; do
      echo "  $entry"
    done
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  WITNESS SIGNATURES"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Witness 1: _________________________ Date: _______________"
    echo ""
    echo "  Witness 2: _________________________ Date: _______________"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
  } > "$text_log"

  # JSON log
  {
    echo "{"
    echo "  \"ceremony_id\": \"${CEREMONY_ID}\","
    echo "  \"type\": \"intermediate_ca_ceremony\","
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"operator\": \"$(whoami)@$(hostname -s)\","
    echo "  \"parameters\": {"
    echo "    \"algorithm\": \"${ALGORITHM}\","
    echo "    \"validity_days\": ${VALIDITY_DAYS},"
    echo "    \"path_length\": ${PATH_LENGTH},"
    echo "    \"root_cert\": \"${ROOT_CERT}\","
    echo "    \"subject\": \"${SUBJECT}\""
    echo "  },"
    echo "  \"events\": ["
    local first=true
    for evt in "${JSON_EVENTS[@]}"; do
      if [[ "$first" == "true" ]]; then
        echo "    ${evt}"
        first=false
      else
        echo "    ,${evt}"
      fi
    done
    echo "  ]"
    echo "}"
  } > "$json_log"

  log OK "Text log:  ${text_log}"
  log OK "JSON log:  ${json_log}"
}

# ── Summary ───────────────────────────────────────────────────────────────

print_summary() {
  printf '\n'
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
  printf '%s\n' "$(_bold '  INTERMEDIATE CA CEREMONY COMPLETE')"
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
  printf '\n'
  printf '  Ceremony ID:   %s\n' "$CEREMONY_ID"
  printf '  Algorithm:     %s\n' "$ALGORITHM"
  printf '  Validity:      %s days\n' "$VALIDITY_DAYS"
  printf '  Path Length:   %s\n' "$PATH_LENGTH"
  printf '\n'

  if [[ -z "$DRY_RUN" ]]; then
    printf '  %s\n' "$(_bold 'Output Files:')"
    printf '    Intermediate Key:  %s\n' "${OUTPUT_DIR}/keys/intermediate-ca.key"
    printf '    Intermediate Cert: %s\n' "${OUTPUT_DIR}/certs/intermediate-ca.pem"
    printf '    Chain Bundle:      %s\n' "${OUTPUT_DIR}/certs/ca-chain.pem"
    printf '    Ceremony Log:      %s\n' "${OUTPUT_DIR}/logs/ceremony-log.json"
    printf '\n'
    printf '  %s\n' "$(_yellow 'NEXT STEPS:')"
    printf '    1. Verify chain: openssl verify -CAfile root-ca.pem intermediate-ca.pem\n'
    printf '    2. Import into Vault: import_to_vault.sh --cert-dir %s/certs\n' "$OUTPUT_DIR"
    printf '    3. Collect witness signatures on the ceremony log\n'
    printf '    4. Confirm reconstructed root key was securely deleted\n'
    printf '    5. Store ceremony log in tamper-evident storage\n'
  else
    printf '  %s\n' "$(_yellow 'DRY RUN — no files were created')"
  fi

  printf '\n'
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  printf '\n'
  printf '%s\n' "$(_bold '  Intermediate CA Key Ceremony')"
  printf '%s\n' "$(_dim "  ${CEREMONY_ID}")"
  printf '\n'

  if [[ -n "$DRY_RUN" ]]; then
    log WARN "DRY RUN MODE — no changes will be made"
  fi

  log_json_event "ceremony_start" "algorithm=${ALGORITHM}, threshold=${THRESHOLD}, path_length=${PATH_LENGTH}"

  check_prereqs
  setup_output
  validate_shares
  reconstruct_root_key
  generate_intermediate_key
  create_intermediate_csr
  sign_intermediate_cert
  build_chain_bundle
  cleanup_reconstructed_key
  write_ceremony_log

  log_json_event "ceremony_complete" "status=success"

  print_summary
}

main
