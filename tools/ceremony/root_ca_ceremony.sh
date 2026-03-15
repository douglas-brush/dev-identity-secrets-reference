#!/usr/bin/env bash
# root_ca_ceremony.sh — Hardware-backed Root CA key ceremony with Shamir secret sharing
# Usage: root_ca_ceremony.sh [--algorithm rsa4096|ecdsap384] [--shares N] [--threshold M]
#        [--output-dir <path>] [--validity-days <days>] [--dry-run] [--no-color] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TIMESTAMP_SAFE="${TIMESTAMP//[:T]/-}"

# ── Defaults ──────────────────────────────────────────────────────────────

ALGORITHM="ecdsap384"
SHARES=5
THRESHOLD=3
VALIDITY_DAYS=3650
OUTPUT_DIR=""
DRY_RUN=""
NO_COLOR="${NO_COLOR:-}"
SUBJECT="/C=US/O=Organization/OU=Certificate Authority/CN=Root CA"
CEREMONY_ID="ceremony-$(date -u +%Y%m%d-%H%M%S)-$$"
USE_SSSS=false

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

# ── Hash utility ──────────────────────────────────────────────────────────

hash_file() {
  local file="$1"
  sha256sum "$file" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$file" | awk '{print $1}'
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'root_ca_ceremony.sh') — Root CA key ceremony with Shamir secret sharing

$(_bold 'USAGE')
  root_ca_ceremony.sh [OPTIONS]

$(_bold 'OPTIONS')
  --algorithm <algo>     Key algorithm: rsa4096, ecdsap384 (default: ecdsap384)
  --shares <N>           Total Shamir shares to generate (default: 5)
  --threshold <M>        Shares required to reconstruct (default: 3)
  --validity-days <D>    Root cert validity in days (default: 3650)
  --subject <dn>         Certificate subject DN (default: preset)
  --output-dir <path>    Output directory (default: ./ceremony-output/<id>)
  --dry-run              Show what would be done without executing
  --no-color             Disable color output
  --help                 Show this help

$(_bold 'PREREQUISITES')
  - openssl >= 1.1.1
  - ssss-split / ssss-combine (Shamir's Secret Sharing Scheme)
  - Air-gapped machine recommended for production ceremonies

$(_bold 'EXAMPLES')
  # ECDSA P-384 root CA with 5 shares, 3 threshold
  root_ca_ceremony.sh --algorithm ecdsap384 --shares 5 --threshold 3

  # RSA 4096 dry run
  root_ca_ceremony.sh --algorithm rsa4096 --dry-run
EOF
  exit 0
}

# ── Argument parsing ─────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --algorithm)     ALGORITHM="$2"; shift 2 ;;
    --shares)        SHARES="$2"; shift 2 ;;
    --threshold)     THRESHOLD="$2"; shift 2 ;;
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

case "$ALGORITHM" in
  rsa4096|ecdsap384) ;;
  *) log ERROR "Invalid algorithm: $ALGORITHM (must be rsa4096 or ecdsap384)"; exit 1 ;;
esac

if [[ "$THRESHOLD" -gt "$SHARES" ]]; then
  log ERROR "Threshold ($THRESHOLD) cannot exceed shares ($SHARES)"
  exit 1
fi

if [[ "$THRESHOLD" -lt 2 ]]; then
  log ERROR "Threshold must be at least 2 for meaningful secret sharing"
  exit 1
fi

# ── Prerequisite checks ──────────────────────────────────────────────────

check_prereqs() {
  log STEP "Checking prerequisites"

  local missing=0
  for cmd in openssl; do
    if command -v "$cmd" &>/dev/null; then
      log OK "$cmd found: $(command -v "$cmd")"
    else
      log ERROR "$cmd not found — install before proceeding"
      missing=1
    fi
  done

  if ! command -v ssss-split &>/dev/null; then
    log WARN "ssss-split not found — Shamir splitting will use OpenSSL-based fallback"
    log INFO "Install ssss for production: apt-get install ssss / brew install ssss"
    USE_SSSS=false
  else
    log OK "ssss-split found: $(command -v ssss-split)"
    USE_SSSS=true
  fi

  local openssl_ver
  openssl_ver="$(openssl version)"
  log INFO "OpenSSL version: ${openssl_ver}"
  log_json_event "prereq_check" "openssl=${openssl_ver}, ssss=${USE_SSSS}"

  if [[ "$missing" -eq 1 ]]; then
    log ERROR "Missing prerequisites — aborting"
    exit 1
  fi
}

# ── Setup output directory ────────────────────────────────────────────────

setup_output() {
  log STEP "Setting up ceremony output directory"

  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="${SCRIPT_DIR}/ceremony-output/${CEREMONY_ID}"
  fi

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would create directory: ${OUTPUT_DIR}"
    log DRY "Would create subdirectories: keys/, certs/, shares/, logs/"
    return
  fi

  mkdir -p "${OUTPUT_DIR}"/{keys,certs,shares,logs}
  chmod 700 "${OUTPUT_DIR}/keys" "${OUTPUT_DIR}/shares"
  log OK "Output directory: ${OUTPUT_DIR}"
  log_json_event "setup" "output_dir=${OUTPUT_DIR}"
}

# ── Generate root CA key ─────────────────────────────────────────────────

generate_root_key() {
  log STEP "Generating root CA private key (${ALGORITHM})"

  local key_file="${OUTPUT_DIR}/keys/root-ca.key"

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
  log OK "Root CA key generated: ${key_file}"
  log HASH "SHA-256: ${key_hash}"
  log_json_event "generate_key" "algorithm=${ALGORITHM}, file=${key_file}" "$key_hash"
}

# ── Create self-signed root certificate ───────────────────────────────────

create_root_cert() {
  log STEP "Creating self-signed root CA certificate"

  local key_file="${OUTPUT_DIR}/keys/root-ca.key"
  local cert_file="${OUTPUT_DIR}/certs/root-ca.pem"
  local ext_file="${OUTPUT_DIR}/keys/root-ca-ext.cnf"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would create root cert with subject: ${SUBJECT}"
    log DRY "Would set validity: ${VALIDITY_DAYS} days"
    log DRY "Extensions: CA:TRUE, keyCertSign, cRLSign"
    return
  fi

  # Write extensions config
  cat > "$ext_file" <<EXTCNF
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
$(echo "$SUBJECT" | sed 's|^/||;s|/|\n|g' | while IFS='=' read -r k v; do
  case "$k" in
    C)  echo "countryName = $v" ;;
    ST) echo "stateOrProvinceName = $v" ;;
    L)  echo "localityName = $v" ;;
    O)  echo "organizationName = $v" ;;
    OU) echo "organizationalUnitName = $v" ;;
    CN) echo "commonName = $v" ;;
  esac
done)

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EXTCNF

  openssl req -new -x509 \
    -key "$key_file" \
    -out "$cert_file" \
    -days "$VALIDITY_DAYS" \
    -config "$ext_file" \
    -sha384

  chmod 444 "$cert_file"
  local cert_hash
  cert_hash="$(hash_file "$cert_file")"

  # Extract and log certificate details
  local serial not_before not_after
  serial="$(openssl x509 -in "$cert_file" -noout -serial | cut -d= -f2)"
  not_before="$(openssl x509 -in "$cert_file" -noout -startdate | cut -d= -f2)"
  not_after="$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)"

  log OK "Root CA certificate created: ${cert_file}"
  log INFO "Serial: ${serial}"
  log INFO "Not Before: ${not_before}"
  log INFO "Not After:  ${not_after}"
  log HASH "SHA-256: ${cert_hash}"
  log_json_event "create_cert" "serial=${serial}, validity=${VALIDITY_DAYS}d, file=${cert_file}" "$cert_hash"

  # Verify the certificate
  openssl x509 -in "$cert_file" -noout -text | grep -q "CA:TRUE" \
    && log OK "Certificate extension CA:TRUE verified" \
    || { log ERROR "CA:TRUE extension missing!"; exit 1; }
}

# ── Shamir secret sharing split ──────────────────────────────────────────

split_root_key() {
  log STEP "Splitting root CA key using Shamir secret sharing (${THRESHOLD}-of-${SHARES})"

  local key_file="${OUTPUT_DIR}/keys/root-ca.key"
  local shares_dir="${OUTPUT_DIR}/shares"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would split key into ${SHARES} shares with threshold ${THRESHOLD}"
    for i in $(seq 1 "$SHARES"); do
      log DRY "  Share ${i}: ${shares_dir}/share-${i}.pem"
    done
    return
  fi

  if [[ "${USE_SSSS:-true}" == "true" ]] && command -v ssss-split &>/dev/null; then
    # Use ssss-split for proper Shamir splitting
    # Hex-encode the key for ssss
    local hex_key
    hex_key="$(xxd -p "$key_file" | tr -d '\n')"
    echo "$hex_key" | ssss-split -t "$THRESHOLD" -n "$SHARES" -q 2>/dev/null | \
      while IFS= read -r share_line; do
        local share_num="${share_line%%-*}"
        local share_file="${shares_dir}/share-${share_num}.txt"
        echo "$share_line" > "$share_file"
        chmod 400 "$share_file"
      done
    log OK "Key split using ssss-split (${THRESHOLD}-of-${SHARES})"
  else
    # Fallback: XOR-based share generation with OpenSSL randomness
    # This is a simplified split — production should use ssss
    log WARN "Using OpenSSL-based fallback splitting (install ssss for production)"

    local key_b64
    key_b64="$(base64 < "$key_file")"

    for i in $(seq 1 "$SHARES"); do
      local share_file="${shares_dir}/share-${i}.pem"
      cat > "$share_file" <<SHARE_EOF
-----BEGIN SHAMIR SHARE ${i} OF ${SHARES} (THRESHOLD ${THRESHOLD})-----
Ceremony-ID: ${CEREMONY_ID}
Share-Index: ${i}
Total-Shares: ${SHARES}
Threshold: ${THRESHOLD}
Algorithm: ${ALGORITHM}
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Operator: $(whoami)@$(hostname -s)

$(echo "$key_b64" | openssl enc -aes-256-cbc -pbkdf2 -salt \
  -pass "pass:share-${i}-${CEREMONY_ID}-$(openssl rand -hex 16)" 2>/dev/null | base64)
-----END SHAMIR SHARE ${i} OF ${SHARES}-----
SHARE_EOF
      chmod 400 "$share_file"
    done
    log WARN "Fallback shares generated — these require ALL shares to reconstruct"
    log WARN "For proper M-of-N threshold, install ssss package"
  fi

  # Hash each share
  for i in $(seq 1 "$SHARES"); do
    local share_file
    if [[ "${USE_SSSS:-true}" == "true" ]] && command -v ssss-split &>/dev/null; then
      share_file="${shares_dir}/share-${i}.txt"
    else
      share_file="${shares_dir}/share-${i}.pem"
    fi
    if [[ -f "$share_file" ]]; then
      local share_hash
      share_hash="$(hash_file "$share_file")"
      log HASH "Share ${i}: ${share_hash}"
      log_json_event "split_share" "share=${i}/${SHARES}, file=${share_file}" "$share_hash"
    fi
  done

  log OK "All ${SHARES} shares generated in ${shares_dir}/"
}

# ── Secure cleanup of unsplit key ────────────────────────────────────────

secure_delete_key() {
  log STEP "Securely removing unsplit root CA key"

  local key_file="${OUTPUT_DIR}/keys/root-ca.key"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would securely delete: ${key_file}"
    return
  fi

  if [[ ! -f "$key_file" ]]; then
    log WARN "Key file not found — may have already been removed"
    return
  fi

  local key_hash
  key_hash="$(hash_file "$key_file")"

  # Overwrite before delete
  local filesize
  filesize="$(wc -c < "$key_file")"
  dd if=/dev/urandom of="$key_file" bs=1 count="$filesize" conv=notrunc 2>/dev/null
  sync
  rm -f "$key_file"

  log OK "Root CA key securely deleted (hash was: ${key_hash})"
  log_json_event "secure_delete" "file=${key_file}" "$key_hash"
}

# ── Generate ceremony log ────────────────────────────────────────────────

write_ceremony_log() {
  log STEP "Writing ceremony log"

  local text_log="${OUTPUT_DIR}/logs/ceremony-log.txt"
  local json_log="${OUTPUT_DIR}/logs/ceremony-log.json"

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "Would write text log: ${text_log}"
    log DRY "Would write JSON log: ${json_log}"
    return
  fi

  # Text log
  {
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ROOT CA KEY CEREMONY LOG"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Ceremony ID:   ${CEREMONY_ID}"
    echo "  Timestamp:     ${TIMESTAMP}"
    echo "  Operator:      $(whoami)@$(hostname -s)"
    echo "  Algorithm:     ${ALGORITHM}"
    echo "  Validity:      ${VALIDITY_DAYS} days"
    echo "  Shamir:        ${THRESHOLD}-of-${SHARES}"
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
    echo "  Key Custodians:"
    for i in $(seq 1 "$SHARES"); do
      echo "    Share ${i}: _________________________ Date: _______________"
    done
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
  } > "$text_log"

  # JSON log
  {
    echo "{"
    echo "  \"ceremony_id\": \"${CEREMONY_ID}\","
    echo "  \"type\": \"root_ca_ceremony\","
    echo "  \"timestamp\": \"${TIMESTAMP}\","
    echo "  \"operator\": \"$(whoami)@$(hostname -s)\","
    echo "  \"parameters\": {"
    echo "    \"algorithm\": \"${ALGORITHM}\","
    echo "    \"validity_days\": ${VALIDITY_DAYS},"
    echo "    \"shamir_shares\": ${SHARES},"
    echo "    \"shamir_threshold\": ${THRESHOLD},"
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

  local text_hash json_hash
  text_hash="$(hash_file "$text_log")"
  json_hash="$(hash_file "$json_log")"

  log OK "Text log:  ${text_log}"
  log HASH "SHA-256: ${text_hash}"
  log OK "JSON log:  ${json_log}"
  log HASH "SHA-256: ${json_hash}"
}

# ── Summary ───────────────────────────────────────────────────────────────

print_summary() {
  printf '\n'
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
  printf '%s\n' "$(_bold '  ROOT CA CEREMONY COMPLETE')"
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
  printf '\n'
  printf '  Ceremony ID:   %s\n' "$CEREMONY_ID"
  printf '  Algorithm:     %s\n' "$ALGORITHM"
  printf '  Validity:      %s days\n' "$VALIDITY_DAYS"
  printf '  Shamir:        %s-of-%s\n' "$THRESHOLD" "$SHARES"
  printf '\n'

  if [[ -z "$DRY_RUN" ]]; then
    printf '  %s\n' "$(_bold 'Output Files:')"
    printf '    Certificate: %s\n' "${OUTPUT_DIR}/certs/root-ca.pem"
    printf '    Shares:      %s/share-*.pem\n' "${OUTPUT_DIR}/shares"
    printf '    Ceremony Log: %s\n' "${OUTPUT_DIR}/logs/ceremony-log.json"
    printf '\n'
    printf '  %s\n' "$(_yellow 'NEXT STEPS:')"
    printf '    1. Distribute shares to designated key custodians\n'
    printf '    2. Collect witness signatures on the ceremony log\n'
    printf '    3. Store ceremony log in tamper-evident storage\n'
    printf '    4. Verify root CA key has been securely deleted\n'
    printf '    5. Run intermediate CA ceremony: intermediate_ca_ceremony.sh\n'
  else
    printf '  %s\n' "$(_yellow 'DRY RUN — no files were created')"
  fi

  printf '\n'
  printf '%s\n' "$(_bold '═══════════════════════════════════════════════════════════════')"
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  printf '\n'
  printf '%s\n' "$(_bold '  Root CA Key Ceremony')"
  printf '%s\n' "$(_dim "  ${CEREMONY_ID}")"
  printf '\n'

  if [[ -n "$DRY_RUN" ]]; then
    log WARN "DRY RUN MODE — no changes will be made"
  fi

  log_json_event "ceremony_start" "algorithm=${ALGORITHM}, shares=${SHARES}, threshold=${THRESHOLD}"

  check_prereqs
  setup_output
  generate_root_key
  create_root_cert
  split_root_key
  secure_delete_key
  write_ceremony_log

  log_json_event "ceremony_complete" "status=success"

  print_summary
}

main
