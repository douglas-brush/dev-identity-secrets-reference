#!/usr/bin/env bash

#!/usr/bin/env bash
# cert_inventory.sh — Comprehensive certificate inventory and expiry reporting
# Scans filesystem, Vault PKI, and Kubernetes for certificates; flags expired/weak
# Usage: cert_inventory.sh [--path <dir>] [--vault] [--k8s] [--json] [--threshold <days>] [--verbose] [--no-color]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${REPO_ROOT}/logs/cert-inventory-${TIMESTAMP//[:T]/-}.log"

# ── Defaults ──────────────────────────────────────────────────────────────

SCAN_PATH="$REPO_ROOT"
SCAN_VAULT=""
SCAN_K8S=""
JSON_OUTPUT=""
VERBOSE=""
NO_COLOR=""
THRESHOLD_DAYS=30
EXIT_CODE=0

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

# ── Logging ───────────────────────────────────────────────────────────────

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} [${level}] ${msg}"

  # When JSON output mode, send log lines to stderr to keep stdout clean
  local fd=1
  [[ -n "$JSON_OUTPUT" ]] && fd=2

  case "$level" in
    INFO)  printf '  %s %s\n' "$(_blue 'INFO')" "$msg" >&$fd ;;
    WARN)  printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" >&$fd ;;
    ERROR) printf '  %s %s\n' "$(_red 'ERROR')" "$msg" >&$fd ;;
    OK)    printf '  %s %s\n' "$(_green '  OK')" "$msg" >&$fd ;;
    SKIP)  printf '  %s %s\n' "$(_dim 'SKIP')" "$msg" >&$fd ;;
    DEBUG) [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_dim 'DBUG')" "$msg" >&$fd ;;
  esac

  mkdir -p "$(dirname "$LOG_FILE")"
  echo "$entry" >> "$LOG_FILE"
}

# ── Data collection ──────────────────────────────────────────────────────

declare -a CERT_ENTRIES=()

add_cert() {
  local source="$1" path="$2" subject="$3" issuer="$4" serial="$5"
  local not_before="$6" not_after="$7" key_type="$8" key_size="$9"
  local sans="${10:-}" status="${11:-OK}" flags="${12:--}"
  CERT_ENTRIES+=("${source}|${path}|${subject}|${issuer}|${serial}|${not_before}|${not_after}|${key_type}|${key_size}|${sans}|${status}|${flags}")
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'cert_inventory.sh') — Certificate inventory and expiry reporting

$(_bold 'USAGE')
  cert_inventory.sh [OPTIONS]

$(_bold 'OPTIONS')
  --path <dir>         Directory to scan for cert files (default: repo root)
  --vault              Also query Vault PKI mounts for issued certificates
  --k8s                Also scan Kubernetes TLS secrets and cert-manager Certificates
  --json               Output as JSON instead of table
  --threshold <days>   Days before expiry to flag as EXPIRING_SOON (default: 30)
  --verbose            Show additional diagnostic info
  --no-color           Disable color output
  -h, --help           Show this help

$(_bold 'DESCRIPTION')
  Comprehensive certificate scanner that discovers and analyzes X.509
  certificates across multiple sources:

  Filesystem:
    Scans for .pem, .crt, .cert, .p12, .pfx files
    Parses with openssl: subject, issuer, serial, dates, key info, SANs

  Vault (--vault):
    Queries PKI secret engine mounts for issued certificates
    Checks CRL status and CA chain

  Kubernetes (--k8s):
    Scans kubernetes.io/tls secrets for embedded certificates
    Checks cert-manager Certificate resources for status and expiry

  Flags certificates as:
    EXPIRED         — Certificate has passed its notAfter date
    EXPIRING_SOON   — Certificate expires within --threshold days
    WEAK_KEY        — RSA key < 2048 bits or EC key < 256 bits

$(_bold 'ENVIRONMENT')
  VAULT_ADDR          Vault server address (for --vault)
  VAULT_TOKEN         Vault authentication token
  KUBECONFIG          Kubernetes config path (for --k8s)

$(_bold 'EXIT CODES')
  0   All certificates healthy
  1   Expired, expiring, or weak certificates found
  2   Usage error

$(_bold 'EXAMPLES')
  cert_inventory.sh                                # Scan repo root
  cert_inventory.sh --path /etc/ssl --threshold 60 # Scan /etc/ssl, 60-day window
  cert_inventory.sh --vault --k8s --json           # All sources, JSON output
  cert_inventory.sh --no-color | tee report.txt    # Plain text for piping
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage ;;
    --path)          SCAN_PATH="$2"; shift 2 ;;
    --vault)         SCAN_VAULT=1; shift ;;
    --k8s)           SCAN_K8S=1; shift ;;
    --json)          JSON_OUTPUT=1; shift ;;
    --threshold)     THRESHOLD_DAYS="$2"; shift 2 ;;
    --verbose)       VERBOSE=1; shift ;;
    --no-color)      NO_COLOR=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# Validate scan path
if [[ ! -d "$SCAN_PATH" ]]; then
  printf 'Error: scan path does not exist: %s\n' "$SCAN_PATH" >&2
  exit 2
fi

# ── Date utilities ────────────────────────────────────────────────────────

# Convert openssl date string to epoch
date_to_epoch() {
  local date_str="$1"
  if date --version &>/dev/null 2>&1; then
    # GNU date
    date -d "$date_str" +%s 2>/dev/null || echo "0"
  else
    # BSD date (macOS) — openssl outputs "Mon DD HH:MM:SS YYYY GMT"
    date -jf "%b %d %H:%M:%S %Y %Z" "$date_str" +%s 2>/dev/null || \
    date -jf "%b  %d %H:%M:%S %Y %Z" "$date_str" +%s 2>/dev/null || echo "0"
  fi
}

# Convert ISO 8601 to epoch
iso_to_epoch() {
  local ts="$1"
  if date --version &>/dev/null 2>&1; then
    date -d "$ts" +%s 2>/dev/null || echo "0"
  else
    local clean="${ts%%Z*}"
    clean="${clean%%+*}"
    date -j -f "%Y-%m-%dT%H:%M:%S" "$clean" +%s 2>/dev/null || \
    date -j -f "%Y-%m-%d" "${clean:0:10}" +%s 2>/dev/null || echo "0"
  fi
}

now_epoch() {
  date +%s
}

# ── Certificate parsing ──────────────────────────────────────────────────

# Determine expiry status
cert_status() {
  local not_after_epoch="$1" key_type="$2" key_size="$3"
  local now
  now=$(now_epoch)
  local threshold_secs=$(( THRESHOLD_DAYS * 86400 ))
  local status="OK"
  local flags=""

  # Check expiry
  if [[ "$not_after_epoch" -le "$now" ]]; then
    status="EXPIRED"
    EXIT_CODE=1
  elif [[ $(( not_after_epoch - now )) -le $threshold_secs ]]; then
    status="EXPIRING_SOON"
    EXIT_CODE=1
  fi

  # Check key strength
  local weak=""
  case "$key_type" in
    RSA|rsaEncryption)
      if [[ -n "$key_size" && "$key_size" =~ ^[0-9]+$ && "$key_size" -lt 2048 ]]; then
        weak="WEAK_KEY(RSA-${key_size})"
      fi
      ;;
    EC|id-ecPublicKey)
      if [[ -n "$key_size" && "$key_size" =~ ^[0-9]+$ && "$key_size" -lt 256 ]]; then
        weak="WEAK_KEY(EC-${key_size})"
      fi
      ;;
  esac

  if [[ -n "$weak" ]]; then
    if [[ "$status" == "OK" ]]; then
      status="WEAK_KEY"
    fi
    flags="$weak"
    EXIT_CODE=1
  fi

  printf '%s|%s' "$status" "$flags"
}

# Parse a single x509 certificate file
parse_x509_file() {
  local file="$1" source="${2:-file}"
  local display_path="$file"

  # Make path relative if within repo
  if [[ "$file" == "$REPO_ROOT"/* ]]; then
    display_path="${file#"$REPO_ROOT"/}"
  fi

  log DEBUG "Parsing: $display_path"

  # Try to parse as x509
  local cert_text
  cert_text=$(openssl x509 -text -noout -in "$file" 2>/dev/null) || return 0

  local subject issuer serial not_before_str not_after_str key_type key_size sans

  subject=$(openssl x509 -subject -noout -in "$file" 2>/dev/null | sed 's/^subject= *//' | sed 's/^subject=//')
  issuer=$(openssl x509 -issuer -noout -in "$file" 2>/dev/null | sed 's/^issuer= *//' | sed 's/^issuer=//')
  serial=$(openssl x509 -serial -noout -in "$file" 2>/dev/null | sed 's/^serial=//')
  not_before_str=$(openssl x509 -startdate -noout -in "$file" 2>/dev/null | sed 's/^notBefore=//')
  not_after_str=$(openssl x509 -enddate -noout -in "$file" 2>/dev/null | sed 's/^notAfter=//')

  # Key type and size
  key_type=$(echo "$cert_text" | grep -oP 'Public Key Algorithm: \K\S+' 2>/dev/null || \
             echo "$cert_text" | sed -n 's/.*Public Key Algorithm: *\([^ ]*\).*/\1/p' | head -1)
  key_size=$(echo "$cert_text" | grep -oP 'Public-Key: \(\K[0-9]+' 2>/dev/null || \
             echo "$cert_text" | sed -n 's/.*Public-Key: *(\([0-9]*\).*/\1/p' | head -1)

  # SANs
  sans=$(echo "$cert_text" | grep -A1 'Subject Alternative Name' 2>/dev/null | \
         tail -1 | sed 's/^ *//' | tr -d '\n' || echo "")

  # Calculate status
  local not_after_epoch
  not_after_epoch=$(date_to_epoch "$not_after_str")

  local status_flags
  status_flags=$(cert_status "$not_after_epoch" "$key_type" "$key_size")
  local status="${status_flags%%|*}"
  local flags="${status_flags#*|}"

  # Clean up fields for delimiter safety
  subject="${subject//|/;}"
  issuer="${issuer//|/;}"
  sans="${sans//|/;}"

  add_cert "$source" "$display_path" "$subject" "$issuer" "$serial" \
           "$not_before_str" "$not_after_str" "$key_type" "$key_size" "$sans" "$status" "$flags"
}

# Parse PKCS#12/PFX file (extract cert, then parse)
parse_pkcs12_file() {
  local file="$1"
  local display_path="$file"
  if [[ "$file" == "$REPO_ROOT"/* ]]; then
    display_path="${file#"$REPO_ROOT"/}"
  fi

  log DEBUG "Parsing PKCS#12: $display_path"

  # Try to extract cert with empty passphrase first
  local tmp_cert
  tmp_cert=$(mktemp)
  # shellcheck disable=SC2064  # $tmp_cert must expand now, not at signal time
  trap "rm -f '$tmp_cert'" RETURN

  if openssl pkcs12 -in "$file" -clcerts -nokeys -passin pass: -out "$tmp_cert" 2>/dev/null; then
    if [[ -s "$tmp_cert" ]]; then
      parse_x509_file "$tmp_cert" "file"
      # Fix the path in the last entry
      if [[ ${#CERT_ENTRIES[@]} -gt 0 ]]; then
        local last_idx=$(( ${#CERT_ENTRIES[@]} - 1 ))
        local last="${CERT_ENTRIES[$last_idx]}"
        # Replace the tmp path with actual path
        CERT_ENTRIES[$last_idx]="${last/|$tmp_cert|/|$display_path|}"
        # Fix: the path is the second field
        local IFS='|'
        local -a parts
        read -ra parts <<< "$last"
        parts[1]="$display_path"
        CERT_ENTRIES[$last_idx]=$(IFS='|'; echo "${parts[*]}")
      fi
    fi
  else
    log WARN "Cannot parse PKCS#12 (may require passphrase): $display_path"
    add_cert "file" "$display_path" "(password-protected)" "" "" "" "" "" "" "" "UNKNOWN" "requires passphrase"
  fi

  rm -f "$tmp_cert"
  trap - RETURN
}

# ── Filesystem scan ──────────────────────────────────────────────────────

scan_filesystem() {
  if [[ -z "$JSON_OUTPUT" ]]; then
    printf '\n%s\n' "$(_bold '── Filesystem Certificate Scan ──')"
  fi

  if ! command -v openssl &>/dev/null; then
    log ERROR "openssl not installed — cannot parse certificates"
    return
  fi

  log INFO "Scanning: $SCAN_PATH"

  local cert_count=0
  local skipped=0

  # Scan for PEM, CRT, CERT files
  while IFS= read -r -d '' f; do
    # Skip files containing private keys only (no CERTIFICATE block)
    if grep -q 'PRIVATE KEY' "$f" 2>/dev/null && ! grep -q 'CERTIFICATE' "$f" 2>/dev/null; then
      log DEBUG "Skipping private-key-only file: $f"
      skipped=$((skipped + 1))
      continue
    fi

    # Must contain CERTIFICATE or look like a DER-encoded cert
    if grep -q 'CERTIFICATE' "$f" 2>/dev/null; then
      parse_x509_file "$f" "file"
      cert_count=$((cert_count + 1))
    elif openssl x509 -inform DER -noout -in "$f" 2>/dev/null; then
      # DER-encoded certificate — convert on the fly
      local tmp_pem
      tmp_pem=$(mktemp)
      if openssl x509 -inform DER -in "$f" -out "$tmp_pem" 2>/dev/null; then
        parse_x509_file "$tmp_pem" "file"
        if [[ ${#CERT_ENTRIES[@]} -gt 0 ]]; then
          local last_idx=$(( ${#CERT_ENTRIES[@]} - 1 ))
          local last="${CERT_ENTRIES[$last_idx]}"
          local display_path="$f"
          [[ "$f" == "$REPO_ROOT"/* ]] && display_path="${f#"$REPO_ROOT"/}"
          local IFS='|'
          local -a parts
          read -ra parts <<< "$last"
          parts[1]="$display_path"
          CERT_ENTRIES[$last_idx]=$(IFS='|'; echo "${parts[*]}")
        fi
        cert_count=$((cert_count + 1))
      fi
      rm -f "$tmp_pem"
    else
      log DEBUG "Not a parseable certificate: $f"
      skipped=$((skipped + 1))
    fi
  done < <(find "$SCAN_PATH" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cert' \) \
    -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -not -path '*/.terraform/*' -not -path '*/vendor/*' -print0 2>/dev/null)

  # Scan PKCS#12 / PFX files
  while IFS= read -r -d '' f; do
    parse_pkcs12_file "$f"
    cert_count=$((cert_count + 1))
  done < <(find "$SCAN_PATH" -type f \( -name '*.p12' -o -name '*.pfx' \) \
    -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -not -path '*/.terraform/*' -not -path '*/vendor/*' -print0 2>/dev/null)

  log OK "Found ${cert_count} certificate file(s), skipped ${skipped}"
}

# ── Vault PKI scan ───────────────────────────────────────────────────────

scan_vault_pki() {
  if [[ -z "$SCAN_VAULT" ]]; then
    return
  fi

  if [[ -z "$JSON_OUTPUT" ]]; then
    printf '\n%s\n' "$(_bold '── Vault PKI Certificate Scan ──')"
  fi

  if ! command -v vault &>/dev/null; then
    log SKIP "vault CLI not installed"
    return
  fi

  if [[ -z "${VAULT_ADDR:-}" ]]; then
    log SKIP "VAULT_ADDR not set"
    return
  fi

  if ! vault token lookup &>/dev/null 2>&1; then
    log SKIP "Cannot authenticate to Vault"
    return
  fi

  # Find PKI mounts
  local mounts
  mounts=$(vault secrets list -format=json 2>/dev/null || echo '{}')
  local pki_mounts
  pki_mounts=$(echo "$mounts" | jq -r 'to_entries[] | select(.value.type == "pki") | .key' 2>/dev/null || echo "")

  if [[ -z "$pki_mounts" ]]; then
    log INFO "No PKI secret engine mounts found"
    return
  fi

  for mount in $pki_mounts; do
    mount="${mount%/}"
    log INFO "Scanning PKI mount: ${mount}"

    # Get CA certificate
    local ca_cert
    ca_cert=$(vault read -format=json "${mount}/cert/ca" 2>/dev/null || echo '{}')
    if [[ "$ca_cert" != "{}" ]]; then
      local ca_pem
      ca_pem=$(echo "$ca_cert" | jq -r '.data.certificate // empty' 2>/dev/null)
      if [[ -n "$ca_pem" ]]; then
        local tmp_ca
        tmp_ca=$(mktemp)
        echo "$ca_pem" > "$tmp_ca"
        parse_x509_file "$tmp_ca" "vault"
        # Fix path to show vault mount
        if [[ ${#CERT_ENTRIES[@]} -gt 0 ]]; then
          local last_idx=$(( ${#CERT_ENTRIES[@]} - 1 ))
          local IFS='|'
          local -a parts
          read -ra parts <<< "${CERT_ENTRIES[$last_idx]}"
          parts[1]="${mount}/ca"
          CERT_ENTRIES[$last_idx]=$(IFS='|'; echo "${parts[*]}")
        fi
        rm -f "$tmp_ca"
      fi
    fi

    # List issued certificates (serials)
    local certs_list
    certs_list=$(vault list -format=json "${mount}/certs" 2>/dev/null || echo '[]')

    if [[ "$certs_list" != "[]" ]]; then
      local cert_serials
      cert_serials=$(echo "$certs_list" | jq -r '.[]' 2>/dev/null)
      local cert_scan_count=0

      while IFS= read -r serial; do
        [[ -z "$serial" ]] && continue

        local cert_data
        cert_data=$(vault read -format=json "${mount}/cert/${serial}" 2>/dev/null || echo '{}')
        if [[ "$cert_data" == "{}" ]]; then
          continue
        fi

        local pem_data revocation_time
        pem_data=$(echo "$cert_data" | jq -r '.data.certificate // empty' 2>/dev/null)
        revocation_time=$(echo "$cert_data" | jq -r '.data.revocation_time // 0' 2>/dev/null)

        if [[ -n "$pem_data" ]]; then
          local tmp_cert
          tmp_cert=$(mktemp)
          echo "$pem_data" > "$tmp_cert"
          parse_x509_file "$tmp_cert" "vault"

          # Fix path and add revocation info
          if [[ ${#CERT_ENTRIES[@]} -gt 0 ]]; then
            local last_idx=$(( ${#CERT_ENTRIES[@]} - 1 ))
            local IFS='|'
            local -a parts
            read -ra parts <<< "${CERT_ENTRIES[$last_idx]}"
            parts[1]="${mount}/cert/${serial}"
            if [[ "$revocation_time" != "0" && "$revocation_time" != "null" ]]; then
              parts[11]="${parts[11]:-}${parts[11]:+,}REVOKED"
            fi
            CERT_ENTRIES[$last_idx]=$(IFS='|'; echo "${parts[*]}")
          fi

          rm -f "$tmp_cert"
          cert_scan_count=$((cert_scan_count + 1))
        fi
      done <<< "$cert_serials"

      log OK "Scanned ${cert_scan_count} issued certificate(s) from ${mount}"
    fi

    # Check CRL
    local crl_data
    crl_data=$(vault read -format=json "${mount}/cert/crl" 2>/dev/null || echo '{}')
    if [[ "$crl_data" != "{}" ]]; then
      log OK "CRL available for ${mount}"
    else
      log WARN "No CRL found for ${mount}"
    fi
  done
}

# ── Kubernetes scan ──────────────────────────────────────────────────────

scan_kubernetes() {
  if [[ -z "$SCAN_K8S" ]]; then
    return
  fi

  if [[ -z "$JSON_OUTPUT" ]]; then
    printf '\n%s\n' "$(_bold '── Kubernetes Certificate Scan ──')"
  fi

  if ! command -v kubectl &>/dev/null; then
    log SKIP "kubectl not installed"
    return
  fi

  if ! kubectl cluster-info &>/dev/null 2>&1; then
    log SKIP "Cannot connect to Kubernetes cluster"
    return
  fi

  # Scan TLS secrets
  log INFO "Scanning TLS secrets..."

  local namespaces
  namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "default")

  local tls_count=0

  for ns in $namespaces; do
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    local secrets_json
    secrets_json=$(kubectl get secrets -n "$ns" -o json --field-selector type=kubernetes.io/tls 2>/dev/null || echo '{"items":[]}')
    local count
    count=$(echo "$secrets_json" | jq '.items | length' 2>/dev/null || echo "0")

    for ((i = 0; i < count; i++)); do
      local name tls_crt
      name=$(echo "$secrets_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
      tls_crt=$(echo "$secrets_json" | jq -r ".items[${i}].data[\"tls.crt\"] // empty" 2>/dev/null)

      if [[ -z "$tls_crt" ]]; then
        continue
      fi

      # Decode and parse
      local tmp_cert
      tmp_cert=$(mktemp)
      echo "$tls_crt" | base64 -d > "$tmp_cert" 2>/dev/null || continue

      if openssl x509 -noout -in "$tmp_cert" 2>/dev/null; then
        parse_x509_file "$tmp_cert" "k8s"

        if [[ ${#CERT_ENTRIES[@]} -gt 0 ]]; then
          local last_idx=$(( ${#CERT_ENTRIES[@]} - 1 ))
          local IFS='|'
          local -a parts
          read -ra parts <<< "${CERT_ENTRIES[$last_idx]}"
          parts[1]="${ns}/${name}"
          CERT_ENTRIES[$last_idx]=$(IFS='|'; echo "${parts[*]}")
        fi

        tls_count=$((tls_count + 1))
      fi

      rm -f "$tmp_cert"
    done
  done

  log OK "Found ${tls_count} TLS secret(s)"

  # Scan cert-manager Certificate resources
  if kubectl get crd certificates.cert-manager.io &>/dev/null 2>&1; then
    log INFO "Scanning cert-manager Certificates..."

    local certs_json
    certs_json=$(kubectl get certificates -A -o json 2>/dev/null || echo '{"items":[]}')
    local cert_count
    cert_count=$(echo "$certs_json" | jq '.items | length' 2>/dev/null || echo "0")

    for ((i = 0; i < cert_count; i++)); do
      local cert_name cert_ns not_after ready_status secret_name
      cert_name=$(echo "$certs_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
      cert_ns=$(echo "$certs_json" | jq -r ".items[${i}].metadata.namespace" 2>/dev/null)
      not_after=$(echo "$certs_json" | jq -r ".items[${i}].status.notAfter // empty" 2>/dev/null)
      ready_status=$(echo "$certs_json" | jq -r ".items[${i}].status.conditions[]? | select(.type==\"Ready\") | .status" 2>/dev/null)
      # shellcheck disable=SC2034  # secret_name reserved for future output columns
      secret_name=$(echo "$certs_json" | jq -r ".items[${i}].spec.secretName // empty" 2>/dev/null)

      local status="OK"
      local flags=""

      if [[ "$ready_status" != "True" ]]; then
        flags="NOT_READY"
        status="WARN"
      fi

      if [[ -n "$not_after" ]]; then
        local expire_epoch
        expire_epoch=$(iso_to_epoch "$not_after")
        local now
        now=$(now_epoch)
        local threshold_secs=$(( THRESHOLD_DAYS * 86400 ))

        if [[ "$expire_epoch" -le "$now" ]]; then
          status="EXPIRED"
          EXIT_CODE=1
        elif [[ $(( expire_epoch - now )) -le $threshold_secs ]]; then
          status="EXPIRING_SOON"
          EXIT_CODE=1
        fi
      fi

      local dns_names
      dns_names=$(echo "$certs_json" | jq -r ".items[${i}].spec.dnsNames // [] | join(\", \")" 2>/dev/null || echo "")

      add_cert "k8s-cm" "${cert_ns}/${cert_name}" "cert-manager" "" "" "" "${not_after:-unknown}" "" "" "$dns_names" "$status" "$flags"
    done

    log OK "Found ${cert_count} cert-manager Certificate(s)"
  else
    log INFO "cert-manager CRDs not installed — skipping"
  fi
}

# ── Output formatters ────────────────────────────────────────────────────

output_text() {
  printf '\n'
  _bold '╔══════════════════════════════════════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║                           CERTIFICATE INVENTORY REPORT                                  ║'
  printf '\n'
  _bold '╠══════════════════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Generated:  %-74s ║\n' "$TIMESTAMP"
  printf '║  Scan path:  %-74s ║\n' "$SCAN_PATH"
  printf '║  Threshold:  %-74s ║\n' "${THRESHOLD_DAYS} days"
  _bold '╚══════════════════════════════════════════════════════════════════════════════════════════╝'
  printf '\n'

  if [[ ${#CERT_ENTRIES[@]} -eq 0 ]]; then
    printf '\n  %s\n\n' "$(_dim 'No certificates found.')"
    return
  fi

  # Table header
  printf '\n  %-6s %-30s %-30s %-12s %-12s %-10s %s\n' \
    "SOURCE" "PATH" "SUBJECT" "NOT_AFTER" "KEY" "STATUS" "FLAGS"
  printf '  %s\n' "$(printf '%.0s─' {1..130})"

  local ok_count=0 expired_count=0 expiring_count=0 weak_count=0 warn_count=0

  for entry in "${CERT_ENTRIES[@]}"; do
    local IFS='|'
    local -a parts
    read -ra parts <<< "$entry"

    local source="${parts[0]}" path="${parts[1]}" subject="${parts[2]}"
    local not_after="${parts[6]}" key_type="${parts[7]}" key_size="${parts[8]}"
    local status="${parts[10]:-OK}" flags="${parts[11]:-}"
    [[ "$flags" == "-" ]] && flags=""

    # Truncate for display
    local disp_path="$path"
    [[ ${#disp_path} -gt 28 ]] && disp_path="...${disp_path: -25}"
    local disp_subject="$subject"
    [[ ${#disp_subject} -gt 28 ]] && disp_subject="...${disp_subject: -25}"

    # Shorten notAfter for display
    local disp_date="$not_after"
    [[ ${#disp_date} -gt 10 ]] && disp_date="${disp_date:0:20}"

    local key_info="${key_type:+${key_type}}${key_size:+-${key_size}}"
    [[ ${#key_info} -gt 10 ]] && key_info="${key_info:0:10}"

    # Status coloring
    local status_display
    case "$status" in
      OK)            status_display="$(_green 'OK')"; ok_count=$((ok_count + 1)) ;;
      EXPIRED)       status_display="$(_red 'EXPIRED')"; expired_count=$((expired_count + 1)) ;;
      EXPIRING_SOON) status_display="$(_yellow 'EXPIRING')"; expiring_count=$((expiring_count + 1)) ;;
      WEAK_KEY)      status_display="$(_red 'WEAK_KEY')"; weak_count=$((weak_count + 1)) ;;
      WARN)          status_display="$(_yellow 'WARN')"; warn_count=$((warn_count + 1)) ;;
      UNKNOWN)       status_display="$(_dim 'UNKNOWN')" ;;
      *)             status_display="$status" ;;
    esac

    printf '  %-6s %-30s %-30s %-12s %-12s %s  %s\n' \
      "$source" "$disp_path" "$disp_subject" "$disp_date" "$key_info" "$status_display" "$flags"
  done

  # Summary
  printf '\n  %s\n' "$(printf '%.0s─' {1..130})"
  printf '  Total: %d | ' "${#CERT_ENTRIES[@]}"
  printf '%s %d | ' "$(_green 'OK:')" "$ok_count"
  printf '%s %d | ' "$(_red 'Expired:')" "$expired_count"
  printf '%s %d | ' "$(_yellow 'Expiring:')" "$expiring_count"
  printf '%s %d\n' "$(_red 'Weak:')" "$weak_count"

  if [[ $expired_count -gt 0 ]]; then
    printf '\n  %s\n' "$(_red 'ACTION REQUIRED: Expired certificates detected — renew immediately.')"
  fi
  if [[ $expiring_count -gt 0 ]]; then
    printf '  %s\n' "$(_yellow 'WARNING: Certificates expiring within '"${THRESHOLD_DAYS}"' days — plan renewal.')"
  fi
  if [[ $weak_count -gt 0 ]]; then
    printf '  %s\n' "$(_red 'WARNING: Weak key algorithms detected — re-issue with stronger keys.')"
  fi
  printf '\n'
}

output_json() {
  local entries="["
  local first=true

  for entry in "${CERT_ENTRIES[@]}"; do
    local IFS='|'
    local -a parts
    read -ra parts <<< "$entry"

    # Escape quotes in all fields
    local source="${parts[0]//\"/\\\"}" path="${parts[1]//\"/\\\"}" subject="${parts[2]//\"/\\\"}"
    local issuer="${parts[3]//\"/\\\"}" serial="${parts[4]//\"/\\\"}"
    local not_before="${parts[5]//\"/\\\"}" not_after="${parts[6]//\"/\\\"}"
    local key_type="${parts[7]//\"/\\\"}" key_size="${parts[8]//\"/\\\"}"
    local sans="${parts[9]:-}" status="${parts[10]:-OK}" flags="${parts[11]:-}"
    [[ "$flags" == "-" ]] && flags=""
    sans="${sans//\"/\\\"}" status="${status//\"/\\\"}" flags="${flags//\"/\\\"}"

    if [[ "$first" == "true" ]]; then
      first=false
    else
      entries+=","
    fi

    entries+=$(cat <<ENTRY
{"source":"${source}","path":"${path}","subject":"${subject}","issuer":"${issuer}","serial":"${serial}","not_before":"${not_before}","not_after":"${not_after}","key_type":"${key_type}","key_size":"${key_size}","sans":"${sans}","status":"${status}","flags":"${flags}"}
ENTRY
)
  done
  entries+="]"

  local overall="HEALTHY"
  [[ $EXIT_CODE -ne 0 ]] && overall="ACTION_REQUIRED"

  cat <<EOF
{
  "report": "certificate_inventory",
  "timestamp": "${TIMESTAMP}",
  "scan_path": "${SCAN_PATH}",
  "threshold_days": ${THRESHOLD_DAYS},
  "overall_status": "${overall}",
  "total_certificates": ${#CERT_ENTRIES[@]},
  "certificates": ${entries}
}
EOF
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  if [[ -z "$JSON_OUTPUT" ]]; then
    printf '\n%s\n' "$(_bold '═══ Certificate Inventory ═══')"
  fi

  log INFO "Certificate inventory started at ${TIMESTAMP}"
  log INFO "Threshold: ${THRESHOLD_DAYS} days"

  # Run scans
  scan_filesystem
  scan_vault_pki
  scan_kubernetes

  # Output
  if [[ -n "$JSON_OUTPUT" ]]; then
    output_json
  else
    output_text
    log INFO "Log file: ${LOG_FILE}"
  fi

  exit $EXIT_CODE
}

main
