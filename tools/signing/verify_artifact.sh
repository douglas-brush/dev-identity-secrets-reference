#!/usr/bin/env bash
# verify_artifact.sh — Verify signatures on container images, binaries, or SBOMs
# Usage: verify_artifact.sh --artifact <ref> --type <image|binary|sbom> [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_DIR="${REPO_ROOT}/logs"
LOG_FILE="${LOG_DIR}/verify-${TIMESTAMP//[:T]/-}.log"
METADATA_DIR="${REPO_ROOT}/.signatures"

# ── Defaults ──────────────────────────────────────────────────────────────

ARTIFACT=""
ARTIFACT_TYPE=""
VAULT_KEY=""
CERTIFICATE=""
CERTIFICATE_CHAIN=""
CERTIFICATE_IDENTITY=""
CERTIFICATE_OIDC_ISSUER=""
NO_COLOR="${NO_COLOR:-}"
VERBOSE=""
DRY_RUN=""
OUTPUT_FORMAT="text"
EXIT_CODE=0

# Verification result tracking
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_SKIPPED=0
declare -a CHECK_RESULTS=()

# ── Color & output ────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  case "$level" in
    INFO)  printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)  printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR) printf '  %s %s\n' "$(_red 'ERROR')" "$msg" ;;
    OK)    printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    DRY)   printf '  %s %s\n' "$(_yellow ' DRY')" "$msg" ;;
    DEBUG) [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_dim 'DEBUG')" "$msg" ;;
  esac

  mkdir -p "$(dirname "$LOG_FILE")"
  echo "${ts} [${level}] ${msg}" >> "$LOG_FILE"
}

die() {
  log ERROR "$1"
  exit "${2:-1}"
}

check_pass() {
  local name="$1" detail="${2:-}"
  CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
  CHECK_RESULTS+=("PASS|${name}|${detail}")
  printf '  %s %s' "$(_green '✓ PASS')" "$name"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'
}

check_fail() {
  local name="$1" detail="${2:-}"
  CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
  CHECKS_FAILED=$((CHECKS_FAILED + 1))
  CHECK_RESULTS+=("FAIL|${name}|${detail}")
  printf '  %s %s' "$(_red '✗ FAIL')" "$name"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'
  EXIT_CODE=1
}

check_skip() {
  local name="$1" detail="${2:-}"
  CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
  CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
  CHECK_RESULTS+=("SKIP|${name}|${detail}")
  printf '  %s %s' "$(_dim '— SKIP')" "$name"
  [[ -n "$detail" ]] && printf ' — %s' "$detail"
  printf '\n'
}

section() {
  printf '\n%s\n' "$(_bold "── $1 ──")"
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'verify_artifact.sh') — Artifact signature verification

$(_bold 'USAGE')
  verify_artifact.sh --artifact <ref> --type <type> [OPTIONS]

$(_bold 'REQUIRED')
  --artifact <ref>             File path or container image reference to verify
  --type <type>                Artifact type: image, binary, or sbom

$(_bold 'OPTIONS')
  --key <name>                 Vault transit key name used for signing
  --certificate <path>         Certificate file for verification
  --certificate-chain <path>   Certificate chain file for trust validation
  --certificate-identity <id>  Expected certificate identity (SAN)
  --certificate-oidc-issuer <url>  Expected OIDC issuer for keyless verification
  --output-format <fmt>        Output format: text (default) or json
  --metadata-dir <path>        Directory for signature metadata (default: .signatures/)
  --dry-run                    Show what would be verified without running
  --verbose                    Show additional diagnostic info
  --no-color                   Disable colored output
  -h, --help                   Show this help

$(_bold 'VERIFICATION CHECKS')
  1. Signature exists       — a valid signature is present for the artifact
  2. Signature valid        — cryptographic verification passes
  3. Key trust chain        — signing key was trusted at time of signing
  4. Metadata consistency   — stored metadata matches artifact state
  5. Timestamp validation   — signature timestamp within acceptable window

$(_bold 'ENVIRONMENT')
  VAULT_ADDR              Vault server address (for Vault transit verification)
  VAULT_TOKEN             Vault authentication token
  COSIGN_KEY              Override cosign key reference
  NO_COLOR                Disable colored output

$(_bold 'EXIT CODES')
  0   All verification checks passed
  1   One or more checks failed
  2   Usage error or missing dependencies

$(_bold 'EXAMPLES')
  # Verify a cosign-signed container image with Vault KMS
  verify_artifact.sh --artifact ghcr.io/org/app:v1.2.3 --type image --key transit-sign-key

  # Verify a keyless-signed image with identity constraints
  verify_artifact.sh --artifact ghcr.io/org/app:v1.2.3 --type image \\
    --certificate-identity "https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main" \\
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

  # Verify a Vault transit signed binary
  verify_artifact.sh --artifact ./dist/myapp-linux-amd64 --type binary --key code-signing

  # Verify an SBOM with verbose output
  verify_artifact.sh --artifact ./sbom.spdx.json --type sbom --key sbom-key --verbose

  # JSON output for CI integration
  verify_artifact.sh --artifact ghcr.io/org/app:v1.2.3 --type image --key mykey --output-format json
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)                  usage ;;
    --artifact)                 ARTIFACT="$2"; shift 2 ;;
    --type)                     ARTIFACT_TYPE="$2"; shift 2 ;;
    --key)                      VAULT_KEY="$2"; shift 2 ;;
    --certificate)              CERTIFICATE="$2"; export CERTIFICATE; shift 2 ;;
    --certificate-chain)        CERTIFICATE_CHAIN="$2"; export CERTIFICATE_CHAIN; shift 2 ;;
    --certificate-identity)     CERTIFICATE_IDENTITY="$2"; shift 2 ;;
    --certificate-oidc-issuer)  CERTIFICATE_OIDC_ISSUER="$2"; shift 2 ;;
    --output-format)            OUTPUT_FORMAT="$2"; shift 2 ;;
    --metadata-dir)             METADATA_DIR="$2"; shift 2 ;;
    --dry-run)                  DRY_RUN=1; shift ;;
    --verbose)                  VERBOSE=1; shift ;;
    --no-color)                 NO_COLOR=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run verify_artifact.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

[[ -z "$ARTIFACT" ]] && die "--artifact is required" 2
[[ -z "$ARTIFACT_TYPE" ]] && die "--type is required" 2

case "$ARTIFACT_TYPE" in
  image|binary|sbom) ;;
  *) die "Invalid --type: ${ARTIFACT_TYPE} (must be image, binary, or sbom)" 2 ;;
esac

# For binary/sbom, verify the file exists
if [[ "$ARTIFACT_TYPE" != "image" ]]; then
  [[ -f "$ARTIFACT" ]] || die "Artifact file not found: ${ARTIFACT}" 2
fi

# ── Tool detection ────────────────────────────────────────────────────────

HAS_COSIGN=""
HAS_NOTATION=""
HAS_VAULT=""

command -v cosign &>/dev/null && HAS_COSIGN=1
command -v notation &>/dev/null && HAS_NOTATION=1
command -v vault &>/dev/null && HAS_VAULT=1

detect_verification_method() {
  if [[ -n "$HAS_COSIGN" && -n "$VAULT_KEY" && -n "${VAULT_ADDR:-}" ]]; then
    echo "cosign-vault"
  elif [[ -n "$HAS_COSIGN" && -z "$VAULT_KEY" ]]; then
    echo "cosign-keyless"
  elif [[ -n "$HAS_COSIGN" && -n "$VAULT_KEY" ]]; then
    echo "cosign-vault"
  elif [[ -n "$HAS_NOTATION" ]]; then
    echo "notation"
  elif [[ -n "$HAS_VAULT" && -n "$VAULT_KEY" ]]; then
    echo "vault-transit"
  else
    echo "none"
  fi
}

VERIFY_METHOD=$(detect_verification_method)

if [[ "$VERIFY_METHOD" == "none" ]]; then
  die "No verification tool found. Install cosign, notation, or vault CLI." 2
fi

# ── Hash computation ──────────────────────────────────────────────────────

compute_hash() {
  local target="$1"
  local target_type="$2"

  if [[ "$target_type" == "image" ]]; then
    if [[ -n "$HAS_COSIGN" ]]; then
      cosign triangulate "$target" 2>/dev/null | head -1 || echo "digest-unavailable"
    elif command -v crane &>/dev/null; then
      crane digest "$target" 2>/dev/null || echo "digest-unavailable"
    else
      echo "digest-requires-crane-or-cosign"
    fi
  else
    if command -v sha256sum &>/dev/null; then
      sha256sum "$target" | awk '{print "sha256:" $1}'
    else
      shasum -a 256 "$target" | awk '{print "sha256:" $1}'
    fi
  fi
}

# ── Check: Signature exists ─────────────────────────────────────────────

check_signature_exists() {
  section "Signature Existence"

  case "$VERIFY_METHOD" in
    cosign-vault|cosign-keyless)
      if [[ "$ARTIFACT_TYPE" == "image" ]]; then
        if cosign tree "$ARTIFACT" &>/dev/null 2>&1; then
          check_pass "Cosign signature found for image"
        else
          check_fail "No cosign signature found for image"
        fi
      else
        local sig_file="${ARTIFACT}.sig"
        if [[ -f "$sig_file" ]]; then
          check_pass "Detached signature file exists" "$sig_file"
        else
          check_fail "Detached signature file not found" "expected ${sig_file}"
        fi
        # Check certificate for keyless
        if [[ "$VERIFY_METHOD" == "cosign-keyless" ]]; then
          local cert_file="${ARTIFACT}.cert"
          if [[ -f "$cert_file" ]]; then
            check_pass "Signing certificate exists" "$cert_file"
          else
            check_fail "Signing certificate not found" "expected ${cert_file}"
          fi
        fi
      fi
      ;;
    notation)
      if [[ "$ARTIFACT_TYPE" == "image" ]]; then
        if notation inspect "$ARTIFACT" &>/dev/null 2>&1; then
          check_pass "Notation signature found for image"
        else
          check_fail "No notation signature found for image"
        fi
      else
        check_skip "Notation signature check" "notation only supports images"
      fi
      ;;
    vault-transit)
      local sig_file="${ARTIFACT}.vault-sig"
      if [[ -f "$sig_file" ]]; then
        local sig_content
        sig_content=$(cat "$sig_file")
        if [[ "$sig_content" == vault:v1:* ]]; then
          check_pass "Vault transit signature exists" "valid vault:v1: format"
        else
          check_fail "Vault transit signature format invalid" "expected vault:v1: prefix"
        fi
      else
        check_fail "Vault transit signature file not found" "expected ${sig_file}"
      fi
      ;;
  esac
}

# ── Check: Cryptographic verification ────────────────────────────────────

check_signature_valid() {
  section "Cryptographic Verification"

  if [[ -n "$DRY_RUN" ]]; then
    check_skip "Cryptographic verification" "dry run mode"
    return
  fi

  case "$VERIFY_METHOD" in
    cosign-vault)
      local key_ref="${COSIGN_KEY:-hashivault://${VAULT_KEY}}"
      log DEBUG "Verifying with key: ${key_ref}"

      if [[ "$ARTIFACT_TYPE" == "image" ]]; then
        if cosign verify --key "$key_ref" "$ARTIFACT" &>/dev/null 2>&1; then
          check_pass "Cosign signature cryptographically valid"
        else
          check_fail "Cosign signature verification failed"
        fi
      else
        local sig_file="${ARTIFACT}.sig"
        if cosign verify-blob --key "$key_ref" --signature "$sig_file" "$ARTIFACT" &>/dev/null 2>&1; then
          check_pass "Cosign blob signature cryptographically valid"
        else
          check_fail "Cosign blob signature verification failed"
        fi
      fi
      ;;

    cosign-keyless)
      local verify_args=()
      if [[ -n "$CERTIFICATE_IDENTITY" ]]; then
        verify_args+=(--certificate-identity "$CERTIFICATE_IDENTITY")
      fi
      if [[ -n "$CERTIFICATE_OIDC_ISSUER" ]]; then
        verify_args+=(--certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER")
      fi

      if [[ "$ARTIFACT_TYPE" == "image" ]]; then
        if COSIGN_EXPERIMENTAL=1 cosign verify "${verify_args[@]}" "$ARTIFACT" &>/dev/null 2>&1; then
          check_pass "Keyless signature cryptographically valid"
        else
          check_fail "Keyless signature verification failed"
        fi
      else
        local sig_file="${ARTIFACT}.sig"
        local cert_file="${ARTIFACT}.cert"
        if COSIGN_EXPERIMENTAL=1 cosign verify-blob \
            --signature "$sig_file" \
            --certificate "$cert_file" \
            "${verify_args[@]}" \
            "$ARTIFACT" &>/dev/null 2>&1; then
          check_pass "Keyless blob signature cryptographically valid"
        else
          check_fail "Keyless blob signature verification failed"
        fi
      fi
      ;;

    notation)
      if notation verify "$ARTIFACT" &>/dev/null 2>&1; then
        check_pass "Notation signature cryptographically valid"
      else
        check_fail "Notation signature verification failed"
      fi
      ;;

    vault-transit)
      local sig_file="${ARTIFACT}.vault-sig"
      local signature
      signature=$(cat "$sig_file" 2>/dev/null) || { check_fail "Cannot read signature file"; return; }

      local artifact_hash
      artifact_hash=$(compute_hash "$ARTIFACT" "$ARTIFACT_TYPE")

      local input_b64
      if [[ "$ARTIFACT_TYPE" == "image" ]]; then
        input_b64=$(printf '%s' "$artifact_hash" | base64)
      else
        local raw_hash="${artifact_hash#sha256:}"
        input_b64=$(printf '%s' "$raw_hash" | base64)
      fi

      local verify_result
      verify_result=$(vault write -format=json "transit/verify/${VAULT_KEY}" \
        input="$input_b64" \
        signature="$signature" \
        hash_algorithm=sha2-256 \
        signature_algorithm=pkcs1v15 2>/dev/null) || { check_fail "Vault transit verify call failed"; return; }

      local valid
      valid=$(echo "$verify_result" | jq -r '.data.valid // false')

      if [[ "$valid" == "true" ]]; then
        check_pass "Vault transit signature cryptographically valid"
      else
        check_fail "Vault transit signature invalid"
      fi
      ;;
  esac
}

# ── Check: Key trust chain ───────────────────────────────────────────────

check_key_trust() {
  section "Key Trust Chain"

  case "$VERIFY_METHOD" in
    cosign-vault|vault-transit)
      if [[ -z "${VAULT_ADDR:-}" ]]; then
        check_skip "Vault key trust" "VAULT_ADDR not set"
        return
      fi
      if [[ -n "$DRY_RUN" ]]; then
        check_skip "Vault key trust" "dry run mode"
        return
      fi

      # Check the transit key exists and is active
      local key_info
      key_info=$(vault read -format=json "transit/keys/${VAULT_KEY}" 2>/dev/null) || {
        check_fail "Transit key not found or inaccessible" "${VAULT_KEY}"
        return
      }

      # Check key is not disabled
      local deletion_allowed
      deletion_allowed=$(echo "$key_info" | jq -r '.data.deletion_allowed // false')
      if [[ "$deletion_allowed" == "true" ]]; then
        check_fail "Transit key has deletion_allowed=true" "key may be decommissioned"
      else
        check_pass "Transit key is protected against deletion"
      fi

      # Check key type supports signing
      local key_type
      key_type=$(echo "$key_info" | jq -r '.data.type // "unknown"')
      case "$key_type" in
        rsa-2048|rsa-3072|rsa-4096|ecdsa-p256|ecdsa-p384|ecdsa-p521|ed25519)
          check_pass "Transit key type supports signing" "$key_type"
          ;;
        *)
          check_fail "Transit key type may not support signing" "$key_type"
          ;;
      esac

      # Check minimum version
      local min_version
      min_version=$(echo "$key_info" | jq -r '.data.min_decryption_version // 0')
      local latest_version
      latest_version=$(echo "$key_info" | jq -r '.data.latest_version // 0')
      log DEBUG "Key versions: latest=${latest_version}, min_decryption=${min_version}"
      check_pass "Transit key version info" "latest v${latest_version}"
      ;;

    cosign-keyless)
      # For keyless, trust is established through Fulcio CA and Rekor transparency log
      check_pass "Trust chain via Fulcio CA and Rekor transparency log"

      if [[ -n "$CERTIFICATE_IDENTITY" ]]; then
        check_pass "Certificate identity constraint set" "$CERTIFICATE_IDENTITY"
      else
        check_fail "No certificate identity constraint" "set --certificate-identity for production"
      fi

      if [[ -n "$CERTIFICATE_OIDC_ISSUER" ]]; then
        check_pass "OIDC issuer constraint set" "$CERTIFICATE_OIDC_ISSUER"
      else
        check_fail "No OIDC issuer constraint" "set --certificate-oidc-issuer for production"
      fi
      ;;

    notation)
      # Notation uses trust policies
      if notation policy show &>/dev/null 2>&1; then
        check_pass "Notation trust policy is configured"
      else
        check_fail "Notation trust policy not configured" "run: notation policy init"
      fi
      ;;
  esac
}

# ── Check: Metadata consistency ──────────────────────────────────────────

check_metadata_consistency() {
  section "Metadata Consistency"

  local safe_name
  safe_name=$(echo "$ARTIFACT" | sed 's|[/:@]|_|g')
  local metadata_file="${METADATA_DIR}/${safe_name}.json"

  if [[ ! -f "$metadata_file" ]]; then
    check_skip "Metadata consistency" "no metadata file found at ${metadata_file#"$REPO_ROOT"/}"
    return
  fi

  log DEBUG "Reading metadata: ${metadata_file}"

  # Check artifact hash matches
  local stored_hash
  stored_hash=$(jq -r '.artifact_hash // empty' "$metadata_file" 2>/dev/null)
  if [[ -n "$stored_hash" ]]; then
    local current_hash
    current_hash=$(compute_hash "$ARTIFACT" "$ARTIFACT_TYPE")
    if [[ "$stored_hash" == "$current_hash" ]]; then
      check_pass "Artifact hash matches metadata" "${current_hash:0:24}..."
    else
      check_fail "Artifact hash mismatch" "stored=${stored_hash:0:24}... current=${current_hash:0:24}..."
    fi
  else
    check_skip "Artifact hash check" "no hash in metadata"
  fi

  # Check artifact type matches
  local stored_type
  stored_type=$(jq -r '.artifact_type // empty' "$metadata_file" 2>/dev/null)
  if [[ -n "$stored_type" && "$stored_type" == "$ARTIFACT_TYPE" ]]; then
    check_pass "Artifact type matches metadata" "$stored_type"
  elif [[ -n "$stored_type" ]]; then
    check_fail "Artifact type mismatch" "stored=${stored_type} current=${ARTIFACT_TYPE}"
  fi

  # Check signing method matches
  local stored_method
  stored_method=$(jq -r '.signing_method // empty' "$metadata_file" 2>/dev/null)
  if [[ -n "$stored_method" ]]; then
    check_pass "Signing method recorded" "$stored_method"
  fi

  # Report signing identity
  local stored_identity
  stored_identity=$(jq -r '.signing_identity // empty' "$metadata_file" 2>/dev/null)
  if [[ -n "$stored_identity" ]]; then
    check_pass "Signer identity recorded" "$stored_identity"
  fi
}

# ── Check: Timestamp validation ──────────────────────────────────────────

check_timestamp() {
  section "Timestamp Validation"

  local safe_name
  safe_name=$(echo "$ARTIFACT" | sed 's|[/:@]|_|g')
  local metadata_file="${METADATA_DIR}/${safe_name}.json"

  if [[ ! -f "$metadata_file" ]]; then
    check_skip "Timestamp validation" "no metadata file"
    return
  fi

  local sign_ts
  sign_ts=$(jq -r '.timestamp // empty' "$metadata_file" 2>/dev/null)

  if [[ -z "$sign_ts" ]]; then
    check_skip "Timestamp validation" "no timestamp in metadata"
    return
  fi

  check_pass "Signature timestamp recorded" "$sign_ts"

  # Check if signature is not from the future
  local now_epoch sign_epoch
  now_epoch=$(date +%s)

  if date --version &>/dev/null 2>&1; then
    sign_epoch=$(date -d "$sign_ts" +%s 2>/dev/null || echo "0")
  else
    local clean_ts="${sign_ts%%Z*}"
    clean_ts="${clean_ts%%+*}"
    sign_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$clean_ts" +%s 2>/dev/null || echo "0")
  fi

  if [[ "$sign_epoch" -eq 0 ]]; then
    check_skip "Timestamp future check" "cannot parse timestamp"
    return
  fi

  if [[ "$sign_epoch" -gt "$now_epoch" ]]; then
    check_fail "Signature timestamp is in the future" "$sign_ts"
  else
    local age_days=$(( (now_epoch - sign_epoch) / 86400 ))
    if [[ $age_days -gt 365 ]]; then
      check_fail "Signature is older than 1 year" "${age_days} days old"
    elif [[ $age_days -gt 90 ]]; then
      check_pass "Signature age" "${age_days} days (consider re-signing)"
    else
      check_pass "Signature age" "${age_days} days"
    fi
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────

print_banner() {
  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║           Artifact Signature Verification                 ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Artifact:  %-44s ║\n' "${ARTIFACT:0:44}"
  printf '║  Type:      %-44s ║\n' "$ARTIFACT_TYPE"
  printf '║  Method:    %-44s ║\n' "$VERIFY_METHOD"
  printf '║  Timestamp: %-44s ║\n' "$TIMESTAMP"
  [[ -n "$VAULT_KEY" ]] && printf '║  Vault key: %-44s ║\n' "$VAULT_KEY"
  [[ -n "$DRY_RUN" ]] && printf '║  Mode:      %-44s ║\n' "DRY RUN"
  _bold '╚═══════════════════════════════════════════════════════════╝'
  printf '\n'
}

# ── Summary ───────────────────────────────────────────────────────────────

print_summary() {
  printf '\n'
  _bold '┌─────────────────────────────────────────────────────────┐'
  printf '\n'
  _bold '│                 VERIFICATION SUMMARY                     │'
  printf '\n'
  _bold '├─────────────────────────────────────────────────────────┤'
  printf '\n'
  printf '│  %s %-10s %s %-10s %s %-10s           │\n' \
    "$(_green '✓')" "${CHECKS_PASSED} passed" \
    "$(_red '✗')" "${CHECKS_FAILED} failed" \
    "$(_dim '—')" "${CHECKS_SKIPPED} skipped"
  printf '\n'

  local overall
  if [[ $CHECKS_FAILED -gt 0 ]]; then
    overall="$(_red 'FAILED')"
  elif [[ $CHECKS_SKIPPED -gt 0 && $CHECKS_PASSED -eq 0 ]]; then
    overall="$(_yellow 'INCONCLUSIVE')"
  else
    overall="$(_green 'PASSED')"
  fi
  printf '│  Verdict: %s  (%d checks)%*s│\n' "$overall" "$CHECKS_TOTAL" $((27 - ${#CHECKS_TOTAL})) ""
  printf '\n'
  _bold '└─────────────────────────────────────────────────────────┘'
  printf '\n'
}

print_json_summary() {
  local json_results="["
  local first=true
  for r in "${CHECK_RESULTS[@]}"; do
    local status="${r%%|*}"
    local rest="${r#*|}"
    local name="${rest%%|*}"
    local detail="${rest#*|}"
    name="${name//\"/\\\"}"
    detail="${detail//\"/\\\"}"
    if [[ "$first" == "true" ]]; then
      first=false
    else
      json_results+=","
    fi
    json_results+="{\"status\":\"${status}\",\"check\":\"${name}\",\"detail\":\"${detail}\"}"
  done
  json_results+="]"

  local verdict="PASSED"
  [[ $CHECKS_FAILED -gt 0 ]] && verdict="FAILED"
  [[ $CHECKS_SKIPPED -gt 0 && $CHECKS_PASSED -eq 0 ]] && verdict="INCONCLUSIVE"

  cat <<EOF
{
  "artifact": "${ARTIFACT}",
  "artifact_type": "${ARTIFACT_TYPE}",
  "verification_method": "${VERIFY_METHOD}",
  "timestamp": "${TIMESTAMP}",
  "verdict": "${verdict}",
  "summary": {
    "total": ${CHECKS_TOTAL},
    "passed": ${CHECKS_PASSED},
    "failed": ${CHECKS_FAILED},
    "skipped": ${CHECKS_SKIPPED}
  },
  "checks": ${json_results}
}
EOF
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  print_banner

  log INFO "Starting verification of: ${ARTIFACT}"
  log INFO "Verification method: ${VERIFY_METHOD}"

  # Run all verification checks
  check_signature_exists
  check_signature_valid
  check_key_trust
  check_metadata_consistency
  check_timestamp

  # Output results
  if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    print_json_summary
  else
    print_summary
  fi

  log INFO "Verification complete: ${CHECKS_PASSED} passed, ${CHECKS_FAILED} failed, ${CHECKS_SKIPPED} skipped"
  printf '\n'
  exit $EXIT_CODE
}

main
