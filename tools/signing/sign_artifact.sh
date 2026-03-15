#!/usr/bin/env bash
# sign_artifact.sh — Sign container images, binaries, or SBOMs using cosign, notation, or Vault transit
# Usage: sign_artifact.sh --artifact <ref> --type <image|binary|sbom> [--key <vault-key>] [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_DIR="${REPO_ROOT}/logs"
LOG_FILE="${LOG_DIR}/signing-${TIMESTAMP//[:T]/-}.log"
METADATA_DIR="${REPO_ROOT}/.signatures"

# ── Defaults ──────────────────────────────────────────────────────────────

ARTIFACT=""
ARTIFACT_TYPE=""
VAULT_KEY=""
VERIFY_MODE=""
DRY_RUN=""
VERBOSE=""
NO_COLOR="${NO_COLOR:-}"
OUTPUT_FORMAT="text"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-$(whoami)@$(hostname -s)}"
EXIT_CODE=0

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

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'sign_artifact.sh') — Artifact signing with cosign, notation, or Vault transit

$(_bold 'USAGE')
  sign_artifact.sh --artifact <ref> --type <type> [OPTIONS]

$(_bold 'REQUIRED')
  --artifact <ref>        File path or container image reference to sign
  --type <type>           Artifact type: image, binary, or sbom

$(_bold 'OPTIONS')
  --key <name>            Vault transit key name for signing
  --verify                Verify existing signature instead of signing
  --output-format <fmt>   Output format: text (default) or json
  --identity <id>         Signer identity (default: user@host)
  --metadata-dir <path>   Directory for signature metadata (default: .signatures/)
  --dry-run               Show what would be done without signing
  --verbose               Show additional diagnostic info
  --no-color              Disable colored output
  -h, --help              Show this help

$(_bold 'SIGNING METHODS (auto-detected)')
  1. cosign with Vault KMS     — COSIGN_KEY=hashivault://<key> or --key flag + VAULT_ADDR
  2. cosign keyless (Fulcio)   — cosign available, no key specified, OIDC token present
  3. notation                  — notation available, cosign not found
  4. Vault transit direct      — vault CLI available, --key specified, no cosign/notation

$(_bold 'ENVIRONMENT')
  VAULT_ADDR              Vault server address (for Vault transit or cosign KMS)
  VAULT_TOKEN             Vault authentication token
  COSIGN_KEY              Override cosign key reference (e.g. hashivault://mykey)
  SIGNING_IDENTITY        Override signer identity string
  NO_COLOR                Disable colored output

$(_bold 'EXIT CODES')
  0   Signing/verification succeeded
  1   Signing/verification failed
  2   Usage error or missing dependencies

$(_bold 'EXAMPLES')
  # Sign a container image with cosign + Vault KMS
  sign_artifact.sh --artifact ghcr.io/org/app:v1.2.3 --type image --key transit-sign-key

  # Sign a binary with Vault transit directly
  sign_artifact.sh --artifact ./dist/myapp-linux-amd64 --type binary --key code-signing

  # Sign an SBOM file
  sign_artifact.sh --artifact ./sbom.spdx.json --type sbom --key sbom-key

  # Keyless signing (Fulcio/OIDC) for a container image
  sign_artifact.sh --artifact ghcr.io/org/app:sha-abc1234 --type image

  # Verify a signed image
  sign_artifact.sh --artifact ghcr.io/org/app:v1.2.3 --type image --verify

  # Dry run
  sign_artifact.sh --artifact ./dist/binary --type binary --key mykey --dry-run
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)          usage ;;
    --artifact)         ARTIFACT="$2"; shift 2 ;;
    --type)             ARTIFACT_TYPE="$2"; shift 2 ;;
    --key)              VAULT_KEY="$2"; shift 2 ;;
    --verify)           VERIFY_MODE=1; shift ;;
    --output-format)    OUTPUT_FORMAT="$2"; shift 2 ;;
    --identity)         SIGNING_IDENTITY="$2"; shift 2 ;;
    --metadata-dir)     METADATA_DIR="$2"; shift 2 ;;
    --dry-run)          DRY_RUN=1; shift ;;
    --verbose)          VERBOSE=1; shift ;;
    --no-color)         NO_COLOR=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run sign_artifact.sh --help for usage.\n' >&2
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
if [[ "$ARTIFACT_TYPE" != "image" && -z "$VERIFY_MODE" ]]; then
  [[ -f "$ARTIFACT" ]] || die "Artifact file not found: ${ARTIFACT}" 2
fi

# ── Tool detection ────────────────────────────────────────────────────────

HAS_COSIGN=""
HAS_NOTATION=""
HAS_VAULT=""

command -v cosign &>/dev/null && HAS_COSIGN=1
command -v notation &>/dev/null && HAS_NOTATION=1
command -v vault &>/dev/null && HAS_VAULT=1

detect_signing_method() {
  # Priority: cosign+Vault KMS > cosign keyless > notation > vault transit direct
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

SIGNING_METHOD=$(detect_signing_method)

if [[ "$SIGNING_METHOD" == "none" ]]; then
  die "No signing tool found. Install cosign, notation, or vault CLI." 2
fi

# ── Hash computation ──────────────────────────────────────────────────────

compute_hash() {
  local target="$1"
  local target_type="$2"

  if [[ "$target_type" == "image" ]]; then
    # For images, get the digest
    if [[ -n "$HAS_COSIGN" ]]; then
      cosign triangulate "$target" 2>/dev/null | head -1 || echo "digest-unavailable"
    elif command -v crane &>/dev/null; then
      crane digest "$target" 2>/dev/null || echo "digest-unavailable"
    else
      echo "digest-requires-crane-or-cosign"
    fi
  else
    # For files, compute SHA-256
    if command -v sha256sum &>/dev/null; then
      sha256sum "$target" | awk '{print "sha256:" $1}'
    else
      shasum -a 256 "$target" | awk '{print "sha256:" $1}'
    fi
  fi
}

# ── Signature metadata ───────────────────────────────────────────────────

store_metadata() {
  local artifact_ref="$1"
  local artifact_hash="$2"
  local signature="$3"
  local method="$4"

  mkdir -p "$METADATA_DIR"

  local safe_name
  safe_name=$(echo "$artifact_ref" | sed 's|[/:@]|_|g')
  local metadata_file="${METADATA_DIR}/${safe_name}.json"

  cat > "$metadata_file" <<EOF
{
  "artifact": "${artifact_ref}",
  "artifact_type": "${ARTIFACT_TYPE}",
  "artifact_hash": "${artifact_hash}",
  "signature": "${signature}",
  "signing_method": "${method}",
  "signing_identity": "${SIGNING_IDENTITY}",
  "vault_key": "${VAULT_KEY:-none}",
  "timestamp": "${TIMESTAMP}",
  "tool_versions": {
    "cosign": "$(cosign version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'n/a')",
    "notation": "$(notation version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'n/a')",
    "vault": "$(vault version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'n/a')"
  }
}
EOF

  log OK "Signature metadata stored: ${metadata_file#"$REPO_ROOT"/}"
}

# ── Signing methods ───────────────────────────────────────────────────────

sign_with_cosign_vault() {
  local artifact_ref="$1"
  local key_ref="${COSIGN_KEY:-hashivault://${VAULT_KEY}}"

  log INFO "Signing with cosign + Vault KMS: ${key_ref}"

  if [[ "$ARTIFACT_TYPE" == "image" ]]; then
    if [[ -n "$DRY_RUN" ]]; then
      log DRY "cosign sign --key ${key_ref} ${artifact_ref}"
      return 0
    fi
    cosign sign --key "$key_ref" \
      --annotation "signer=${SIGNING_IDENTITY}" \
      --annotation "timestamp=${TIMESTAMP}" \
      --annotation "type=${ARTIFACT_TYPE}" \
      --yes \
      "$artifact_ref" 2>&1 | while IFS= read -r line; do log DEBUG "$line"; done
  else
    # Sign file — produces detached signature
    if [[ -n "$DRY_RUN" ]]; then
      log DRY "cosign sign-blob --key ${key_ref} ${artifact_ref}"
      return 0
    fi
    local sig_file="${artifact_ref}.sig"
    cosign sign-blob --key "$key_ref" \
      --output-signature "$sig_file" \
      --yes \
      "$artifact_ref" 2>&1 | while IFS= read -r line; do log DEBUG "$line"; done
    log OK "Detached signature: ${sig_file}"
  fi
}

sign_with_cosign_keyless() {
  local artifact_ref="$1"

  log INFO "Signing with cosign keyless (Fulcio/OIDC)"

  if [[ "$ARTIFACT_TYPE" == "image" ]]; then
    if [[ -n "$DRY_RUN" ]]; then
      log DRY "cosign sign --yes ${artifact_ref} (keyless)"
      return 0
    fi
    COSIGN_EXPERIMENTAL=1 cosign sign \
      --annotation "signer=${SIGNING_IDENTITY}" \
      --annotation "timestamp=${TIMESTAMP}" \
      --annotation "type=${ARTIFACT_TYPE}" \
      --yes \
      "$artifact_ref" 2>&1 | while IFS= read -r line; do log DEBUG "$line"; done
  else
    if [[ -n "$DRY_RUN" ]]; then
      log DRY "cosign sign-blob --yes ${artifact_ref} (keyless)"
      return 0
    fi
    local sig_file="${artifact_ref}.sig"
    local cert_file="${artifact_ref}.cert"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob \
      --output-signature "$sig_file" \
      --output-certificate "$cert_file" \
      --yes \
      "$artifact_ref" 2>&1 | while IFS= read -r line; do log DEBUG "$line"; done
    log OK "Detached signature: ${sig_file}"
    log OK "Certificate: ${cert_file}"
  fi
}

sign_with_notation() {
  local artifact_ref="$1"

  log INFO "Signing with notation"

  if [[ "$ARTIFACT_TYPE" != "image" ]]; then
    die "notation only supports container image signing. Use cosign or vault transit for files."
  fi

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "notation sign ${artifact_ref}"
    return 0
  fi

  notation sign "$artifact_ref" 2>&1 | while IFS= read -r line; do log DEBUG "$line"; done
}

sign_with_vault_transit() {
  local artifact_ref="$1"

  log INFO "Signing with Vault transit key: ${VAULT_KEY}"

  # Verify Vault connectivity
  if [[ -z "${VAULT_ADDR:-}" ]]; then
    die "VAULT_ADDR is required for Vault transit signing" 2
  fi
  if ! vault token lookup &>/dev/null 2>&1; then
    die "Cannot authenticate to Vault — check VAULT_TOKEN" 2
  fi

  # Compute hash of the artifact
  local artifact_hash
  artifact_hash=$(compute_hash "$artifact_ref" "$ARTIFACT_TYPE")
  log DEBUG "Artifact hash: ${artifact_hash}"

  # For files, base64-encode the hash for transit
  local input_b64
  if [[ "$ARTIFACT_TYPE" == "image" ]]; then
    # Hash the image reference string for transit signing
    input_b64=$(printf '%s' "$artifact_hash" | base64)
  else
    # Hash the file content
    local raw_hash="${artifact_hash#sha256:}"
    input_b64=$(printf '%s' "$raw_hash" | base64)
  fi

  if [[ -n "$DRY_RUN" ]]; then
    log DRY "vault write transit/sign/${VAULT_KEY} input=${input_b64}"
    return 0
  fi

  local sign_result
  sign_result=$(vault write -format=json "transit/sign/${VAULT_KEY}" \
    input="$input_b64" \
    hash_algorithm=sha2-256 \
    signature_algorithm=pkcs1v15 2>/dev/null) || die "Vault transit sign failed"

  local signature
  signature=$(echo "$sign_result" | jq -r '.data.signature // empty')

  if [[ -z "$signature" ]]; then
    die "No signature returned from Vault transit"
  fi

  # Write detached signature file
  local sig_file="${artifact_ref}.vault-sig"
  echo "$signature" > "$sig_file"
  log OK "Vault transit signature: ${sig_file}"

  # Store metadata
  store_metadata "$artifact_ref" "$artifact_hash" "$signature" "vault-transit"
}

# ── Verification methods ─────────────────────────────────────────────────

verify_with_cosign_vault() {
  local artifact_ref="$1"
  local key_ref="${COSIGN_KEY:-hashivault://${VAULT_KEY}}"

  log INFO "Verifying with cosign + Vault KMS: ${key_ref}"

  if [[ "$ARTIFACT_TYPE" == "image" ]]; then
    cosign verify --key "$key_ref" "$artifact_ref" 2>&1
  else
    local sig_file="${artifact_ref}.sig"
    [[ -f "$sig_file" ]] || die "Signature file not found: ${sig_file}"
    cosign verify-blob --key "$key_ref" \
      --signature "$sig_file" \
      "$artifact_ref" 2>&1
  fi
}

verify_with_cosign_keyless() {
  local artifact_ref="$1"

  log INFO "Verifying with cosign keyless"

  if [[ "$ARTIFACT_TYPE" == "image" ]]; then
    COSIGN_EXPERIMENTAL=1 cosign verify "$artifact_ref" 2>&1
  else
    local sig_file="${artifact_ref}.sig"
    local cert_file="${artifact_ref}.cert"
    [[ -f "$sig_file" ]] || die "Signature file not found: ${sig_file}"
    [[ -f "$cert_file" ]] || die "Certificate file not found: ${cert_file}"
    COSIGN_EXPERIMENTAL=1 cosign verify-blob \
      --signature "$sig_file" \
      --certificate "$cert_file" \
      "$artifact_ref" 2>&1
  fi
}

verify_with_notation() {
  local artifact_ref="$1"

  log INFO "Verifying with notation"

  if [[ "$ARTIFACT_TYPE" != "image" ]]; then
    die "notation verification only supports container images"
  fi

  notation verify "$artifact_ref" 2>&1
}

verify_with_vault_transit() {
  local artifact_ref="$1"

  log INFO "Verifying with Vault transit key: ${VAULT_KEY}"

  if [[ -z "${VAULT_ADDR:-}" ]]; then
    die "VAULT_ADDR is required for Vault transit verification" 2
  fi

  # Read the signature file
  local sig_file="${artifact_ref}.vault-sig"
  [[ -f "$sig_file" ]] || die "Vault signature file not found: ${sig_file}"

  local signature
  signature=$(cat "$sig_file")

  # Compute hash of the artifact
  local artifact_hash
  artifact_hash=$(compute_hash "$artifact_ref" "$ARTIFACT_TYPE")

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
    signature_algorithm=pkcs1v15 2>/dev/null) || die "Vault transit verify failed"

  local valid
  valid=$(echo "$verify_result" | jq -r '.data.valid // false')

  if [[ "$valid" == "true" ]]; then
    log OK "Signature is VALID"
    return 0
  else
    log ERROR "Signature is INVALID"
    return 1
  fi
}

# ── Banner ────────────────────────────────────────────────────────────────

print_banner() {
  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════╗'
  printf '\n'
  if [[ -n "$VERIFY_MODE" ]]; then
    _bold '║           Artifact Signature Verification                 ║'
  else
    _bold '║           Artifact Signing Tool                           ║'
  fi
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Artifact:  %-44s ║\n' "${ARTIFACT:0:44}"
  printf '║  Type:      %-44s ║\n' "$ARTIFACT_TYPE"
  printf '║  Method:    %-44s ║\n' "$SIGNING_METHOD"
  printf '║  Timestamp: %-44s ║\n' "$TIMESTAMP"
  [[ -n "$VAULT_KEY" ]] && printf '║  Vault key: %-44s ║\n' "$VAULT_KEY"
  [[ -n "$DRY_RUN" ]] && printf '║  Mode:      %-44s ║\n' "DRY RUN"
  _bold '╚═══════════════════════════════════════════════════════════╝'
  printf '\n\n'
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  print_banner

  if [[ -n "$VERIFY_MODE" ]]; then
    # ── Verification path ──
    log INFO "Verifying signature on: ${ARTIFACT}"

    case "$SIGNING_METHOD" in
      cosign-vault)    verify_with_cosign_vault "$ARTIFACT" ;;
      cosign-keyless)  verify_with_cosign_keyless "$ARTIFACT" ;;
      notation)        verify_with_notation "$ARTIFACT" ;;
      vault-transit)   verify_with_vault_transit "$ARTIFACT" ;;
      *) die "Unknown signing method: ${SIGNING_METHOD}" ;;
    esac

    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 0 ]]; then
      printf '\n  %s Signature verification %s\n\n' "$(_green '✓')" "$(_green 'PASSED')"
    else
      printf '\n  %s Signature verification %s\n\n' "$(_red '✗')" "$(_red 'FAILED')"
    fi
  else
    # ── Signing path ──
    log INFO "Signing artifact: ${ARTIFACT}"

    # Compute pre-sign hash
    local artifact_hash
    artifact_hash=$(compute_hash "$ARTIFACT" "$ARTIFACT_TYPE")
    log INFO "Artifact hash: ${artifact_hash}"

    case "$SIGNING_METHOD" in
      cosign-vault)    sign_with_cosign_vault "$ARTIFACT" ;;
      cosign-keyless)  sign_with_cosign_keyless "$ARTIFACT" ;;
      notation)        sign_with_notation "$ARTIFACT" ;;
      vault-transit)   sign_with_vault_transit "$ARTIFACT" ;;
      *) die "Unknown signing method: ${SIGNING_METHOD}" ;;
    esac

    EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 0 ]]; then
      # Store metadata for non-vault-transit (vault-transit stores its own)
      if [[ "$SIGNING_METHOD" != "vault-transit" ]]; then
        store_metadata "$ARTIFACT" "$artifact_hash" "stored-by-${SIGNING_METHOD}" "$SIGNING_METHOD"
      fi

      printf '\n  %s Artifact signed successfully\n' "$(_green '✓')"
      log OK "Signing complete: ${ARTIFACT} via ${SIGNING_METHOD}"

      if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        cat <<EOF
{
  "status": "signed",
  "artifact": "${ARTIFACT}",
  "artifact_type": "${ARTIFACT_TYPE}",
  "artifact_hash": "${artifact_hash}",
  "signing_method": "${SIGNING_METHOD}",
  "signing_identity": "${SIGNING_IDENTITY}",
  "vault_key": "${VAULT_KEY:-none}",
  "timestamp": "${TIMESTAMP}",
  "dry_run": ${DRY_RUN:-false}
}
EOF
      fi
    else
      printf '\n  %s Signing failed\n' "$(_red '✗')"
    fi
  fi

  printf '\n'
  exit $EXIT_CODE
}

main
