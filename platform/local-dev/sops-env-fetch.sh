#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# sops-env-fetch.sh — Decrypt SOPS-encrypted files to environment variables
#
# Reads SOPS-encrypted YAML or JSON files and outputs KEY=value pairs suitable
# for eval or sourcing. Decrypted content NEVER touches disk — all output goes
# to stdout or is eval'd directly.
#
# Usage:
#   eval "$(./sops-env-fetch.sh --file secrets.enc.yaml)"
#   eval "$(./sops-env-fetch.sh --file secrets.enc.yaml --prefix APP_)"
#   ./sops-env-fetch.sh --file secrets.enc.json --export
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"

# --- Logging ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*" >&2; }
ok()    { echo -e "${GREEN}[✓]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $*" >&2; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# --- Defaults ---
SOPS_FILE=""
PREFIX=""
EXPORT_MODE="eval"  # "eval" prints export statements; "print" prints KEY=value

usage() {
  cat >&2 <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Decrypt a SOPS-encrypted YAML/JSON file and output environment variables.
Decrypted content never touches the filesystem.

Options:
  --file FILE        Path to SOPS-encrypted file (required)
  --prefix PREFIX    Prefix to prepend to variable names (e.g. APP_)
  --export           Print KEY=value pairs (no export keyword), suitable for
                     piping to other tools. Default: print export statements.
  --help             Show this help message

Examples:
  # Load secrets into current shell
  eval "\$($SCRIPT_NAME --file secrets.enc.yaml)"

  # Load with prefix
  eval "\$($SCRIPT_NAME --file secrets.enc.yaml --prefix DB_)"

  # Print without export (for piping to docker run --env-file)
  $SCRIPT_NAME --file secrets.enc.yaml --export > /dev/stdin

  # Use with process substitution (no disk writes)
  docker run --env-file <($SCRIPT_NAME --file secrets.enc.yaml --export) myimage
EOF
  exit "${1:-0}"
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)
      SOPS_FILE="$2"
      shift 2
      ;;
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --export)
      EXPORT_MODE="print"
      shift
      ;;
    --help|-h)
      usage 0
      ;;
    *)
      die "Unknown option: $1 (see --help)"
      ;;
  esac
done

# --- Validation ---
[[ -n "$SOPS_FILE" ]] || die "Missing required --file argument (see --help)"
[[ -f "$SOPS_FILE" ]] || die "File not found: $SOPS_FILE"

if ! command -v sops &>/dev/null; then
  die "sops is required but not found. Install: https://github.com/getsops/sops"
fi

if ! command -v jq &>/dev/null; then
  die "jq is required but not found. Install: https://stedolan.github.io/jq/"
fi

# --- Detect file format ---
case "$SOPS_FILE" in
  *.yaml|*.yml) FORMAT="yaml" ;;
  *.json)       FORMAT="json" ;;
  *)            die "Unsupported file extension. Use .yaml, .yml, or .json" ;;
esac

# --- Decrypt and convert to env vars ---
# Decryption happens entirely in memory via pipe to jq.
# No temporary files are created.
info "Decrypting $SOPS_FILE..."

DECRYPTED_JSON=$(sops -d --output-type json "$SOPS_FILE" 2>/dev/null) || \
  die "SOPS decryption failed. Check your key configuration (age/pgp/kms)."

# Flatten nested YAML/JSON to top-level KEY=value pairs.
# Nested keys are joined with underscore: parent.child -> PARENT_CHILD
# Arrays are skipped (not representable as env vars).
_flatten_to_env() {
  echo "$DECRYPTED_JSON" | jq -r '
    # Recursively flatten, joining keys with _
    [paths(scalars)] as $paths |
    $paths[] |
    . as $path |
    ($path | map(
      if type == "number" then tostring
      else .
      end
    ) | join("_") | ascii_upcase) as $key |
    (getpath($path) | tostring) as $val |
    "\($key)\t\($val)"
  '
}

COUNT=0
while IFS=$'\t' read -r key value; do
  # Skip SOPS metadata keys
  case "$key" in
    SOPS_*) continue ;;
  esac

  FULL_KEY="${PREFIX}${key}"

  case "$EXPORT_MODE" in
    eval)
      printf 'export %s=%s\n' "$FULL_KEY" "$(printf '%q' "$value")"
      ;;
    print)
      printf '%s=%s\n' "$FULL_KEY" "$value"
      ;;
  esac
  COUNT=$((COUNT + 1))
done < <(_flatten_to_env)

ok "Exported $COUNT variables from $SOPS_FILE" >&2

# Clear sensitive data from shell variables
unset DECRYPTED_JSON
