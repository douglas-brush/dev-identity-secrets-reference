#!/usr/bin/env bash
# rotate_sops_keys.sh — SOPS encryption key rotation tool
# Re-encrypts all .enc.yaml files with updated recipients from .sops.yaml
# Usage: rotate_sops_keys.sh [--dry-run] [--env <environment>] [--verbose] [--log-file <path>]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${REPO_ROOT}/logs/sops-rotation-${TIMESTAMP//[:T]/-}.log"

# ── Defaults ──────────────────────────────────────────────────────────────

DRY_RUN=""
TARGET_ENV=""
VERBOSE=""
EXIT_CODE=0

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }

# ── Logging ───────────────────────────────────────────────────────────────

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} [${level}] ${msg}"

  case "$level" in
    INFO)  printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)  printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR) printf '  %s %s\n' "$(_red 'ERROR')" "$msg" ;;
    OK)    printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    DRY)   printf '  %s %s\n' "$(_yellow ' DRY')" "$msg" ;;
  esac

  # Append to log file
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "$entry" >> "$LOG_FILE"
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'rotate_sops_keys.sh') — SOPS encryption key rotation

$(_bold 'USAGE')
  rotate_sops_keys.sh [OPTIONS]

$(_bold 'OPTIONS')
  --dry-run           Show what would be re-encrypted without making changes
  --env <environment> Only rotate files matching environment (dev|staging|prod)
  --log-file <path>   Custom log file path (default: logs/sops-rotation-<ts>.log)
  --verbose           Show detailed output
  -h, --help          Show this help

$(_bold 'PREREQUISITES')
  - sops CLI installed
  - age or GPG keys available for decryption of current files
  - Updated .sops.yaml with new recipients before running
  - SOPS_AGE_KEY_FILE set (or default ~/.config/sops/age/keys.txt)

$(_bold 'WORKFLOW')
  1. Update .sops.yaml with new age/KMS recipients
  2. Run: rotate_sops_keys.sh --dry-run
  3. Review the plan
  4. Run: rotate_sops_keys.sh
  5. Verify: rotate_sops_keys.sh --dry-run (should show no changes needed)
  6. Commit the re-encrypted files

$(_bold 'EXAMPLES')
  rotate_sops_keys.sh --dry-run              # Preview rotation
  rotate_sops_keys.sh --env prod             # Rotate only production secrets
  rotate_sops_keys.sh --verbose              # Rotate all with detailed output
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)      usage ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --env)          TARGET_ENV="$2"; shift 2 ;;
    --log-file)     LOG_FILE="$2"; shift 2 ;;
    --verbose)      VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# ── Preflight checks ─────────────────────────────────────────────────────

preflight() {
  printf '\n%s\n\n' "$(_bold '═══ SOPS Key Rotation ═══')"

  if [[ -n "$DRY_RUN" ]]; then
    printf '  %s\n\n' "$(_yellow 'DRY RUN MODE — no files will be modified')"
  fi

  # Check sops
  if ! command -v sops &>/dev/null; then
    log ERROR "sops CLI not found — install it first"
    exit 1
  fi
  log INFO "sops version: $(sops --version 2>/dev/null | head -1)"

  # Check .sops.yaml
  local sops_config="${REPO_ROOT}/.sops.yaml"
  if [[ ! -f "$sops_config" ]]; then
    log ERROR ".sops.yaml not found at ${sops_config}"
    exit 1
  fi
  log OK ".sops.yaml found"

  # Check age key availability
  local age_key_file="${SOPS_AGE_KEY_FILE:-${HOME}/.config/sops/age/keys.txt}"
  if [[ -f "$age_key_file" ]]; then
    local key_count
    key_count=$(grep -c 'AGE-SECRET-KEY-' "$age_key_file" 2>/dev/null || echo "0")
    log OK "age key file found with ${key_count} key(s)"
  else
    log WARN "age key file not found at ${age_key_file} — may fail if files use age encryption"
  fi

  log INFO "Log file: ${LOG_FILE}"
}

# ── Find encrypted files ─────────────────────────────────────────────────

find_encrypted_files() {
  local files=()

  while IFS= read -r -d '' f; do
    # Verify file is actually SOPS-encrypted
    if grep -q 'sops:' "$f" 2>/dev/null || grep -q '"sops":' "$f" 2>/dev/null; then
      # Apply environment filter if specified
      if [[ -n "$TARGET_ENV" ]]; then
        case "$TARGET_ENV" in
          dev|staging|prod)
            if [[ "$f" == *"/${TARGET_ENV}/"* || "$f" == *".${TARGET_ENV}."* || "$f" == *"-${TARGET_ENV}"* ]]; then
              files+=("$f")
            fi
            ;;
          *)
            log ERROR "Invalid environment: ${TARGET_ENV} — use dev, staging, or prod"
            exit 2
            ;;
        esac
      else
        files+=("$f")
      fi
    fi
  done < <(find "$REPO_ROOT" -type f \( \
    -name '*.enc.yaml' -o -name '*.enc.yml' -o -name '*.enc.json' \
    -o -name '*.sops.yaml' -o -name '*.sops.yml' -o -name '*.sops.json' \
  \) -not -path '*/.git/*' -not -path '*/node_modules/*' -print0 2>/dev/null)

  # Also check files that contain sops metadata but have regular extensions
  while IFS= read -r -d '' f; do
    local already_found=false
    for existing in "${files[@]+"${files[@]}"}"; do
      if [[ "$existing" == "$f" ]]; then
        already_found=true
        break
      fi
    done
    if [[ "$already_found" == "false" ]]; then
      if grep -q 'sops:' "$f" 2>/dev/null && grep -q 'lastmodified:' "$f" 2>/dev/null; then
        if [[ -z "$TARGET_ENV" ]] || [[ "$f" == *"/${TARGET_ENV}/"* ]]; then
          files+=("$f")
        fi
      fi
    fi
  done < <(find "$REPO_ROOT/secrets" -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) \
    -not -path '*/.git/*' -print0 2>/dev/null || true)

  printf '%s\n' "${files[@]+"${files[@]}"}"
}

# ── Rotate a single file ─────────────────────────────────────────────────

rotate_file() {
  local file="$1"
  local relative="${file#"$REPO_ROOT"/}"

  [[ -n "$VERBOSE" ]] && log INFO "Processing: ${relative}"

  # Get current recipients hash for comparison
  local current_hash
  current_hash=$(grep -A5 'sops:' "$file" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)

  if [[ -n "$DRY_RUN" ]]; then
    # Verify we can decrypt
    if sops --decrypt "$file" >/dev/null 2>&1; then
      log DRY "Would re-encrypt: ${relative}"
    else
      log WARN "Cannot decrypt: ${relative} — rotation will fail"
      EXIT_CODE=1
    fi
    return
  fi

  # Decrypt to temp file
  local tmpfile
  tmpfile=$(mktemp)
  trap "rm -f '$tmpfile'" RETURN

  if ! sops --decrypt "$file" > "$tmpfile" 2>/dev/null; then
    log ERROR "Failed to decrypt: ${relative}"
    rm -f "$tmpfile"
    EXIT_CODE=1
    return
  fi

  # Re-encrypt with current .sops.yaml recipients
  if ! sops --encrypt --input-type "${file##*.}" --output-type "${file##*.}" "$tmpfile" > "${file}.new" 2>/dev/null; then
    log ERROR "Failed to re-encrypt: ${relative}"
    rm -f "$tmpfile" "${file}.new"
    EXIT_CODE=1
    return
  fi

  # Verify the new file can be decrypted
  if ! sops --decrypt "${file}.new" >/dev/null 2>&1; then
    log ERROR "Verification failed for re-encrypted file: ${relative}"
    rm -f "$tmpfile" "${file}.new"
    EXIT_CODE=1
    return
  fi

  # Check if content actually changed
  local new_hash
  new_hash=$(grep -A5 'sops:' "${file}.new" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)

  if [[ "$current_hash" == "$new_hash" ]]; then
    log INFO "No recipient changes for: ${relative}"
    rm -f "${file}.new"
  else
    mv "${file}.new" "$file"
    log OK "Rotated: ${relative}"
  fi

  rm -f "$tmpfile"
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  preflight

  printf '\n%s\n' "$(_bold '── Finding encrypted files ──')"

  local files_list
  files_list=$(find_encrypted_files)

  if [[ -z "$files_list" ]]; then
    log WARN "No encrypted files found to rotate"
    if [[ -n "$TARGET_ENV" ]]; then
      log INFO "Filter was set to environment: ${TARGET_ENV}"
    fi
    exit 0
  fi

  local file_count
  file_count=$(echo "$files_list" | wc -l | tr -d ' ')
  log INFO "Found ${file_count} encrypted file(s) to process"

  if [[ -n "$TARGET_ENV" ]]; then
    log INFO "Environment filter: ${TARGET_ENV}"
  fi

  printf '\n%s\n' "$(_bold '── Processing files ──')"

  local success_count=0
  local error_count=0

  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    if rotate_file "$file"; then
      success_count=$((success_count + 1))
    fi
  done <<< "$files_list"

  # ── Summary ──────────────────────────────────────────────────────────

  printf '\n%s\n' "$(_bold '── Rotation Summary ──')"
  log INFO "Files processed: ${file_count}"
  log INFO "Log file: ${LOG_FILE}"

  if [[ -n "$DRY_RUN" ]]; then
    printf '\n  %s\n' "$(_yellow 'Dry run complete — no files were modified')"
    printf '  %s\n\n' "Run without --dry-run to apply changes"
  else
    if [[ $EXIT_CODE -eq 0 ]]; then
      printf '\n  %s\n\n' "$(_green 'Rotation complete — verify and commit the changes')"
    else
      printf '\n  %s\n\n' "$(_red 'Rotation completed with errors — review log file')"
    fi
  fi

  exit $EXIT_CODE
}

main
