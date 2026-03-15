#!/usr/bin/env bash
# sirm-evidence — SIRM evidence chain management
# Registers, verifies, and tracks evidence with chain of custody.
# All operations are READ-ONLY on source files — hash and record, never touch.
# Usage: sirm-evidence.sh <command> [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Color & output ──────────────────────────────────────────────────────────

NO_COLOR="${NO_COLOR:-}"
VERBOSE="${VERBOSE:-}"

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

log_pass() { printf '  %s %s\n' "$(_green '✓ PASS')" "$1"; }
log_warn() { printf '  %s %s\n' "$(_yellow '⚠ WARN')" "$1"; }
log_fail() { printf '  %s %s\n' "$(_red '✗ FAIL')" "$1"; }
log_info() { [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_blue 'ℹ INFO')" "$1" || true; }

section() { printf '\n%s\n' "$(_bold "═══ $1 ═══")"; }

die() { printf '%s\n' "$(_red "Error: $1")" >&2; exit 1; }

# ── Globals ─────────────────────────────────────────────────────────────────

SESSION_DIR="./sessions"
COMMAND=""
SESSION_ID=""
FILE_PATH=""
EVIDENCE_ID=""
DESCRIPTION=""
CLASSIFICATION="INTERNAL"
TRANSFER_TO=""
TRANSFER_REASON=""
MANIFEST_FORMAT="text"

# ── Help ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'sirm-evidence') — SIRM evidence chain management

$(_bold 'USAGE')
  sirm-evidence.sh <command> <session-id> [OPTIONS]

$(_bold 'COMMANDS')
  register <session-id> <file-path>     Register evidence (hash, record, never copy)
  verify   <session-id> [evidence-id]   Re-hash and verify evidence integrity
  transfer <session-id> <evidence-id>   Log custody transfer
  manifest <session-id>                 Generate evidence manifest
  list     <session-id>                 List registered evidence

$(_bold 'OPTIONS')
  --description <text>      Evidence description (for register)
  --classification <level>  Evidence classification (for register)
  --to <custodian>          Transfer destination custodian
  --reason <text>           Transfer reason
  --format <fmt>            Manifest format: json, text (default: text)
  --session-dir <path>      Session directory (default: ./sessions/)
  --no-color                Disable colored output
  --verbose                 Show additional info
  -h, --help                Show this help

$(_bold 'PRINCIPLES')
  - All evidence operations are READ-ONLY on source files
  - Files are NEVER copied, moved, or modified
  - SHA-256 hash is computed and recorded at registration
  - Chain of custody tracked for every transfer
  - Verify re-hashes and compares to detect tampering

$(_bold 'EXAMPLES')
  sirm-evidence.sh register abc123 /path/to/disk.img --description "Primary disk image"
  sirm-evidence.sh verify abc123
  sirm-evidence.sh verify abc123 EV-001
  sirm-evidence.sh transfer abc123 EV-001 --to "Lab Tech A" --reason "Forensic analysis"
  sirm-evidence.sh manifest abc123 --format json
  sirm-evidence.sh list abc123
EOF
  exit 0
}

# ── Argument parsing ────────────────────────────────────────────────────────

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)           usage ;;
    --no-color)          NO_COLOR=1; shift ;;
    --verbose)           VERBOSE=1; shift ;;
    --session-dir)       SESSION_DIR="$2"; shift 2 ;;
    --description)       DESCRIPTION="$2"; shift 2 ;;
    --classification)    CLASSIFICATION="$2"; shift 2 ;;
    --to)                TRANSFER_TO="$2"; shift 2 ;;
    --reason)            TRANSFER_REASON="$2"; shift 2 ;;
    --format)            MANIFEST_FORMAT="$2"; shift 2 ;;
    register|verify|transfer|manifest|list)
      COMMAND="$1"; shift
      # Next positional: session-id
      if [[ $# -gt 0 && "$1" != -* ]]; then
        SESSION_ID="$1"; shift
      fi
      # Next positional: file-path or evidence-id depending on command
      if [[ $# -gt 0 && "$1" != -* ]]; then
        case "$COMMAND" in
          register) FILE_PATH="$1"; shift ;;
          transfer|verify) EVIDENCE_ID="$1"; shift ;;
        esac
      fi
      ;;
    *)
      if [[ -z "$SESSION_ID" && "$1" != -* ]]; then
        SESSION_ID="$1"; shift
      elif [[ -z "$FILE_PATH" && "$COMMAND" == "register" && "$1" != -* ]]; then
        FILE_PATH="$1"; shift
      elif [[ -z "$EVIDENCE_ID" && ("$COMMAND" == "transfer" || "$COMMAND" == "verify") && "$1" != -* ]]; then
        EVIDENCE_ID="$1"; shift
      else
        die "Unknown argument: $1"
      fi
      ;;
  esac
done

[[ -z "$COMMAND" ]] && die "No command specified. Run sirm-evidence.sh --help" || true

# ── Helpers ─────────────────────────────────────────────────────────────────

resolve_session() {
  local sid="$1"
  local matches=()
  if [[ -d "${SESSION_DIR}" ]]; then
    for d in "${SESSION_DIR}"/*; do
      [[ -d "$d" ]] || continue
      local base
      base="$(basename "$d")"
      if [[ "$base" == "$sid"* ]]; then
        matches+=("$base")
      fi
    done
  fi
  case ${#matches[@]} in
    0) die "No session found matching '${sid}'" ;;
    1) SESSION_ID="${matches[0]}"; return 0 ;;
    *) die "Ambiguous session ID '${sid}' — matches: ${matches[*]}" ;;
  esac
}

session_json() {
  echo "${SESSION_DIR}/${SESSION_ID}/session.json"
}

audit_log() {
  local action="$1" detail="${2:-}"
  local ts operator audit_file
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local sjson
  sjson="$(session_json)"
  operator="$(jq -r '.operator' "$sjson" 2>/dev/null || echo 'unknown')"
  audit_file="${SESSION_DIR}/${SESSION_ID}/audit.log"
  printf '%s | %s | %s | %s\n' "$ts" "$operator" "$action" "$detail" >> "$audit_file"
}

check_sealed() {
  local sjson
  sjson="$(session_json)"
  local sealed
  sealed="$(jq -r '.sealed' "$sjson" 2>/dev/null || echo 'false')"
  if [[ "$sealed" == "true" ]]; then
    die "Session ${SESSION_ID} is SEALED — no modifications allowed"
  fi
}

compute_hash() {
  local file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

next_evidence_id() {
  local sjson
  sjson="$(session_json)"
  local count
  count="$(jq '.evidence | length' "$sjson")"
  printf 'EV-%03d' "$((count + 1))"
}

# ── Commands ────────────────────────────────────────────────────────────────

cmd_register() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  [[ -z "$FILE_PATH" ]] && die "file-path required for register" || true
  resolve_session "$SESSION_ID"
  check_sealed

  # Resolve to absolute path
  local abs_path
  abs_path="$(cd "$(dirname "$FILE_PATH")" && pwd)/$(basename "$FILE_PATH")"

  [[ -f "$abs_path" ]] || die "File not found: ${abs_path}"

  section "Evidence Registration"

  local sjson
  sjson="$(session_json)"
  local ev_id
  ev_id="$(next_evidence_id)"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local operator
  operator="$(jq -r '.operator' "$sjson")"

  log_info "Computing SHA-256 hash of ${abs_path}..."
  local hash
  hash="$(compute_hash "$abs_path")"

  local file_size
  if stat --version &>/dev/null 2>&1; then
    file_size="$(stat -c %s "$abs_path" 2>/dev/null)"
  else
    file_size="$(stat -f %z "$abs_path" 2>/dev/null)"
  fi

  local desc="${DESCRIPTION:-$(basename "$abs_path")}"

  # Add evidence to session JSON
  local tmp="${sjson}.tmp"
  jq --arg id "$ev_id" \
     --arg path "$abs_path" \
     --arg hash "$hash" \
     --arg desc "$desc" \
     --arg cls "$CLASSIFICATION" \
     --arg ts "$ts" \
     --arg op "$operator" \
     --arg size "$file_size" \
    '.evidence += [{
      "id": $id,
      "path": $path,
      "hash": $hash,
      "algorithm": "SHA-256",
      "description": $desc,
      "classification": $cls,
      "file_size": ($size | tonumber),
      "registered_at": $ts,
      "registered_by": $op,
      "chain_of_custody": [
        {"timestamp": $ts, "custodian": $op, "action": "REGISTERED", "detail": "Initial registration"}
      ]
    }] | .updated_at = $ts' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "EVIDENCE_REGISTERED" "${ev_id}: ${abs_path} SHA-256:${hash}"

  log_pass "Evidence registered: ${ev_id}"
  printf '  %-14s %s\n' "Evidence ID:" "$ev_id"
  printf '  %-14s %s\n' "File:" "$abs_path"
  printf '  %-14s %s\n' "SHA-256:" "$hash"
  printf '  %-14s %s\n' "Size:" "${file_size} bytes"
  printf '  %-14s %s\n' "Description:" "$desc"
  printf '  %-14s %s\n' "Classification:" "$CLASSIFICATION"
  printf '  %-14s %s\n' "Custodian:" "$operator"
}

cmd_verify() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"

  section "Evidence Verification"

  local pass_count=0 fail_count=0 missing_count=0
  local filter="."
  [[ -n "$EVIDENCE_ID" ]] && filter="select(.id == \"${EVIDENCE_ID}\")" || true

  local ev_ids ev_paths ev_hashes
  ev_ids=()
  ev_paths=()
  ev_hashes=()

  while IFS='|' read -r eid epath ehash; do
    ev_ids+=("$eid")
    ev_paths+=("$epath")
    ev_hashes+=("$ehash")
  done < <(jq -r ".evidence[] | ${filter} | [.id, .path, .hash] | join(\"|\")" "$sjson" 2>/dev/null)

  if [[ ${#ev_ids[@]} -eq 0 ]]; then
    if [[ -n "$EVIDENCE_ID" ]]; then
      die "Evidence ${EVIDENCE_ID} not found in session"
    fi
    printf '  No evidence registered in this session.\n'
    return 0
  fi

  for i in "${!ev_ids[@]}"; do
    local eid="${ev_ids[$i]}"
    local epath="${ev_paths[$i]}"
    local ehash="${ev_hashes[$i]}"

    if [[ ! -f "$epath" ]]; then
      log_fail "${eid}: FILE MISSING — ${epath}"
      missing_count=$((missing_count + 1))
      audit_log "EVIDENCE_VERIFY_MISSING" "${eid}: ${epath}"
      continue
    fi

    local current_hash
    current_hash="$(compute_hash "$epath")"

    if [[ "$current_hash" == "$ehash" ]]; then
      log_pass "${eid}: INTEGRITY VERIFIED — ${epath}"
      pass_count=$((pass_count + 1))
      audit_log "EVIDENCE_VERIFY_PASS" "${eid}: hash match confirmed"
    else
      log_fail "${eid}: INTEGRITY FAILURE — hash mismatch"
      printf '    Expected: %s\n' "$ehash"
      printf '    Actual:   %s\n' "$current_hash"
      fail_count=$((fail_count + 1))
      audit_log "EVIDENCE_VERIFY_FAIL" "${eid}: expected=${ehash} actual=${current_hash}"
    fi
  done

  printf '\n  Results: %s passed, %s failed, %s missing\n' \
    "$pass_count" "$fail_count" "$missing_count"

  if [[ $fail_count -gt 0 || $missing_count -gt 0 ]]; then return 1; fi
  return 0
}

cmd_transfer() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  [[ -z "$EVIDENCE_ID" ]] && die "evidence-id required for transfer" || true
  [[ -z "$TRANSFER_TO" ]] && die "--to required for transfer" || true
  [[ -z "$TRANSFER_REASON" ]] && die "--reason required for transfer" || true
  resolve_session "$SESSION_ID"
  check_sealed

  local sjson
  sjson="$(session_json)"

  # Verify evidence exists
  local exists
  exists="$(jq --arg id "$EVIDENCE_ID" '[.evidence[] | select(.id == $id)] | length' "$sjson")"
  [[ "$exists" -eq 0 ]] && die "Evidence ${EVIDENCE_ID} not found in session" || true

  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local operator
  operator="$(jq -r '.operator' "$sjson")"

  # Append custody record
  local tmp="${sjson}.tmp"
  jq --arg eid "$EVIDENCE_ID" \
     --arg to "$TRANSFER_TO" \
     --arg reason "$TRANSFER_REASON" \
     --arg ts "$ts" \
     --arg from "$operator" \
    '(.evidence[] | select(.id == $eid) | .chain_of_custody) += [{
      "timestamp": $ts,
      "custodian": $to,
      "action": "TRANSFERRED",
      "from": $from,
      "detail": $reason
    }] | .updated_at = $ts' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "EVIDENCE_TRANSFERRED" "${EVIDENCE_ID}: ${operator} -> ${TRANSFER_TO}, reason: ${TRANSFER_REASON}"

  section "Custody Transfer"
  log_pass "Transfer recorded: ${EVIDENCE_ID}"
  printf '  %-12s %s\n' "From:" "$operator"
  printf '  %-12s %s\n' "To:" "$TRANSFER_TO"
  printf '  %-12s %s\n' "Reason:" "$TRANSFER_REASON"
  printf '  %-12s %s\n' "Timestamp:" "$ts"
}

cmd_manifest() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"

  case "$MANIFEST_FORMAT" in
    json)
      jq '{
        session_id: .id,
        operator: .operator,
        classification: .classification,
        case_id: .case_id,
        generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        evidence_count: (.evidence | length),
        evidence: .evidence
      }' "$sjson"
      ;;
    text)
      local operator case_id classification
      operator="$(jq -r '.operator' "$sjson")"
      case_id="$(jq -r '.case_id // "N/A"' "$sjson")"
      classification="$(jq -r '.classification' "$sjson")"

      section "Evidence Manifest"
      printf '  Session:        %s\n' "$SESSION_ID"
      printf '  Operator:       %s\n' "$operator"
      printf '  Case ID:        %s\n' "$case_id"
      printf '  Classification: %s\n' "$classification"
      printf '  Generated:      %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf '\n'

      local ev_count
      ev_count="$(jq '.evidence | length' "$sjson")"

      if [[ "$ev_count" -eq 0 ]]; then
        printf '  No evidence registered.\n'
        return 0
      fi

      printf '  %-8s %-40s %-66s %s\n' "ID" "DESCRIPTION" "SHA-256" "CUSTODIAN"
      printf '  %s\n' "$(printf '%.0s─' {1..120})"

      jq -r '.evidence[] | [.id, .description, .hash, (.chain_of_custody[-1].custodian)] | @tsv' "$sjson" | \
      while IFS=$'\t' read -r eid edesc ehash ecust; do
        printf '  %-8s %-40s %-66s %s\n' "$eid" "${edesc:0:38}" "$ehash" "$ecust"
      done

      printf '\n'

      # Chain of custody details
      printf '  %s\n' "$(_bold '--- Chain of Custody ---')"
      jq -r '.evidence[] | "\n  Evidence: \(.id) — \(.description)\n" + (.chain_of_custody[] | "    \(.timestamp) | \(.custodian) | \(.action) | \(.detail)")' "$sjson"
      ;;
    *)
      die "Unknown format: ${MANIFEST_FORMAT}. Valid: json, text"
      ;;
  esac
}

cmd_list() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"

  section "Registered Evidence"

  local ev_count
  ev_count="$(jq '.evidence | length' "$sjson")"

  if [[ "$ev_count" -eq 0 ]]; then
    printf '  No evidence registered in this session.\n'
    return 0
  fi

  printf '  %-8s %-32s %-20s %-16s %s\n' "ID" "SHA-256" "REGISTERED" "CUSTODIAN" "DESCRIPTION"
  printf '  %s\n' "$(printf '%.0s─' {1..110})"

  jq -r '.evidence[] | [.id, .hash[0:30], .registered_at, (.chain_of_custody[-1].custodian), .description] | @tsv' "$sjson" | \
  while IFS=$'\t' read -r eid ehash ereg ecust edesc; do
    printf '  %-8s %-32s %-20s %-16s %s\n' "$eid" "${ehash}..." "$ereg" "$ecust" "${edesc:0:40}"
  done

  printf '\n  Total: %d evidence item(s)\n' "$ev_count"
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  case "$COMMAND" in
    register) cmd_register ;;
    verify)   cmd_verify ;;
    transfer) cmd_transfer ;;
    manifest) cmd_manifest ;;
    list)     cmd_list ;;
    *)        die "Unknown command: ${COMMAND}" ;;
  esac
}

main
