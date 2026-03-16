#!/usr/bin/env bash
# sirm-session — SIRM session lifecycle management
# Manages session state transitions with full audit trail.
# Usage: sirm-session.sh <command> [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export REPO_ROOT

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
REASON=""
FINDINGS=""
EXPORT_FORMAT="json"

# ── Help ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'sirm-session') — SIRM session lifecycle management

$(_bold 'USAGE')
  sirm-session.sh <command> [session-id] [OPTIONS]

$(_bold 'COMMANDS')
  status  <session-id>                 Show session state and summary
  suspend <session-id> --reason <r>    Suspend an active session
  resume  <session-id>                 Resume a suspended session
  close   <session-id> --findings <f>  Close session with findings
  seal    <session-id>                 Seal session (irreversible)
  list                                 List all sessions
  export  <session-id> --format <fmt>  Export session record

$(_bold 'OPTIONS')
  --session-dir <path>   Session directory (default: ./sessions/)
  --reason <text>        Reason for suspend
  --findings <text>      Findings summary for close
  --format <fmt>         Export format: json, markdown, csv (default: json)
  --no-color             Disable colored output
  --verbose              Show additional info
  -h, --help             Show this help

$(_bold 'STATE MACHINE')
  INITIALIZING -> ACTIVE -> SUSPENDED <-> ACTIVE -> CLOSED -> SEALED

$(_bold 'EXAMPLES')
  sirm-session.sh status abc123-def456
  sirm-session.sh suspend abc123 --reason "Awaiting lab results"
  sirm-session.sh seal abc123
  sirm-session.sh list
  sirm-session.sh export abc123 --format markdown
EOF
  exit 0
}

# ── Argument parsing ────────────────────────────────────────────────────────

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage ;;
    --no-color)      NO_COLOR=1; shift ;;
    --verbose)       VERBOSE=1; shift ;;
    --session-dir)   SESSION_DIR="$2"; shift 2 ;;
    --reason)        REASON="$2"; shift 2 ;;
    --findings)      FINDINGS="$2"; shift 2 ;;
    --format)        EXPORT_FORMAT="$2"; shift 2 ;;
    status|suspend|resume|close|seal|list|export)
      COMMAND="$1"; shift
      # Next arg is session-id if present and not a flag
      if [[ $# -gt 0 && "$1" != -* && "$COMMAND" != "list" ]]; then
        SESSION_ID="$1"; shift
      fi
      ;;
    *)
      # Could be a session-id positional
      if [[ -z "$SESSION_ID" && "$1" != -* ]]; then
        SESSION_ID="$1"; shift
      else
        die "Unknown argument: $1"
      fi
      ;;
  esac
done

[[ -z "$COMMAND" ]] && die "No command specified. Run sirm-session.sh --help" || true

# ── Helpers ─────────────────────────────────────────────────────────────────

resolve_session() {
  local sid="$1"
  # Support partial UUID match
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

get_state() {
  jq -r '.state' "$(session_json)"
}

set_state() {
  local new_state="$1"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local sjson
  sjson="$(session_json)"
  local tmp="${sjson}.tmp"
  jq --arg s "$new_state" --arg t "$ts" '.state = $s | .updated_at = $t' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"
}

validate_transition() {
  local current="$1" target="$2"
  case "${current}:${target}" in
    ACTIVE:SUSPENDED)   return 0 ;;
    SUSPENDED:ACTIVE)   return 0 ;;
    ACTIVE:CLOSED)      return 0 ;;
    CLOSED:SEALED)      return 0 ;;
    *) die "Invalid state transition: ${current} -> ${target}" ;;
  esac
}

# ── Commands ────────────────────────────────────────────────────────────────

cmd_status() {
  [[ -z "$SESSION_ID" ]] && die "session-id required for status" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"
  [[ -f "$sjson" ]] || die "Session file not found: $sjson"

  local state operator classification case_id created_at updated_at
  state="$(jq -r '.state' "$sjson")"
  operator="$(jq -r '.operator' "$sjson")"
  classification="$(jq -r '.classification' "$sjson")"
  case_id="$(jq -r '.case_id // "none"' "$sjson")"
  created_at="$(jq -r '.created_at' "$sjson")"
  updated_at="$(jq -r '.updated_at' "$sjson")"

  local evidence_count timeline_count
  evidence_count="$(jq '.evidence | length' "$sjson")"
  timeline_count="$(jq '.timeline | length' "$sjson")"
  local sealed
  sealed="$(jq -r '.sealed' "$sjson")"

  # Compute duration
  local created_epoch now_epoch duration_human
  if date -j -f "%Y-%m-%dT%H:%M:%SZ" "$created_at" +%s &>/dev/null 2>&1; then
    created_epoch="$(TZ=UTC date -j -f "%Y-%m-%dT%H:%M:%SZ" "$created_at" +%s 2>/dev/null)"
  else
    created_epoch="$(date -d "$created_at" +%s 2>/dev/null || echo 0)"
  fi
  now_epoch="$(date -u +%s)"
  local elapsed=$(( now_epoch - created_epoch ))
  if [[ $elapsed -gt 86400 ]]; then
    duration_human="$((elapsed / 86400))d $((elapsed % 86400 / 3600))h"
  elif [[ $elapsed -gt 3600 ]]; then
    duration_human="$((elapsed / 3600))h $((elapsed % 3600 / 60))m"
  else
    duration_human="$((elapsed / 60))m"
  fi

  local state_color
  case "$state" in
    ACTIVE)     state_color="$(_green "$state")" ;;
    SUSPENDED)  state_color="$(_yellow "$state")" ;;
    CLOSED)     state_color="$(_blue "$state")" ;;
    SEALED)     state_color="$(_dim "$state")" ;;
    *)          state_color="$state" ;;
  esac

  section "Session Status"
  printf '  %-16s %s\n' "Session ID:" "$SESSION_ID"
  printf '  %-16s %s\n' "State:" "$state_color"
  printf '  %-16s %s\n' "Operator:" "$operator"
  printf '  %-16s %s\n' "Classification:" "$classification"
  printf '  %-16s %s\n' "Case ID:" "$case_id"
  printf '  %-16s %s\n' "Created:" "$created_at"
  printf '  %-16s %s\n' "Updated:" "$updated_at"
  printf '  %-16s %s\n' "Duration:" "$duration_human"
  printf '  %-16s %s\n' "Evidence:" "${evidence_count} items"
  printf '  %-16s %s\n' "Timeline:" "${timeline_count} events"
  printf '  %-16s %s\n' "Sealed:" "$sealed"
}

cmd_suspend() {
  [[ -z "$SESSION_ID" ]] && die "session-id required for suspend" || true
  [[ -z "$REASON" ]] && die "--reason required for suspend" || true
  resolve_session "$SESSION_ID"

  local current
  current="$(get_state)"
  validate_transition "$current" "SUSPENDED"

  set_state "SUSPENDED"
  audit_log "SESSION_SUSPENDED" "Reason: ${REASON}"

  log_pass "Session ${SESSION_ID} suspended"
  printf '  Reason: %s\n' "$REASON"
}

cmd_resume() {
  [[ -z "$SESSION_ID" ]] && die "session-id required for resume" || true
  resolve_session "$SESSION_ID"

  local current
  current="$(get_state)"
  validate_transition "$current" "ACTIVE"

  set_state "ACTIVE"
  audit_log "SESSION_RESUMED" "Resumed from SUSPENDED"

  log_pass "Session ${SESSION_ID} resumed — state: ACTIVE"
}

cmd_close() {
  [[ -z "$SESSION_ID" ]] && die "session-id required for close" || true
  resolve_session "$SESSION_ID"

  local current
  current="$(get_state)"
  validate_transition "$current" "CLOSED"

  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local sjson
  sjson="$(session_json)"
  local tmp="${sjson}.tmp"
  jq --arg s "CLOSED" --arg t "$ts" --arg f "${FINDINGS:-No findings provided}" \
    '.state = $s | .updated_at = $t | .findings = $f' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "SESSION_CLOSED" "Findings: ${FINDINGS:-none}"

  log_pass "Session ${SESSION_ID} closed"
  [[ -n "$FINDINGS" ]] && printf '  Findings: %s\n' "$FINDINGS" || true
}

cmd_seal() {
  [[ -z "$SESSION_ID" ]] && die "session-id required for seal" || true
  resolve_session "$SESSION_ID"

  local current
  current="$(get_state)"
  validate_transition "$current" "SEALED"

  local sjson
  sjson="$(session_json)"

  # Compute SHA-256 of the session file before sealing
  local hash
  if command -v sha256sum &>/dev/null; then
    hash="$(sha256sum "$sjson" | awk '{print $1}')"
  else
    hash="$(shasum -a 256 "$sjson" | awk '{print $1}')"
  fi

  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local tmp="${sjson}.tmp"
  jq --arg s "SEALED" --arg t "$ts" --arg h "$hash" \
    '.state = $s | .updated_at = $t | .sealed = true | .seal_hash = $h' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "SESSION_SEALED" "SHA-256: ${hash}"

  log_pass "Session ${SESSION_ID} SEALED"
  printf '  SHA-256: %s\n' "$hash"
  printf '  %s\n' "$(_yellow 'This action is irreversible. Session is now read-only.')"
}

cmd_list() {
  section "SIRM Sessions"

  if [[ ! -d "$SESSION_DIR" ]]; then
    printf '  No sessions directory found.\n'
    return 0
  fi

  local count=0
  printf '  %-38s %-12s %-16s %-8s %s\n' "SESSION ID" "STATE" "OPERATOR" "EVIDENCE" "CREATED"
  printf '  %s\n' "$(printf '%.0s─' {1..100})"

  for d in "${SESSION_DIR}"/*/; do
    [[ -d "$d" ]] || continue
    local sjson="${d}session.json"
    [[ -f "$sjson" ]] || continue

    local sid state operator created_at ev_count
    sid="$(basename "$d")"
    state="$(jq -r '.state' "$sjson" 2>/dev/null || echo '?')"
    operator="$(jq -r '.operator' "$sjson" 2>/dev/null || echo '?')"
    created_at="$(jq -r '.created_at' "$sjson" 2>/dev/null || echo '?')"
    ev_count="$(jq '.evidence | length' "$sjson" 2>/dev/null || echo '0')"

    local state_display
    case "$state" in
      ACTIVE)    state_display="$(_green "$state")" ;;
      SUSPENDED) state_display="$(_yellow "$state")" ;;
      CLOSED)    state_display="$(_blue "$state")" ;;
      SEALED)    state_display="$(_dim "$state")" ;;
      *)         state_display="$state" ;;
    esac

    printf '  %-38s %-12s %-16s %-8s %s\n' \
      "$sid" "$state_display" "$operator" "$ev_count" "$created_at"
    count=$((count + 1))
  done

  printf '\n  Total: %d session(s)\n' "$count"
}

cmd_export() {
  [[ -z "$SESSION_ID" ]] && die "session-id required for export" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"
  [[ -f "$sjson" ]] || die "Session file not found: $sjson"

  case "$EXPORT_FORMAT" in
    json)
      jq '.' "$sjson"
      ;;
    markdown)
      local state operator classification case_id created_at
      state="$(jq -r '.state' "$sjson")"
      operator="$(jq -r '.operator' "$sjson")"
      classification="$(jq -r '.classification' "$sjson")"
      case_id="$(jq -r '.case_id // "N/A"' "$sjson")"
      created_at="$(jq -r '.created_at' "$sjson")"

      printf '# SIRM Session Report\n\n'
      printf '| Field | Value |\n|-------|-------|\n'
      printf '| Session ID | `%s` |\n' "$SESSION_ID"
      printf '| State | %s |\n' "$state"
      printf '| Operator | %s |\n' "$operator"
      printf '| Classification | %s |\n' "$classification"
      printf '| Case ID | %s |\n' "$case_id"
      printf '| Created | %s |\n\n' "$created_at"

      local ev_count
      ev_count="$(jq '.evidence | length' "$sjson")"
      if [[ $ev_count -gt 0 ]]; then
        printf '## Evidence (%s items)\n\n' "$ev_count"
        printf '| ID | Description | SHA-256 | Registered |\n|----|----|-------|----|\n'
        jq -r '.evidence[] | "| \(.id) | \(.description) | `\(.hash[0:16])...` | \(.registered_at) |"' "$sjson"
        printf '\n'
      fi

      local tl_count
      tl_count="$(jq '.timeline | length' "$sjson")"
      if [[ $tl_count -gt 0 ]]; then
        printf '## Timeline (%s events)\n\n' "$tl_count"
        printf '| Timestamp | Source | Type | Confidence | Description |\n|-----------|--------|------|------------|-------------|\n'
        jq -r '.timeline[] | "| \(.timestamp) | \(.source) | \(.type) | \(.confidence) | \(.description) |"' "$sjson"
        printf '\n'
      fi

      if jq -e '.findings' "$sjson" &>/dev/null; then
        printf '## Findings\n\n%s\n\n' "$(jq -r '.findings' "$sjson")"
      fi

      local sealed
      sealed="$(jq -r '.sealed' "$sjson")"
      if [[ "$sealed" == "true" ]]; then
        printf '## Seal\n\nSHA-256: `%s`\n' "$(jq -r '.seal_hash' "$sjson")"
      fi
      ;;
    csv)
      printf 'id,operator,state,classification,case_id,created_at,evidence_count,timeline_count,sealed\n'
      jq -r '[.id, .operator, .state, .classification, .case_id, .created_at, (.evidence|length|tostring), (.timeline|length|tostring), (.sealed|tostring)] | join(",")' "$sjson"
      ;;
    *)
      die "Unknown format: ${EXPORT_FORMAT}. Valid: json, markdown, csv"
      ;;
  esac
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  case "$COMMAND" in
    status)  cmd_status ;;
    suspend) cmd_suspend ;;
    resume)  cmd_resume ;;
    close)   cmd_close ;;
    seal)    cmd_seal ;;
    list)    cmd_list ;;
    export)  cmd_export ;;
    *)       die "Unknown command: ${COMMAND}" ;;
  esac
}

main
