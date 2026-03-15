#!/usr/bin/env bash
# sirm-timeline — SIRM timeline builder
# Constructs forensic timelines with confidence classification.
# Usage: sirm-timeline.sh <command> <session-id> [OPTIONS]
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
EVENT_SOURCE=""
EVENT_TYPE=""
EVENT_DESC=""
EVENT_CONFIDENCE=""
EVENT_EVIDENCE_REF=""
EVENT_TIMESTAMP=""
GIT_SINCE=""
GIT_UNTIL=""
LOG_FILE=""
LOG_FORMAT=""
EXPORT_FORMAT="json"
FILTER_SINCE=""
FILTER_UNTIL=""
FILTER_TYPE=""
FILTER_CONFIDENCE=""

# ── Help ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'sirm-timeline') — SIRM timeline builder

$(_bold 'USAGE')
  sirm-timeline.sh <command> <session-id> [OPTIONS]

$(_bold 'COMMANDS')
  add        <session-id>   Add a timeline event
  import-git <session-id>   Import git log as timeline events
  import-log <session-id>   Import log file as timeline events
  export     <session-id>   Export timeline
  show       <session-id>   Display timeline with filters

$(_bold 'ADD OPTIONS')
  --source <text>           Event source (e.g., "operator", "system", "witness")
  --type <text>             Event type (e.g., "action", "observation", "artifact")
  --description <text>      Event description (required)
  --confidence <F|O|I|H>    Confidence: Fact, Observation, Inference, Hypothesis
  --evidence-ref <id>       Link to evidence ID (e.g., EV-001)
  --timestamp <iso>         Event timestamp (default: now)

$(_bold 'IMPORT-GIT OPTIONS')
  --since <date>            Start date for git log import
  --until <date>            End date for git log import

$(_bold 'IMPORT-LOG OPTIONS')
  <log-file>                Path to log file
  --format <fmt>            Log format: syslog, json, vault-audit

$(_bold 'EXPORT/SHOW OPTIONS')
  --format <fmt>            Export format: json, csv, markdown (default: json)
  --since <date>            Filter events after this date
  --until <date>            Filter events before this date
  --type <text>             Filter by event type
  --confidence <F|O|I|H>    Filter by confidence level

$(_bold 'COMMON OPTIONS')
  --session-dir <path>      Session directory (default: ./sessions/)
  --no-color                Disable colored output
  --verbose                 Show additional info
  -h, --help                Show this help

$(_bold 'CONFIDENCE LEVELS')
  F — Fact (verified, evidentiary weight)
  O — Observation (direct observation, evidentiary weight)
  I — Inference (derived, conditional weight)
  H — Hypothesis (unverified, no weight)

$(_bold 'EXAMPLES')
  sirm-timeline.sh add abc123 --source operator --type action \\
    --description "Initiated disk acquisition" --confidence F
  sirm-timeline.sh import-git abc123 --since "2024-01-01"
  sirm-timeline.sh import-log abc123 /var/log/auth.log --format syslog
  sirm-timeline.sh show abc123 --confidence F --type action
  sirm-timeline.sh export abc123 --format markdown
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
    --source)            EVENT_SOURCE="$2"; shift 2 ;;
    --type)              EVENT_TYPE="$2"; shift 2 ;;
    --description)       EVENT_DESC="$2"; shift 2 ;;
    --confidence)        EVENT_CONFIDENCE="$2"; shift 2 ;;
    --evidence-ref)      EVENT_EVIDENCE_REF="$2"; shift 2 ;;
    --timestamp)         EVENT_TIMESTAMP="$2"; shift 2 ;;
    --since)             GIT_SINCE="$2"; FILTER_SINCE="$2"; shift 2 ;;
    --until)             GIT_UNTIL="$2"; FILTER_UNTIL="$2"; shift 2 ;;
    --format)            LOG_FORMAT="$2"; EXPORT_FORMAT="$2"; shift 2 ;;
    add|import-git|import-log|export|show)
      COMMAND="$1"; shift
      if [[ $# -gt 0 && "$1" != -* ]]; then
        SESSION_ID="$1"; shift
      fi
      # For import-log, next positional is the log file
      if [[ "$COMMAND" == "import-log" && $# -gt 0 && "$1" != -* ]]; then
        LOG_FILE="$1"; shift
      fi
      ;;
    *)
      if [[ -z "$SESSION_ID" && "$1" != -* ]]; then
        SESSION_ID="$1"; shift
      elif [[ "$COMMAND" == "import-log" && -z "$LOG_FILE" && "$1" != -* ]]; then
        LOG_FILE="$1"; shift
      else
        die "Unknown argument: $1"
      fi
      ;;
  esac
done

[[ -z "$COMMAND" ]] && die "No command specified. Run sirm-timeline.sh --help" || true

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
  local ts audit_file
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  audit_file="${SESSION_DIR}/${SESSION_ID}/audit.log"
  local operator
  operator="$(jq -r '.operator' "$(session_json)" 2>/dev/null || echo 'unknown')"
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

validate_confidence() {
  case "${1:-}" in
    F|O|I|H) return 0 ;;
    *) die "Invalid confidence: ${1:-empty}. Must be F, O, I, or H" ;;
  esac
}

confidence_label() {
  case "$1" in
    F) echo "Fact" ;;
    O) echo "Observation" ;;
    I) echo "Inference" ;;
    H) echo "Hypothesis" ;;
    *) echo "$1" ;;
  esac
}

confidence_color() {
  case "$1" in
    F) _green "$1" ;;
    O) _blue "$1" ;;
    I) _yellow "$1" ;;
    H) _dim "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}

# ── Commands ────────────────────────────────────────────────────────────────

cmd_add() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  [[ -z "$EVENT_DESC" ]] && die "--description required for add" || true
  resolve_session "$SESSION_ID"
  check_sealed

  local ts="${EVENT_TIMESTAMP:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  local source="${EVENT_SOURCE:-operator}"
  local type="${EVENT_TYPE:-action}"
  local confidence="${EVENT_CONFIDENCE:-O}"
  validate_confidence "$confidence"

  local sjson
  sjson="$(session_json)"

  # Build evidence refs array
  local ev_refs="[]"
  if [[ -n "$EVENT_EVIDENCE_REF" ]]; then
    ev_refs="[\"${EVENT_EVIDENCE_REF}\"]"
  fi

  local tmp="${sjson}.tmp"
  jq --arg ts "$ts" \
     --arg src "$source" \
     --arg typ "$type" \
     --arg desc "$EVENT_DESC" \
     --arg conf "$confidence" \
     --argjson refs "$ev_refs" \
     --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '.timeline += [{
      "timestamp": $ts,
      "source": $src,
      "type": $typ,
      "description": $desc,
      "confidence": $conf,
      "evidence_refs": $refs
    }] | .timeline |= sort_by(.timestamp) | .updated_at = $now' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "TIMELINE_EVENT_ADDED" "${type}/${confidence}: ${EVENT_DESC}"

  log_pass "Timeline event added"
  printf '  %-14s %s\n' "Timestamp:" "$ts"
  printf '  %-14s %s\n' "Source:" "$source"
  printf '  %-14s %s\n' "Type:" "$type"
  printf '  %-14s %s (%s)\n' "Confidence:" "$(confidence_color "$confidence")" "$(confidence_label "$confidence")"
  printf '  %-14s %s\n' "Description:" "$EVENT_DESC"
}

cmd_import_git() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  resolve_session "$SESSION_ID"
  check_sealed

  section "Git Log Import"

  local git_args=("log" "--format=%aI|%H|%an|%s" "--no-merges")
  [[ -n "$GIT_SINCE" ]] && git_args+=("--since=$GIT_SINCE") || true
  [[ -n "$GIT_UNTIL" ]] && git_args+=("--until=$GIT_UNTIL") || true

  local count=0
  local sjson
  sjson="$(session_json)"

  while IFS='|' read -r ts hash author subject; do
    [[ -z "$ts" ]] && continue || true

    local tmp="${sjson}.tmp"
    jq --arg ts "$ts" \
       --arg hash "$hash" \
       --arg author "$author" \
       --arg subject "$subject" \
       --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '.timeline += [{
        "timestamp": $ts,
        "source": ("git:" + $author),
        "type": "commit",
        "description": ($hash[0:7] + " " + $subject),
        "confidence": "F",
        "evidence_refs": []
      }] | .updated_at = $now' "$sjson" > "$tmp"
    mv "$tmp" "$sjson"
    count=$((count + 1))
  done < <(git "${git_args[@]}" 2>/dev/null || true)

  # Sort timeline
  local tmp="${sjson}.tmp"
  jq '.timeline |= sort_by(.timestamp)' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "TIMELINE_GIT_IMPORT" "${count} commits imported"
  log_pass "${count} git commits imported as timeline events (confidence: F)"
}

cmd_import_log() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  [[ -z "$LOG_FILE" ]] && die "log-file required for import-log" || true
  [[ -z "$LOG_FORMAT" ]] && die "--format required for import-log" || true
  [[ -f "$LOG_FILE" ]] || die "Log file not found: ${LOG_FILE}"
  resolve_session "$SESSION_ID"
  check_sealed

  section "Log Import (${LOG_FORMAT})"

  local sjson count=0
  sjson="$(session_json)"

  case "$LOG_FORMAT" in
    syslog)
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue || true
        # Parse syslog: "Mon DD HH:MM:SS hostname process: message"
        local ts_raw host msg
        ts_raw="$(echo "$line" | awk '{print $1, $2, $3}')"
        host="$(echo "$line" | awk '{print $4}')"
        msg="$(echo "$line" | cut -d: -f4- | sed 's/^ //')"
        [[ -z "$msg" ]] && msg="$(echo "$line" | cut -d' ' -f6-)" || true

        # Best-effort timestamp conversion
        local ts
        ts="$(date -u -j -f "%b %d %H:%M:%S" "$ts_raw" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
              date -u -d "$ts_raw" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
              date -u +%Y-%m-%dT%H:%M:%SZ)"

        local tmp="${sjson}.tmp"
        jq --arg ts "$ts" \
           --arg src "syslog:${host}" \
           --arg msg "$msg" \
          '.timeline += [{
            "timestamp": $ts,
            "source": $src,
            "type": "log_entry",
            "description": $msg,
            "confidence": "F",
            "evidence_refs": []
          }]' "$sjson" > "$tmp"
        mv "$tmp" "$sjson"
        count=$((count + 1))
      done < "$LOG_FILE"
      ;;

    json)
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue || true
        local ts msg src
        ts="$(echo "$line" | jq -r '.timestamp // .time // .@timestamp // empty' 2>/dev/null || echo "")"
        msg="$(echo "$line" | jq -r '.message // .msg // .log // empty' 2>/dev/null || echo "")"
        src="$(echo "$line" | jq -r '.source // .logger // .service // "json"' 2>/dev/null || echo "json")"

        [[ -z "$ts" ]] && ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        [[ -z "$msg" ]] && msg="$line" || true

        local tmp="${sjson}.tmp"
        jq --arg ts "$ts" --arg src "$src" --arg msg "$msg" \
          '.timeline += [{
            "timestamp": $ts,
            "source": $src,
            "type": "log_entry",
            "description": $msg,
            "confidence": "F",
            "evidence_refs": []
          }]' "$sjson" > "$tmp"
        mv "$tmp" "$sjson"
        count=$((count + 1))
      done < "$LOG_FILE"
      ;;

    vault-audit)
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue || true
        local ts op path auth_entity
        ts="$(echo "$line" | jq -r '.time // empty' 2>/dev/null || echo "")"
        op="$(echo "$line" | jq -r '.request.operation // "unknown"' 2>/dev/null)"
        path="$(echo "$line" | jq -r '.request.path // "unknown"' 2>/dev/null)"
        auth_entity="$(echo "$line" | jq -r '.auth.display_name // "unknown"' 2>/dev/null)"

        [[ -z "$ts" ]] && ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

        local tmp="${sjson}.tmp"
        jq --arg ts "$ts" \
           --arg op "$op" \
           --arg path "$path" \
           --arg entity "$auth_entity" \
          '.timeline += [{
            "timestamp": $ts,
            "source": ("vault:" + $entity),
            "type": "vault_audit",
            "description": ($op + " " + $path),
            "confidence": "F",
            "evidence_refs": []
          }]' "$sjson" > "$tmp"
        mv "$tmp" "$sjson"
        count=$((count + 1))
      done < "$LOG_FILE"
      ;;

    *)
      die "Unknown log format: ${LOG_FORMAT}. Valid: syslog, json, vault-audit"
      ;;
  esac

  # Sort timeline
  local tmp="${sjson}.tmp"
  jq '.timeline |= sort_by(.timestamp)' "$sjson" > "$tmp"
  mv "$tmp" "$sjson"

  audit_log "TIMELINE_LOG_IMPORT" "${LOG_FORMAT}: ${count} entries from ${LOG_FILE}"
  log_pass "${count} log entries imported from ${LOG_FILE} (format: ${LOG_FORMAT})"
}

cmd_export() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"

  # Build jq filter for optional filtering
  local jq_filter=".timeline"
  [[ -n "$FILTER_SINCE" ]] && jq_filter+=" | map(select(.timestamp >= \"${FILTER_SINCE}\"))"
  [[ -n "$FILTER_UNTIL" ]] && jq_filter+=" | map(select(.timestamp <= \"${FILTER_UNTIL}\"))"
  [[ -n "$FILTER_TYPE" ]] && jq_filter+=" | map(select(.type == \"${FILTER_TYPE}\"))"
  [[ -n "$FILTER_CONFIDENCE" ]] && jq_filter+=" | map(select(.confidence == \"${FILTER_CONFIDENCE}\"))"

  case "$EXPORT_FORMAT" in
    json)
      jq "${jq_filter}" "$sjson"
      ;;
    csv)
      printf 'timestamp,source,type,description,confidence,evidence_refs\n'
      jq -r "${jq_filter} | .[] | [.timestamp, .source, .type, .description, .confidence, (.evidence_refs | join(\";\"))] | @csv" "$sjson"
      ;;
    markdown)
      local tl_count
      tl_count="$(jq "${jq_filter} | length" "$sjson")"
      printf '# Timeline — Session %s\n\n' "$SESSION_ID"
      printf 'Generated: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf '| Timestamp | Source | Type | Confidence | Description |\n'
      printf '|-----------|--------|------|------------|-------------|\n'
      jq -r "${jq_filter} | .[] | \"| \(.timestamp) | \(.source) | \(.type) | \(.confidence) | \(.description) |\"" "$sjson"
      printf '\n*%s events*\n' "$tl_count"
      ;;
    *)
      die "Unknown format: ${EXPORT_FORMAT}. Valid: json, csv, markdown"
      ;;
  esac
}

cmd_show() {
  [[ -z "$SESSION_ID" ]] && die "session-id required" || true
  resolve_session "$SESSION_ID"

  local sjson
  sjson="$(session_json)"

  section "Timeline — ${SESSION_ID}"

  # Build jq filter
  local jq_filter=".timeline"
  [[ -n "$FILTER_SINCE" ]] && jq_filter+=" | map(select(.timestamp >= \"${FILTER_SINCE}\"))"
  [[ -n "$FILTER_UNTIL" ]] && jq_filter+=" | map(select(.timestamp <= \"${FILTER_UNTIL}\"))"
  [[ -n "$FILTER_TYPE" ]] && jq_filter+=" | map(select(.type == \"${FILTER_TYPE}\"))"
  [[ -n "$FILTER_CONFIDENCE" ]] && jq_filter+=" | map(select(.confidence == \"${FILTER_CONFIDENCE}\"))"

  local tl_count
  tl_count="$(jq "${jq_filter} | length" "$sjson")"

  if [[ "$tl_count" -eq 0 ]]; then
    printf '  No timeline events match the filter.\n'
    return 0
  fi

  printf '  %-22s %-4s %-14s %-16s %s\n' "TIMESTAMP" "CONF" "TYPE" "SOURCE" "DESCRIPTION"
  printf '  %s\n' "$(printf '%.0s─' {1..110})"

  jq -r "${jq_filter} | .[] | [.timestamp, .confidence, .type, .source, .description] | @tsv" "$sjson" | \
  while IFS=$'\t' read -r ts conf typ src desc; do
    local conf_display
    conf_display="$(confidence_color "$conf")"
    printf '  %-22s %-4s %-14s %-16s %s\n' "$ts" "$conf_display" "$typ" "${src:0:14}" "${desc:0:60}"
  done

  printf '\n  %d event(s) displayed\n' "$tl_count"
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  case "$COMMAND" in
    add)        cmd_add ;;
    import-git) cmd_import_git ;;
    import-log) cmd_import_log ;;
    export)     cmd_export ;;
    show)       cmd_show ;;
    *)          die "Unknown command: ${COMMAND}" ;;
  esac
}

main
