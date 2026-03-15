#!/usr/bin/env bash
# sirm-bootstrap — SIRM session bootstrap protocol
# Initializes a forensic session with full chain of custody from first keystroke.
# Usage: sirm-bootstrap.sh --operator <name> [OPTIONS]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="1.0.0"

# ── Color & output ──────────────────────────────────────────────────────────

NO_COLOR="${NO_COLOR:-}"
VERBOSE="${VERBOSE:-}"
JSON_OUTPUT="${JSON_OUTPUT:-}"
MINIMAL="${MINIMAL:-}"
DRY_RUN="${DRY_RUN:-}"

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
log_skip() { printf '  %s %s\n' "$(_dim '— SKIP')" "$1"; }

section() { printf '\n%s\n' "$(_bold "═══ $1 ═══")"; }

# ── Globals ─────────────────────────────────────────────────────────────────

OPERATOR=""
CLASSIFICATION="INTERNAL"
CASE_ID=""
SESSION_DIR="./sessions"
SESSION_ID=""
SESSION_PATH=""
AUDIT_LOG=""
PHASE_RESULTS=()
TOOL_STATUS=()
FAIL_COUNT=0
WARN_COUNT=0

# ── Help ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'sirm-bootstrap') — SIRM session bootstrap protocol v${VERSION}

$(_bold 'USAGE')
  sirm-bootstrap.sh --operator <name> [OPTIONS]

$(_bold 'REQUIRED')
  --operator <name>         Operator name for chain of custody

$(_bold 'OPTIONS')
  --classification <level>  Classification level (default: INTERNAL)
  --case-id <id>            Case identifier for the session
  --session-dir <path>      Session storage directory (default: ./sessions/)
  --minimal                 Minimal output — skip dashboard
  --json                    Output session JSON to stdout
  --verbose                 Show additional diagnostic info
  --dry-run                 Validate environment without creating session
  --no-color                Disable colored output
  -h, --help                Show this help

$(_bold 'CLASSIFICATION LEVELS')
  PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, COURT-SEALED

$(_bold 'EXIT CODES')
  0   Session bootstrapped successfully
  1   Critical tool missing or bootstrap failure
  2   Usage error

$(_bold 'EXAMPLES')
  sirm-bootstrap.sh --operator "D. Brush" --case-id "2024-CV-1234"
  sirm-bootstrap.sh --operator "D. Brush" --classification RESTRICTED --verbose
  sirm-bootstrap.sh --operator "D. Brush" --dry-run
EOF
  exit 0
}

# ── Argument parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)           usage ;;
    --operator)          OPERATOR="$2"; shift 2 ;;
    --classification)    CLASSIFICATION="$2"; shift 2 ;;
    --case-id)           CASE_ID="$2"; shift 2 ;;
    --session-dir)       SESSION_DIR="$2"; shift 2 ;;
    --minimal)           MINIMAL=1; shift ;;
    --json)              JSON_OUTPUT=1; shift ;;
    --verbose)           VERBOSE=1; shift ;;
    --dry-run)           DRY_RUN=1; shift ;;
    --no-color)          NO_COLOR=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run sirm-bootstrap.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

if [[ -z "$OPERATOR" ]]; then
  printf 'Error: --operator is required\n' >&2
  printf 'Run sirm-bootstrap.sh --help for usage.\n' >&2
  exit 2
fi

# Validate classification
case "$CLASSIFICATION" in
  PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED|COURT-SEALED) ;;
  *)
    printf 'Error: invalid classification: %s\n' "$CLASSIFICATION" >&2
    printf 'Valid: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, COURT-SEALED\n' >&2
    exit 2
    ;;
esac

# ── Audit logging ───────────────────────────────────────────────────────────

audit_log() {
  local action="$1"
  local detail="${2:-}"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} | ${OPERATOR} | ${action} | ${detail}"
  if [[ -n "$AUDIT_LOG" && -z "$DRY_RUN" ]]; then
    printf '%s\n' "$entry" >> "$AUDIT_LOG"
  fi
  log_info "AUDIT: ${entry}"
}

phase_record() {
  local phase="$1" status="$2" detail="${3:-}"
  PHASE_RESULTS+=("{\"phase\":\"${phase}\",\"status\":\"${status}\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"detail\":\"${detail}\"}")
}

# ── Phase 1: Tool Validation ───────────────────────────────────────────────

phase1_tool_validation() {
  section "Phase 1: Tool Validation"

  local critical_tools=("git" "openssl" "jq")
  local optional_tools=("vault" "sops" "age" "age-keygen" "uuidgen" "sha256sum" "shasum")
  local critical_missing=0

  for tool in "${critical_tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
      local ver
      case "$tool" in
        git)     ver="$(git --version 2>/dev/null | head -1)" ;;
        openssl) ver="$(openssl version 2>/dev/null | head -1)" ;;
        jq)      ver="$(jq --version 2>/dev/null | head -1)" ;;
        *)       ver="present" ;;
      esac
      log_pass "${tool} — ${ver}"
      TOOL_STATUS+=("{\"tool\":\"${tool}\",\"status\":\"present\",\"critical\":true,\"version\":\"${ver}\"}")
    else
      log_fail "${tool} — MISSING (critical)"
      TOOL_STATUS+=("{\"tool\":\"${tool}\",\"status\":\"missing\",\"critical\":true}")
      critical_missing=$((critical_missing + 1))
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  done

  for tool in "${optional_tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
      log_pass "${tool} — available"
      TOOL_STATUS+=("{\"tool\":\"${tool}\",\"status\":\"present\",\"critical\":false}")
    else
      log_warn "${tool} — not found (optional)"
      TOOL_STATUS+=("{\"tool\":\"${tool}\",\"status\":\"missing\",\"critical\":false}")
      WARN_COUNT=$((WARN_COUNT + 1))
    fi
  done

  if [[ $critical_missing -gt 0 ]]; then
    phase_record "tool_validation" "FAIL" "${critical_missing} critical tool(s) missing"
    log_fail "Phase 1 FAILED — ${critical_missing} critical tool(s) missing"
    return 1
  fi

  phase_record "tool_validation" "PASS" "All critical tools present"
  log_pass "Phase 1 complete — all critical tools present"
  return 0
}

# ── Phase 2: Operator Identity ─────────────────────────────────────────────

IDENT_GIT_USER=""
IDENT_GIT_EMAIL=""
IDENT_HOSTNAME=""
IDENT_VAULT_ENTITY=""

phase2_operator_identity() {
  section "Phase 2: Operator Identity"

  IDENT_GIT_USER="$(git config user.name 2>/dev/null || echo 'unknown')"
  IDENT_GIT_EMAIL="$(git config user.email 2>/dev/null || echo 'unknown')"
  IDENT_HOSTNAME="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo 'unknown')"

  log_pass "Operator: ${OPERATOR}"
  log_pass "Git identity: ${IDENT_GIT_USER} <${IDENT_GIT_EMAIL}>"
  log_pass "Hostname: ${IDENT_HOSTNAME}"

  if command -v vault &>/dev/null && [[ -n "${VAULT_ADDR:-}" ]]; then
    if IDENT_VAULT_ENTITY="$(vault token lookup -format=json 2>/dev/null | jq -r '.data.display_name // "unknown"' 2>/dev/null)"; then
      log_pass "Vault identity: ${IDENT_VAULT_ENTITY}"
    else
      log_warn "Vault token lookup failed — proceeding without Vault identity"
      IDENT_VAULT_ENTITY="unavailable"
      WARN_COUNT=$((WARN_COUNT + 1))
    fi
  else
    log_info "Vault not configured — skipping identity lookup"
    IDENT_VAULT_ENTITY="not-configured"
  fi

  phase_record "operator_identity" "PASS" "Operator: ${OPERATOR}, Git: ${IDENT_GIT_USER}"
  log_pass "Phase 2 complete — operator identity confirmed"
}

# ── Phase 3: Environment Context ───────────────────────────────────────────

CTX_GIT_BRANCH=""
CTX_GIT_STATUS=""
CTX_GIT_LOG=""
CTX_VAULT_HEALTH=""
CTX_SOPS_CONFIG=""
CTX_CERT_COUNT=0

phase3_environment_context() {
  section "Phase 3: Environment Context"

  # Git context
  if git rev-parse --is-inside-work-tree &>/dev/null; then
    CTX_GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'detached')"
    CTX_GIT_STATUS="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    CTX_GIT_LOG="$(git log --oneline -5 2>/dev/null || echo 'no commits')"
    log_pass "Git branch: ${CTX_GIT_BRANCH} (${CTX_GIT_STATUS} uncommitted changes)"
    log_info "Recent commits:\n${CTX_GIT_LOG}"
  else
    log_warn "Not in a git repository"
    WARN_COUNT=$((WARN_COUNT + 1))
  fi

  # Vault health
  if command -v vault &>/dev/null && [[ -n "${VAULT_ADDR:-}" ]]; then
    if vault status -format=json &>/dev/null; then
      local sealed
      sealed="$(vault status -format=json 2>/dev/null | jq -r '.sealed' 2>/dev/null)"
      if [[ "$sealed" == "false" ]]; then
        CTX_VAULT_HEALTH="unsealed"
        log_pass "Vault: ${VAULT_ADDR} — unsealed"
      else
        CTX_VAULT_HEALTH="sealed"
        log_warn "Vault: ${VAULT_ADDR} — sealed"
        WARN_COUNT=$((WARN_COUNT + 1))
      fi
    else
      CTX_VAULT_HEALTH="unreachable"
      log_warn "Vault: ${VAULT_ADDR} — unreachable"
      WARN_COUNT=$((WARN_COUNT + 1))
    fi
  else
    CTX_VAULT_HEALTH="not-configured"
    log_info "Vault not configured"
  fi

  # SOPS config
  if [[ -f "${REPO_ROOT}/.sops.yaml" ]]; then
    CTX_SOPS_CONFIG="present"
    local rule_count
    rule_count="$(grep -c 'path_regex\|creation_rules' "${REPO_ROOT}/.sops.yaml" 2>/dev/null || echo '0')"
    log_pass "SOPS config: .sops.yaml (${rule_count} rules)"
  else
    CTX_SOPS_CONFIG="absent"
    log_info "No .sops.yaml found"
  fi

  # Active cert count
  CTX_CERT_COUNT="$(find "${REPO_ROOT}" \( -name '*.crt' -o -name '*.pem' \) -not -path '*/.git/*' 2>/dev/null | wc -l | tr -d ' ')"
  log_pass "Certificate files found: ${CTX_CERT_COUNT}"

  phase_record "environment_context" "PASS" "Branch: ${CTX_GIT_BRANCH}, Vault: ${CTX_VAULT_HEALTH}"
  log_pass "Phase 3 complete — environment context captured"
}

# ── Phase 4: Session Creation ──────────────────────────────────────────────

phase4_session_creation() {
  section "Phase 4: Session Creation"

  if [[ -n "$DRY_RUN" ]]; then
    log_info "DRY RUN — skipping session creation"
    SESSION_ID="dry-run-$(date +%s)"
    phase_record "session_creation" "SKIP" "Dry run mode"
    log_pass "Phase 4 skipped — dry run mode"
    return 0
  fi

  # Generate session UUID
  if command -v uuidgen &>/dev/null; then
    SESSION_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  else
    SESSION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16 | sed 's/\(.\{8\}\)\(.\{4\}\)\(.\{4\}\)\(.\{4\}\)\(.\{12\}\)/\1-\2-\3-\4-\5/')"
  fi

  SESSION_PATH="${SESSION_DIR}/${SESSION_ID}"
  AUDIT_LOG="${SESSION_PATH}/audit.log"

  # Create session directory structure
  mkdir -p "${SESSION_PATH}/evidence"
  log_pass "Session directory: ${SESSION_PATH}"

  # Initialize audit log
  {
    printf '# SIRM Audit Log\n'
    printf '# Session: %s\n' "$SESSION_ID"
    printf '# Created: %s\n' "$TIMESTAMP"
    printf '# Operator: %s\n' "$OPERATOR"
    printf '# Classification: %s\n' "$CLASSIFICATION"
    printf '%s\n' '---'
  } > "$AUDIT_LOG"

  audit_log "SESSION_INIT" "Session ${SESSION_ID} created"
  audit_log "CLASSIFICATION_SET" "Level: ${CLASSIFICATION}"
  [[ -n "$CASE_ID" ]] && audit_log "CASE_LINKED" "Case: ${CASE_ID}" || true

  # Build phase results JSON array
  local phases_json="["
  local first=true
  for p in "${PHASE_RESULTS[@]}"; do
    if [[ "$first" == "true" ]]; then first=false; else phases_json+=","; fi
    phases_json+="$p"
  done
  phases_json+="]"

  # Build tools JSON array
  local tools_json="["
  first=true
  for t in "${TOOL_STATUS[@]}"; do
    if [[ "$first" == "true" ]]; then first=false; else tools_json+=","; fi
    tools_json+="$t"
  done
  tools_json+="]"

  # Create session JSON
  cat > "${SESSION_PATH}/session.json" <<SESEOF
{
  "id": "${SESSION_ID}",
  "version": "${VERSION}",
  "operator": "${OPERATOR}",
  "classification": "${CLASSIFICATION}",
  "case_id": "${CASE_ID}",
  "created_at": "${TIMESTAMP}",
  "updated_at": "${TIMESTAMP}",
  "state": "ACTIVE",
  "identity": {
    "git_user": "${IDENT_GIT_USER}",
    "git_email": "${IDENT_GIT_EMAIL}",
    "hostname": "${IDENT_HOSTNAME}",
    "vault_entity": "${IDENT_VAULT_ENTITY}"
  },
  "context": {
    "git_branch": "${CTX_GIT_BRANCH}",
    "git_uncommitted": ${CTX_GIT_STATUS:-0},
    "vault_health": "${CTX_VAULT_HEALTH}",
    "sops_config": "${CTX_SOPS_CONFIG}",
    "cert_count": ${CTX_CERT_COUNT:-0},
    "repo_root": "${REPO_ROOT}"
  },
  "phases": ${phases_json},
  "tools": ${tools_json},
  "evidence": [],
  "timeline": [],
  "audit_trail": [],
  "sealed": false,
  "seal_hash": ""
}
SESEOF

  audit_log "SESSION_JSON_CREATED" "session.json written"
  log_pass "Session JSON: ${SESSION_PATH}/session.json"
  log_pass "Evidence dir: ${SESSION_PATH}/evidence/"
  log_pass "Audit log: ${AUDIT_LOG}"

  phase_record "session_creation" "PASS" "Session ${SESSION_ID} created"
  log_pass "Phase 4 complete — session ${SESSION_ID} active"
}

# ── Phase 5: Dashboard Output ──────────────────────────────────────────────

phase5_dashboard() {
  if [[ -n "$MINIMAL" ]]; then
    printf '\nSession ID: %s\n' "$SESSION_ID"
    printf 'State: ACTIVE\n'
    [[ -z "$DRY_RUN" ]] && printf 'Path: %s\n' "$SESSION_PATH" || true
    return 0
  fi

  local status_color status_text
  if [[ $FAIL_COUNT -gt 0 ]]; then
    status_text="RED"
    status_color="$(_red 'RED')"
  elif [[ $WARN_COUNT -gt 0 ]]; then
    status_text="YELLOW"
    status_color="$(_yellow 'YELLOW')"
  else
    status_text="GREEN"
    status_color="$(_green 'GREEN')"
  fi

  local case_display="${CASE_ID:-none}"
  local mode_display
  [[ -n "$DRY_RUN" ]] && mode_display="DRY RUN" || mode_display="LIVE"

  printf '\n'
  _bold '╔══════════════════════════════════════════════════════════════╗'; printf '\n'
  _bold '║  SIRM Session Bootstrap — Complete                         ║'; printf '\n'
  _bold '╠══════════════════════════════════════════════════════════════╣'; printf '\n'
  printf '║  Session:   %-47s ║\n' "$SESSION_ID"
  printf '║  Operator:  %-47s ║\n' "$OPERATOR"
  printf '║  Case:      %-47s ║\n' "$case_display"
  printf '║  Class:     %-47s ║\n' "$CLASSIFICATION"
  printf '║  Mode:      %-47s ║\n' "$mode_display"
  _bold '╠══════════════════════════════════════════════════════════════╣'; printf '\n'
  printf '║  Branch:    %-47s ║\n' "${CTX_GIT_BRANCH:-N/A}"
  printf '║  Vault:     %-47s ║\n' "${CTX_VAULT_HEALTH:-N/A}"
  printf '║  SOPS:      %-47s ║\n' "${CTX_SOPS_CONFIG:-N/A}"
  printf '║  Certs:     %-47s ║\n' "${CTX_CERT_COUNT:-0} files"
  _bold '╠══════════════════════════════════════════════════════════════╣'; printf '\n'
  printf '║  Status:    %-47s ║\n' "$status_color — ${WARN_COUNT} warnings, ${FAIL_COUNT} failures"
  printf '║  State:     %-47s ║\n' "ACTIVE"
  printf '║  Created:   %-47s ║\n' "$TIMESTAMP"
  _bold '╚══════════════════════════════════════════════════════════════╝'; printf '\n'

  if [[ -n "$DRY_RUN" ]]; then
    printf '\n%s\n' "$(_yellow 'DRY RUN — no session was created. Re-run without --dry-run to create.')"
  fi
}

# ── JSON output ─────────────────────────────────────────────────────────────

json_output() {
  if [[ -n "$JSON_OUTPUT" && -z "$DRY_RUN" && -f "${SESSION_PATH}/session.json" ]]; then
    jq '.' "${SESSION_PATH}/session.json" 2>/dev/null || cat "${SESSION_PATH}/session.json"
  elif [[ -n "$JSON_OUTPUT" ]]; then
    printf '{"id":"%s","state":"DRY_RUN","operator":"%s","classification":"%s"}\n' \
      "$SESSION_ID" "$OPERATOR" "$CLASSIFICATION"
  fi
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  if ! phase1_tool_validation; then
    printf '\n%s\n' "$(_red 'Bootstrap aborted — critical tools missing.')"
    exit 1
  fi

  phase2_operator_identity
  phase3_environment_context
  phase4_session_creation
  phase5_dashboard
  json_output

  [[ -z "$DRY_RUN" ]] && audit_log "BOOTSTRAP_COMPLETE" "Session ready" || true

  [[ $FAIL_COUNT -gt 0 ]] && exit 1 || true
  exit 0
}

main
