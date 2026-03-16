#!/usr/bin/env bats
# test_sirm.bats — Unit tests for tools/sirm/ (bootstrap, session, evidence, timeline)

load helpers

BOOTSTRAP_SCRIPT="${REPO_ROOT}/tools/sirm/sirm-bootstrap.sh"
SESSION_SCRIPT="${REPO_ROOT}/tools/sirm/sirm-session.sh"
EVIDENCE_SCRIPT="${REPO_ROOT}/tools/sirm/sirm-evidence.sh"
TIMELINE_SCRIPT="${REPO_ROOT}/tools/sirm/sirm-timeline.sh"

setup() {
  common_setup
  export SESSION_DIR="$TEST_TEMP_DIR/sessions"
  mkdir -p "$SESSION_DIR"
}

teardown() {
  common_teardown
}

# Helper: bootstrap a session and capture the session ID
bootstrap_session() {
  local output
  output=$("$BOOTSTRAP_SCRIPT" --operator "Test User" --session-dir "$SESSION_DIR" --minimal --no-color 2>&1)
  echo "$output" | grep "Session ID:" | awk '{print $NF}'
}

# ═══════════════════════════════════════════════════════════════════════════════
# sirm-bootstrap.sh
# ═══════════════════════════════════════════════════════════════════════════════

@test "sirm-bootstrap.sh --help prints usage and exits 0" {
  run "$BOOTSTRAP_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "REQUIRED"
  assert_output_contains "OPTIONS"
  assert_output_contains "CLASSIFICATION LEVELS"
  assert_output_contains "EXIT CODES"
  assert_output_contains "EXAMPLES"
}

@test "sirm-bootstrap.sh -h prints usage" {
  run "$BOOTSTRAP_SCRIPT" -h
  assert_success
  assert_output_contains "sirm-bootstrap"
}

@test "sirm-bootstrap.sh fails without --operator" {
  run "$BOOTSTRAP_SCRIPT"
  [ "$status" -eq 2 ]
  assert_output_contains "--operator is required"
}

@test "sirm-bootstrap.sh rejects unknown arguments" {
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --invalid-flag
  [ "$status" -eq 2 ]
  assert_output_contains "unknown argument"
}

@test "sirm-bootstrap.sh rejects invalid classification" {
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --classification INVALID
  [ "$status" -eq 2 ]
  assert_output_contains "invalid classification"
}

@test "sirm-bootstrap.sh accepts valid classifications" {
  for cls in PUBLIC INTERNAL CONFIDENTIAL RESTRICTED COURT-SEALED; do
    run "$BOOTSTRAP_SCRIPT" --operator "Test" --classification "$cls" --dry-run --minimal --no-color
    assert_success
  done
}

@test "sirm-bootstrap.sh --dry-run does not create session" {
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --dry-run --session-dir "$SESSION_DIR" --minimal --no-color
  assert_success
  # No session directories should be created
  local count
  count=$(find "$SESSION_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  [ "$count" -eq 0 ]
}

@test "sirm-bootstrap.sh creates session directory and files" {
  require_command jq
  run "$BOOTSTRAP_SCRIPT" --operator "Test User" --session-dir "$SESSION_DIR" --minimal --no-color
  assert_success
  # Should have created a session directory
  local count
  count=$(find "$SESSION_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  [ "$count" -ge 1 ]
  # Should have session.json and audit.log in the directory
  local session_path
  session_path=$(find "$SESSION_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
  assert_file_exists "$session_path/session.json"
  assert_file_exists "$session_path/audit.log"
}

@test "sirm-bootstrap.sh session.json has correct structure" {
  require_command jq
  run "$BOOTSTRAP_SCRIPT" --operator "Test User" --session-dir "$SESSION_DIR" --minimal --no-color
  assert_success
  local session_path
  session_path=$(find "$SESSION_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
  local sjson="$session_path/session.json"
  # Validate key fields
  local state
  state=$(jq -r '.state' "$sjson")
  [ "$state" = "ACTIVE" ]
  local operator
  operator=$(jq -r '.operator' "$sjson")
  [ "$operator" = "Test User" ]
}

@test "sirm-bootstrap.sh --case-id sets case in session" {
  require_command jq
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --case-id "2024-CV-1234" --session-dir "$SESSION_DIR" --minimal --no-color
  assert_success
  local session_path
  session_path=$(find "$SESSION_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
  local case_id
  case_id=$(jq -r '.case_id' "$session_path/session.json")
  [ "$case_id" = "2024-CV-1234" ]
}

@test "sirm-bootstrap.sh --json outputs JSON" {
  require_command jq
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --session-dir "$SESSION_DIR" --json --minimal --no-color
  assert_success
  assert_output_contains '"id"'
  assert_output_contains '"state"'
}

@test "sirm-bootstrap.sh phase 1 validates tools" {
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --session-dir "$SESSION_DIR" --no-color --dry-run
  assert_success
  assert_output_contains "Phase 1"
  assert_output_contains "Tool Validation"
}

@test "sirm-bootstrap.sh phase 2 captures operator identity" {
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --session-dir "$SESSION_DIR" --no-color --dry-run
  assert_success
  assert_output_contains "Phase 2"
  assert_output_contains "Operator Identity"
}

@test "sirm-bootstrap.sh phase 3 captures environment context" {
  run "$BOOTSTRAP_SCRIPT" --operator "Test" --session-dir "$SESSION_DIR" --no-color --dry-run
  assert_success
  assert_output_contains "Phase 3"
  assert_output_contains "Environment Context"
}

# ═══════════════════════════════════════════════════════════════════════════════
# sirm-session.sh
# ═══════════════════════════════════════════════════════════════════════════════

@test "sirm-session.sh --help prints usage and exits 0" {
  run "$SESSION_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "COMMANDS"
  assert_output_contains "OPTIONS"
  assert_output_contains "STATE MACHINE"
  assert_output_contains "EXAMPLES"
}

@test "sirm-session.sh with no args prints usage" {
  run "$SESSION_SCRIPT"
  assert_success
}

@test "sirm-session.sh list with empty dir" {
  run "$SESSION_SCRIPT" list --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "SIRM Sessions"
  assert_output_contains "Total: 0"
}

@test "sirm-session.sh status shows session info" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  [ -n "$sid" ]
  run "$SESSION_SCRIPT" status "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Session Status"
  assert_output_contains "ACTIVE"
}

@test "sirm-session.sh suspend requires --reason" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$SESSION_SCRIPT" suspend "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "--reason required"
}

@test "sirm-session.sh suspend transitions ACTIVE -> SUSPENDED" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$SESSION_SCRIPT" suspend "$sid" --reason "Awaiting lab" --session-dir "$SESSION_DIR" --no-color
  assert_success
  local state
  state=$(jq -r '.state' "$SESSION_DIR/$sid/session.json")
  [ "$state" = "SUSPENDED" ]
}

@test "sirm-session.sh resume transitions SUSPENDED -> ACTIVE" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$SESSION_SCRIPT" suspend "$sid" --reason "Pause" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$SESSION_SCRIPT" resume "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  local state
  state=$(jq -r '.state' "$SESSION_DIR/$sid/session.json")
  [ "$state" = "ACTIVE" ]
}

@test "sirm-session.sh close transitions ACTIVE -> CLOSED" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$SESSION_SCRIPT" close "$sid" --findings "No findings" --session-dir "$SESSION_DIR" --no-color
  assert_success
  local state
  state=$(jq -r '.state' "$SESSION_DIR/$sid/session.json")
  [ "$state" = "CLOSED" ]
}

@test "sirm-session.sh seal transitions CLOSED -> SEALED" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$SESSION_SCRIPT" close "$sid" --findings "Done" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$SESSION_SCRIPT" seal "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  local state
  state=$(jq -r '.state' "$SESSION_DIR/$sid/session.json")
  [ "$state" = "SEALED" ]
  assert_output_contains "SHA-256"
}

@test "sirm-session.sh rejects invalid state transition" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  # Cannot seal from ACTIVE directly
  run "$SESSION_SCRIPT" seal "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "Invalid state transition"
}

@test "sirm-session.sh list shows created sessions" {
  require_command jq
  bootstrap_session >/dev/null
  run "$SESSION_SCRIPT" list --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Total: 1"
}

@test "sirm-session.sh export json outputs session data" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$SESSION_SCRIPT" export "$sid" --format json --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains '"state"'
  assert_output_contains '"operator"'
}

@test "sirm-session.sh export csv outputs CSV" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$SESSION_SCRIPT" export "$sid" --format csv --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "id,operator,state"
}

@test "sirm-session.sh export markdown outputs markdown" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$SESSION_SCRIPT" export "$sid" --format markdown --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "# SIRM Session Report"
}

# ═══════════════════════════════════════════════════════════════════════════════
# sirm-evidence.sh
# ═══════════════════════════════════════════════════════════════════════════════

@test "sirm-evidence.sh --help prints usage and exits 0" {
  run "$EVIDENCE_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "COMMANDS"
  assert_output_contains "OPTIONS"
  assert_output_contains "PRINCIPLES"
  assert_output_contains "EXAMPLES"
}

@test "sirm-evidence.sh with no args prints usage" {
  run "$EVIDENCE_SCRIPT"
  assert_success
}

@test "sirm-evidence.sh register requires session-id" {
  run "$EVIDENCE_SCRIPT" register --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "session-id required"
}

@test "sirm-evidence.sh register requires file-path" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$EVIDENCE_SCRIPT" register "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "file-path required"
}

@test "sirm-evidence.sh register adds evidence to session" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  # Create an evidence file
  echo "evidence data content" > "$TEST_TEMP_DIR/disk.img"
  run "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/disk.img" \
    --description "Test disk image" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Evidence registered: EV-001"
  assert_output_contains "SHA-256"
  # Verify evidence in session JSON
  local ev_count
  ev_count=$(jq '.evidence | length' "$SESSION_DIR/$sid/session.json")
  [ "$ev_count" -eq 1 ]
}

@test "sirm-evidence.sh verify checks evidence integrity" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "evidence data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test artifact" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$EVIDENCE_SCRIPT" verify "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "INTEGRITY VERIFIED"
}

@test "sirm-evidence.sh verify detects tampering" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "original data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test artifact" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  # Tamper with the file
  echo "tampered data" > "$TEST_TEMP_DIR/artifact.bin"
  run "$EVIDENCE_SCRIPT" verify "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "INTEGRITY FAILURE"
}

@test "sirm-evidence.sh verify detects missing file" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test artifact" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  rm -f "$TEST_TEMP_DIR/artifact.bin"
  run "$EVIDENCE_SCRIPT" verify "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "FILE MISSING"
}

@test "sirm-evidence.sh transfer records custody change" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$EVIDENCE_SCRIPT" transfer "$sid" EV-001 \
    --to "Lab Tech A" --reason "Forensic analysis" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Transfer recorded"
  assert_output_contains "Lab Tech A"
}

@test "sirm-evidence.sh transfer requires --to and --reason" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$EVIDENCE_SCRIPT" transfer "$sid" EV-001 --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "--to required"
}

@test "sirm-evidence.sh list shows registered evidence" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test artifact" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$EVIDENCE_SCRIPT" list "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "EV-001"
  assert_output_contains "Total: 1"
}

@test "sirm-evidence.sh rejects operations on sealed sessions" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$SESSION_SCRIPT" close "$sid" --findings "Done" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  "$SESSION_SCRIPT" seal "$sid" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  run "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "SEALED"
}

@test "sirm-evidence.sh manifest text format" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test artifact" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$EVIDENCE_SCRIPT" manifest "$sid" --format text --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Evidence Manifest"
  assert_output_contains "EV-001"
}

@test "sirm-evidence.sh manifest json format" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  echo "test data" > "$TEST_TEMP_DIR/artifact.bin"
  "$EVIDENCE_SCRIPT" register "$sid" "$TEST_TEMP_DIR/artifact.bin" \
    --description "Test artifact" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$EVIDENCE_SCRIPT" manifest "$sid" --format json --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains '"evidence_count"'
}

# ═══════════════════════════════════════════════════════════════════════════════
# sirm-timeline.sh
# ═══════════════════════════════════════════════════════════════════════════════

@test "sirm-timeline.sh --help prints usage and exits 0" {
  run "$TIMELINE_SCRIPT" --help
  assert_success
  assert_output_contains "USAGE"
  assert_output_contains "COMMANDS"
  assert_output_contains "CONFIDENCE LEVELS"
  assert_output_contains "EXAMPLES"
}

@test "sirm-timeline.sh with no args prints usage" {
  run "$TIMELINE_SCRIPT"
  assert_success
}

@test "sirm-timeline.sh add requires --description" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$TIMELINE_SCRIPT" add "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "--description required"
}

@test "sirm-timeline.sh add creates timeline event" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$TIMELINE_SCRIPT" add "$sid" \
    --source operator --type action --description "Test event" --confidence F \
    --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Timeline event added"
  assert_output_contains "Test event"
  # Verify timeline in session JSON
  local tl_count
  tl_count=$(jq '.timeline | length' "$SESSION_DIR/$sid/session.json")
  [ "$tl_count" -eq 1 ]
}

@test "sirm-timeline.sh add validates confidence levels" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$TIMELINE_SCRIPT" add "$sid" \
    --description "Test" --confidence X \
    --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "Invalid confidence"
}

@test "sirm-timeline.sh add accepts all valid confidence levels" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  for conf in F O I H; do
    run "$TIMELINE_SCRIPT" add "$sid" \
      --description "Event $conf" --confidence "$conf" \
      --session-dir "$SESSION_DIR" --no-color
    assert_success
  done
  local tl_count
  tl_count=$(jq '.timeline | length' "$SESSION_DIR/$sid/session.json")
  [ "$tl_count" -eq 4 ]
}

@test "sirm-timeline.sh add with --evidence-ref links evidence" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$TIMELINE_SCRIPT" add "$sid" \
    --description "Found artifact" --confidence O --evidence-ref EV-001 \
    --session-dir "$SESSION_DIR" --no-color
  assert_success
  local ref
  ref=$(jq -r '.timeline[0].evidence_refs[0]' "$SESSION_DIR/$sid/session.json")
  [ "$ref" = "EV-001" ]
}

@test "sirm-timeline.sh show displays events" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$TIMELINE_SCRIPT" add "$sid" --description "Event A" --confidence F \
    --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  "$TIMELINE_SCRIPT" add "$sid" --description "Event B" --confidence O \
    --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$TIMELINE_SCRIPT" show "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "Event A"
  assert_output_contains "Event B"
  assert_output_contains "2 event(s)"
}

@test "sirm-timeline.sh export json format" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$TIMELINE_SCRIPT" add "$sid" --description "Test event" --confidence F \
    --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$TIMELINE_SCRIPT" export "$sid" --format json --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains '"description"'
  assert_output_contains '"confidence"'
}

@test "sirm-timeline.sh export csv format" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$TIMELINE_SCRIPT" add "$sid" --description "Test event" --confidence F \
    --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$TIMELINE_SCRIPT" export "$sid" --format csv --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "timestamp,source,type"
}

@test "sirm-timeline.sh export markdown format" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$TIMELINE_SCRIPT" add "$sid" --description "Test event" --confidence F \
    --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$TIMELINE_SCRIPT" export "$sid" --format markdown --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "# Timeline"
}

@test "sirm-timeline.sh import-git imports commits" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$TIMELINE_SCRIPT" import-git "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "git commits imported"
}

@test "sirm-timeline.sh rejects operations on sealed sessions" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  "$SESSION_SCRIPT" close "$sid" --findings "Done" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  "$SESSION_SCRIPT" seal "$sid" --session-dir "$SESSION_DIR" --no-color >/dev/null 2>&1
  run "$TIMELINE_SCRIPT" add "$sid" --description "Test" --confidence F \
    --session-dir "$SESSION_DIR" --no-color
  assert_failure
  assert_output_contains "SEALED"
}

@test "sirm-timeline.sh show with empty timeline" {
  require_command jq
  local sid
  sid=$(bootstrap_session)
  run "$TIMELINE_SCRIPT" show "$sid" --session-dir "$SESSION_DIR" --no-color
  assert_success
  assert_output_contains "No timeline events"
}
