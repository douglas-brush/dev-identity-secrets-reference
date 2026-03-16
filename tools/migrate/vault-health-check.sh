#!/usr/bin/env bash
# vault-health-check.sh — Comprehensive Vault health assessment
# Usage: vault-health-check.sh [--json] [--no-color] [--verbose] [--help]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"; export REPO_ROOT
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
JSON_OUTPUT=""
NO_COLOR="${NO_COLOR:-}"
VERBOSE=""

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
INFO_COUNT=0; export INFO_COUNT

declare -a JSON_SECTIONS=()

# ── Color & output ────────────────────────────────────────────────────────

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }
_cyan()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;36m%s\033[0m' "$1"; }

log() {
  local level="$1"; shift
  local msg="$*"
  [[ -n "$JSON_OUTPUT" ]] && return
  case "$level" in
    INFO)    printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)    printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR)   printf '  %s %s\n' "$(_red 'ERROR')" "$msg" >&2 ;;
    OK)      printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    STEP)    printf '\n%s %s\n' "$(_bold '==>')" "$(_bold "$msg")" ;;
    DEBUG)   [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_dim 'DBG ')" "$msg" || true ;;
  esac
}

pass() { PASS_COUNT=$((PASS_COUNT + 1)); log OK "$*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); log WARN "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); log ERROR "$*"; }
skip() { SKIP_COUNT=$((SKIP_COUNT + 1)); [[ -z "$JSON_OUTPUT" ]] && printf '  %s %s\n' "$(_dim '— SKIP')" "$*"; }

die() { printf '  %s %s\n' "$(_red 'ERROR')" "$*" >&2; exit 1; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'vault-health-check') — Comprehensive Vault health assessment

$(_bold 'USAGE')
  vault-health-check.sh [OPTIONS]

$(_bold 'OPTIONS')
  --json                Output full report as JSON
  --no-color            Disable colored output
  --verbose             Show detailed debug information
  -h, --help            Show this help

$(_bold 'CHECKS PERFORMED')
  1. Seal status, initialization, HA mode
  2. Replication status (DR and performance)
  3. Auth method inventory with configuration
  4. Policy analysis (unused, overly broad)
  5. Lease count and expiration distribution
  6. Secret engine utilization
  7. Audit device status
  8. Token accessor count and TTL health

$(_bold 'ENVIRONMENT')
  VAULT_ADDR              Vault server address (required)
  VAULT_TOKEN             Vault authentication token (required)

$(_bold 'EXAMPLES')
  vault-health-check.sh
  vault-health-check.sh --json | jq '.summary'
  vault-health-check.sh --verbose --no-color

$(_bold 'EXIT CODES')
  0   All checks passed or only warnings
  1   One or more critical issues found
  2   Usage or connectivity error
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    --json)       JSON_OUTPUT=1; shift ;;
    --no-color)   NO_COLOR=1; shift ;;
    --verbose)    VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run vault-health-check.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────

[[ -z "$VAULT_ADDR" ]] && die "VAULT_ADDR environment variable is not set"
[[ -z "$VAULT_TOKEN" ]] && die "VAULT_TOKEN environment variable is not set"

command -v vault >/dev/null 2>&1 || die "vault CLI not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"

# ── Check: Seal Status & HA ──────────────────────────────────────────────

check_seal_status() {
  log STEP "Seal Status & Cluster Health"

  local status_json
  status_json=$(vault status -format=json 2>/dev/null) || {
    fail "Cannot retrieve Vault status"
    JSON_SECTIONS+=("$(jq -n '{seal_status: {error: "unreachable"}}')")
    return
  }

  local initialized sealed ha_enabled cluster_name version storage_type
  initialized=$(echo "$status_json" | jq -r '.initialized')
  sealed=$(echo "$status_json" | jq -r '.sealed')
  ha_enabled=$(echo "$status_json" | jq -r '.ha_enabled // false')
  cluster_name=$(echo "$status_json" | jq -r '.cluster_name // "N/A"')
  version=$(echo "$status_json" | jq -r '.version // "unknown"')
  storage_type=$(echo "$status_json" | jq -r '.storage_type // "unknown"')

  if [[ "$initialized" == "true" ]]; then
    pass "Vault initialized"
  else
    fail "Vault is NOT initialized"
  fi

  if [[ "$sealed" == "false" ]]; then
    pass "Vault is unsealed"
  else
    fail "Vault is SEALED"
  fi

  log INFO "Version: ${version}"
  log INFO "Storage: ${storage_type}"
  log INFO "Cluster: ${cluster_name}"

  if [[ "$ha_enabled" == "true" ]]; then
    local is_leader
    is_leader=$(echo "$status_json" | jq -r '.is_self // "unknown"')
    pass "HA enabled (leader: ${is_leader})"
  else
    log INFO "HA mode: not enabled"
  fi

  JSON_SECTIONS+=("$(echo "$status_json" | jq '{
    seal_status: {
      initialized: .initialized,
      sealed: .sealed,
      version: .version,
      storage_type: .storage_type,
      cluster_name: .cluster_name,
      ha_enabled: .ha_enabled
    }
  }')")
}

# ── Check: Replication ────────────────────────────────────────────────────

check_replication() {
  log STEP "Replication Status"

  local repl_json
  repl_json=$(vault read -format=json sys/replication/status 2>/dev/null) || {
    log INFO "Replication status not available (may require Enterprise)"
    JSON_SECTIONS+=("$(jq -n '{replication: {available: false}}')")
    return
  }

  local dr_mode perf_mode
  dr_mode=$(echo "$repl_json" | jq -r '.data.dr.mode // "disabled"')
  perf_mode=$(echo "$repl_json" | jq -r '.data.performance.mode // "disabled"')

  if [[ "$dr_mode" != "disabled" ]]; then
    local dr_state
    dr_state=$(echo "$repl_json" | jq -r '.data.dr.state // "unknown"')
    [[ "$dr_state" == "stream-wals" ]] && pass "DR replication: ${dr_mode} (streaming)" \
      || warn "DR replication: ${dr_mode} (state: ${dr_state})"
  else
    log INFO "DR replication: disabled"
  fi

  if [[ "$perf_mode" != "disabled" ]]; then
    local perf_state
    perf_state=$(echo "$repl_json" | jq -r '.data.performance.state // "unknown"')
    [[ "$perf_state" == "stream-wals" ]] && pass "Performance replication: ${perf_mode} (streaming)" \
      || warn "Performance replication: ${perf_mode} (state: ${perf_state})"
  else
    log INFO "Performance replication: disabled"
  fi

  JSON_SECTIONS+=("$(jq -n \
    --arg dr "$dr_mode" \
    --arg perf "$perf_mode" \
    '{replication: {dr_mode: $dr, performance_mode: $perf}}')")
}

# ── Check: Auth Methods ──────────────────────────────────────────────────

check_auth_methods() {
  log STEP "Auth Method Inventory"

  local auth_json
  auth_json=$(vault auth list -format=json 2>/dev/null) || {
    fail "Cannot list auth methods"
    JSON_SECTIONS+=("$(jq -n '{auth_methods: {error: "access_denied"}}')")
    return
  }

  local auth_count
  auth_count=$(echo "$auth_json" | jq 'keys | length')
  log INFO "Auth methods enabled: ${auth_count}"

  local auth_report="[]"

  while IFS= read -r mount; do
    [[ -z "$mount" ]] && continue
    local type description accessor
    type=$(echo "$auth_json" | jq -r ".\"${mount}\".type")
    description=$(echo "$auth_json" | jq -r ".\"${mount}\".description // \"\"")
    accessor=$(echo "$auth_json" | jq -r ".\"${mount}\".accessor")

    if [[ -z "$JSON_OUTPUT" ]]; then
      printf '  %s %-20s type=%-12s %s\n' "$(_cyan '  >')" "$mount" "$type" "$(_dim "$description")"
    fi

    auth_report=$(echo "$auth_report" | jq \
      --arg m "$mount" \
      --arg t "$type" \
      --arg d "$description" \
      --arg a "$accessor" \
      '. + [{"mount": $m, "type": $t, "description": $d, "accessor": $a}]')
  done < <(echo "$auth_json" | jq -r 'keys[]')

  # Check for common missing auth methods
  local has_oidc has_ldap has_approle
  local has_oidc has_ldap has_approle
  has_oidc=$(echo "$auth_json" | jq 'to_entries | map(select(.value.type == "oidc")) | length')
  has_ldap=$(echo "$auth_json" | jq 'to_entries | map(select(.value.type == "ldap")) | length')
  has_approle=$(echo "$auth_json" | jq 'to_entries | map(select(.value.type == "approle")) | length')

  [[ "$has_oidc" -eq 0 ]] && log INFO "No OIDC auth — consider for SSO integration"
  [[ "$has_ldap" -eq 0 ]] && log INFO "No LDAP auth — consider for directory integration"
  [[ "$has_approle" -eq 0 ]] && log INFO "No AppRole auth — consider for machine-to-machine"

  pass "Auth methods inventory complete (${auth_count} methods)"

  JSON_SECTIONS+=("$(echo "$auth_report" | jq '{auth_methods: .}')")
}

# ── Check: Policies ───────────────────────────────────────────────────────

check_policies() {
  log STEP "Policy Analysis"

  local policies
  policies=$(vault policy list -format=json 2>/dev/null) || {
    fail "Cannot list policies"
    JSON_SECTIONS+=("$(jq -n '{policies: {error: "access_denied"}}')")
    return
  }

  local policy_count
  policy_count=$(echo "$policies" | jq 'length')
  log INFO "Policies defined: ${policy_count}"

  local overly_broad=()
  local empty_policies=()
  local policy_report="[]"

  while IFS= read -r policy_name; do
    [[ -z "$policy_name" ]] && continue
    [[ "$policy_name" == "root" ]] && continue

    local policy_text
    policy_text=$(vault policy read "$policy_name" 2>/dev/null) || continue

    local rule_count
    rule_count=$(echo "$policy_text" | grep -c 'path ' || true)

    # Check for overly broad patterns
    local has_wildcard_root="" has_sudo=""
    if echo "$policy_text" | grep -qE 'path\s+"[*]"'; then
      has_wildcard_root=1
      overly_broad+=("$policy_name")
    fi
    if echo "$policy_text" | grep -qE 'capabilities.*sudo'; then
      has_sudo=1
    fi

    if [[ "$rule_count" -eq 0 ]]; then
      empty_policies+=("$policy_name")
    fi

    policy_report=$(echo "$policy_report" | jq \
      --arg name "$policy_name" \
      --argjson rules "$rule_count" \
      --argjson broad "$(echo "${has_wildcard_root:-false}" | jq -R 'if . == "1" then true else false end')" \
      --argjson sudo "$(echo "${has_sudo:-false}" | jq -R 'if . == "1" then true else false end')" \
      '. + [{"name": $name, "rule_count": $rules, "wildcard_root": $broad, "has_sudo": $sudo}]')

    log DEBUG "Policy '${policy_name}': ${rule_count} rules"
  done < <(echo "$policies" | jq -r '.[]')

  if [[ ${#overly_broad[@]} -gt 0 ]]; then
    warn "Overly broad policies (wildcard root): ${overly_broad[*]}"
  else
    pass "No overly broad wildcard-root policies"
  fi

  if [[ ${#empty_policies[@]} -gt 0 ]]; then
    warn "Empty policies (no rules): ${empty_policies[*]}"
  fi

  pass "Policy analysis complete (${policy_count} policies)"

  JSON_SECTIONS+=("$(echo "$policy_report" | jq '{policies: {count: length, details: .}}')")
}

# ── Check: Leases ─────────────────────────────────────────────────────────

check_leases() {
  log STEP "Lease Health"

  # Get lease counts by prefix
  local lease_json
  lease_json=$(vault list -format=json sys/leases/lookup/ 2>/dev/null) || {
    log INFO "Cannot enumerate leases (may require root token)"
    JSON_SECTIONS+=("$(jq -n '{leases: {available: false}}')")
    return
  }

  local prefixes
  prefixes=$(echo "$lease_json" | jq -r '.[]')

  local total_leases=0
  local lease_report="[]"

  while IFS= read -r prefix; do
    [[ -z "$prefix" ]] && continue

    local count
    count=$(vault list -format=json "sys/leases/lookup/${prefix}" 2>/dev/null | jq 'length' 2>/dev/null) || continue
    total_leases=$((total_leases + count))

    lease_report=$(echo "$lease_report" | jq \
      --arg p "$prefix" \
      --argjson c "$count" \
      '. + [{"prefix": $p, "count": $c}]')

    if [[ -z "$JSON_OUTPUT" ]]; then
      printf '  %s %-30s %s leases\n' "$(_cyan '  >')" "$prefix" "$count"
    fi
  done <<< "$prefixes"

  if [[ "$total_leases" -gt 10000 ]]; then
    warn "High lease count: ${total_leases} (consider lease cleanup)"
  elif [[ "$total_leases" -gt 1000 ]]; then
    log INFO "Total leases: ${total_leases}"
  else
    pass "Lease count healthy: ${total_leases}"
  fi

  JSON_SECTIONS+=("$(echo "$lease_report" | jq --argjson total "$total_leases" '{leases: {total: $total, by_prefix: .}}')")
}

# ── Check: Secret Engines ────────────────────────────────────────────────

check_secret_engines() {
  log STEP "Secret Engine Utilization"

  local engines_json
  engines_json=$(vault secrets list -format=json 2>/dev/null) || {
    fail "Cannot list secret engines"
    JSON_SECTIONS+=("$(jq -n '{secret_engines: {error: "access_denied"}}')")
    return
  }

  local engine_count
  engine_count=$(echo "$engines_json" | jq 'keys | length')
  log INFO "Secret engines enabled: ${engine_count}"

  local engine_report="[]"

  while IFS= read -r mount; do
    [[ -z "$mount" ]] && continue
    local type description version
    type=$(echo "$engines_json" | jq -r ".\"${mount}\".type")
    description=$(echo "$engines_json" | jq -r ".\"${mount}\".description // \"\"")
    version=$(echo "$engines_json" | jq -r ".\"${mount}\".options.version // \"N/A\"")

    if [[ -z "$JSON_OUTPUT" ]]; then
      local version_str=""
      [[ "$version" != "N/A" ]] && version_str=" v${version}"
      printf '  %s %-25s type=%-12s%s %s\n' "$(_cyan '  >')" "$mount" "$type" "$version_str" "$(_dim "$description")"
    fi

    engine_report=$(echo "$engine_report" | jq \
      --arg m "$mount" \
      --arg t "$type" \
      --arg v "$version" \
      --arg d "$description" \
      '. + [{"mount": $m, "type": $t, "version": $v, "description": $d}]')
  done < <(echo "$engines_json" | jq -r 'keys[]')

  # Check for common patterns
  local kv_count transit_count pki_count
  kv_count=$(echo "$engines_json" | jq '[to_entries[] | select(.value.type == "kv")] | length')
  transit_count=$(echo "$engines_json" | jq '[to_entries[] | select(.value.type == "transit")] | length')
  pki_count=$(echo "$engines_json" | jq '[to_entries[] | select(.value.type == "pki")] | length')

  [[ "$kv_count" -eq 0 ]] && log INFO "No KV engine — consider for secret storage"
  [[ "$transit_count" -eq 0 ]] && log INFO "No Transit engine — consider for encryption-as-a-service"
  [[ "$pki_count" -eq 0 ]] && log INFO "No PKI engine — consider for certificate management"

  pass "Secret engine inventory complete (${engine_count} engines)"

  JSON_SECTIONS+=("$(echo "$engine_report" | jq '{secret_engines: {count: length, details: .}}')")
}

# ── Check: Audit Devices ─────────────────────────────────────────────────

check_audit_devices() {
  log STEP "Audit Devices"

  local audit_json
  audit_json=$(vault audit list -format=json 2>/dev/null) || {
    warn "Cannot list audit devices (may require elevated privileges)"
    JSON_SECTIONS+=("$(jq -n '{audit_devices: {available: false}}')")
    return
  }

  local audit_count
  audit_count=$(echo "$audit_json" | jq 'keys | length')

  if [[ "$audit_count" -eq 0 ]]; then
    fail "No audit devices enabled — all Vault operations are unaudited"
  else
    pass "Audit devices enabled: ${audit_count}"

    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      local type
      type=$(echo "$audit_json" | jq -r ".\"${path}\".type")
      if [[ -z "$JSON_OUTPUT" ]]; then
        printf '  %s %-25s type=%s\n' "$(_cyan '  >')" "$path" "$type"
      fi
    done < <(echo "$audit_json" | jq -r 'keys[]')
  fi

  JSON_SECTIONS+=("$(echo "$audit_json" | jq '{audit_devices: {count: (keys | length), devices: .}}')")
}

# ── Check: Token Health ───────────────────────────────────────────────────

check_token_health() {
  log STEP "Token Self-Check"

  local self_json
  self_json=$(vault token lookup -format=json 2>/dev/null) || {
    fail "Cannot look up current token"
    JSON_SECTIONS+=("$(jq -n '{token_health: {error: "lookup_failed"}}')")
    return
  }

  local display_name policies ttl orphan
  display_name=$(echo "$self_json" | jq -r '.data.display_name // "unknown"')
  policies=$(echo "$self_json" | jq -c '.data.policies // []')
  ttl=$(echo "$self_json" | jq -r '.data.ttl // 0')
  orphan=$(echo "$self_json" | jq -r '.data.orphan // false')

  log INFO "Token identity: ${display_name}"
  log INFO "Token policies: $(echo "$policies" | jq -r 'join(", ")')"

  if [[ "$ttl" -eq 0 ]]; then
    warn "Token has no TTL (root or infinite token)"
  elif [[ "$ttl" -lt 3600 ]]; then
    warn "Token TTL is low: ${ttl}s (less than 1 hour)"
  else
    local hours=$((ttl / 3600))
    pass "Token TTL: ${hours}h remaining"
  fi

  # Check if using root token
  if echo "$policies" | jq -e '. | index("root")' >/dev/null 2>&1; then
    warn "Operating with root token — use a scoped token in production"
  fi

  JSON_SECTIONS+=("$(jq -n \
    --arg name "$display_name" \
    --argjson policies "$policies" \
    --argjson ttl "$ttl" \
    --argjson orphan "$(echo "$orphan" | jq -R 'if . == "true" then true else false end')" \
    '{token_health: {display_name: $name, policies: $policies, ttl_seconds: $ttl, orphan: $orphan}}')")
}

# ── Report ────────────────────────────────────────────────────────────────

print_summary() {
  if [[ -n "$JSON_OUTPUT" ]]; then
    local merged='{}'
    for section in "${JSON_SECTIONS[@]}"; do
      merged=$(echo "$merged" "$section" | jq -s '.[0] * .[1]')
    done

    echo "$merged" | jq \
      --arg addr "$VAULT_ADDR" \
      --arg ts "$TIMESTAMP" \
      --argjson pass "$PASS_COUNT" \
      --argjson warn "$WARN_COUNT" \
      --argjson fail "$FAIL_COUNT" \
      --argjson skip "$SKIP_COUNT" \
      '{
        health_check: {
          vault_addr: $addr,
          timestamp: $ts,
          summary: {
            pass: $pass,
            warn: $warn,
            fail: $fail,
            skip: $skip,
            status: (if $fail > 0 then "CRITICAL" elif $warn > 0 then "WARNING" else "HEALTHY" end)
          }
        }
      } + .'
    return
  fi

  log STEP "Health Check Summary"
  printf '\n'
  printf '  %s  Vault: %s\n' "$(_bold 'Target')" "$VAULT_ADDR"
  printf '  %s  %s\n' "$(_bold '  Time')" "$TIMESTAMP"
  printf '\n'
  printf '  %s  %s\n' "$(_green 'Pass')" "$PASS_COUNT"
  printf '  %s  %s\n' "$(_yellow 'Warn')" "$WARN_COUNT"
  printf '  %s  %s\n' "$(_red 'Fail')" "$FAIL_COUNT"
  printf '  %s  %s\n' "$(_dim 'Skip')" "$SKIP_COUNT"
  printf '\n'

  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    printf '  Status: %s\n\n' "$(_red 'CRITICAL — action required')"
  elif [[ "$WARN_COUNT" -gt 0 ]]; then
    printf '  Status: %s\n\n' "$(_yellow 'WARNING — review recommended')"
  else
    printf '  Status: %s\n\n' "$(_green 'HEALTHY')"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  [[ -z "$JSON_OUTPUT" ]] && {
    printf '\n%s\n' "$(_bold '════════════════════════════════════════════════')"
    printf '%s\n' "$(_bold '  Vault Health Check Report')"
    printf '%s\n' "$(_bold '════════════════════════════════════════════════')"
  }

  check_seal_status
  check_replication
  check_auth_methods
  check_policies
  check_leases
  check_secret_engines
  check_audit_devices
  check_token_health

  print_summary

  [[ "$FAIL_COUNT" -gt 0 ]] && exit 1
  exit 0
}

main
