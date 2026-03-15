#!/usr/bin/env bash

#!/usr/bin/env bash
# secrets-doctor — Comprehensive CLI diagnostic tool for secrets infrastructure
# Usage: doctor.sh [deps|audit|vault|k8s|sops|git|all] [--no-color] [--json] [--verbose]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHECKS_DIR="${SCRIPT_DIR}/checks"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Color & output ──────────────────────────────────────────────────────────

NO_COLOR="${NO_COLOR:-}"
VERBOSE="${VERBOSE:-}"
JSON_OUTPUT="${JSON_OUTPUT:-}"

_red()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "$NO_COLOR" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

declare -a RESULTS=()

pass() {
  local msg="$1"
  PASS_COUNT=$((PASS_COUNT + 1))
  RESULTS+=("PASS|${msg}")
  printf '  %s %s\n' "$(_green '✓ PASS')" "$msg"
}

warn() {
  local msg="$1"
  WARN_COUNT=$((WARN_COUNT + 1))
  RESULTS+=("WARN|${msg}")
  printf '  %s %s\n' "$(_yellow '⚠ WARN')" "$msg"
}

fail() {
  local msg="$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
  RESULTS+=("FAIL|${msg}")
  printf '  %s %s\n' "$(_red '✗ FAIL')" "$msg"
}

skip() {
  local msg="$1"
  SKIP_COUNT=$((SKIP_COUNT + 1))
  RESULTS+=("SKIP|${msg}")
  printf '  %s %s\n' "$(_dim '— SKIP')" "$msg"
}

info() {
  [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_blue 'ℹ INFO')" "$1"
}

section() {
  printf '\n%s\n' "$(_bold "═══ $1 ═══")"
}

# ── Help ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'secrets-doctor') — Secrets infrastructure diagnostic tool

$(_bold 'USAGE')
  doctor.sh [COMMAND] [OPTIONS]

$(_bold 'COMMANDS')
  all       Run all checks (default)
  deps      Check required tool dependencies
  audit     Scan for plaintext secrets and credential hygiene
  vault     Validate Vault connectivity and configuration
  k8s       Check Kubernetes secret configurations
  sops      Validate SOPS configuration
  git       Check git hooks, .gitignore, and history
  certs     Check certificate files and cert-manager health

$(_bold 'OPTIONS')
  --no-color    Disable colored output
  --json        Output results as JSON
  --verbose     Show additional diagnostic info
  -h, --help    Show this help

$(_bold 'EXIT CODES')
  0   All checks passed
  1   One or more checks failed
  2   Usage error

$(_bold 'ENVIRONMENT')
  VAULT_ADDR          Vault server address (enables vault checks)
  VAULT_TOKEN         Vault authentication token
  KUBECONFIG          Kubernetes config path
  SECRETS_DOCTOR_SKIP Comma-separated list of checks to skip

$(_bold 'EXAMPLES')
  doctor.sh                  # Run all checks
  doctor.sh deps vault       # Run dependency and vault checks only
  doctor.sh audit --verbose  # Audit with verbose output
  doctor.sh all --json       # Full check with JSON output
EOF
  exit 0
}

# ── Argument parsing ─────────────────────────────────────────────────────────

COMMANDS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    --no-color)   NO_COLOR=1; shift ;;
    --json)       JSON_OUTPUT=1; shift ;;
    --verbose)    VERBOSE=1; shift ;;
    deps|audit|vault|k8s|sops|git|certs|all)
                  COMMANDS+=("$1"); shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      printf 'Run doctor.sh --help for usage.\n' >&2
      exit 2
      ;;
  esac
done

[[ ${#COMMANDS[@]} -eq 0 ]] && COMMANDS=("all")

# Expand "all" into individual commands
if [[ " ${COMMANDS[*]} " == *" all "* ]]; then
  COMMANDS=("deps" "sops" "git" "audit" "vault" "k8s" "certs")
fi

SKIP_LIST="${SECRETS_DOCTOR_SKIP:-}"

should_skip() {
  local check="$1"
  [[ -n "$SKIP_LIST" ]] && [[ ",${SKIP_LIST}," == *",${check},"* ]]
}

# ── Source check modules ─────────────────────────────────────────────────────

source_check() {
  local check_file="${CHECKS_DIR}/$1"
  if [[ -f "$check_file" ]]; then
    # shellcheck source=/dev/null
    source "$check_file"
  else
    fail "Check module not found: $1"
  fi
}

# ── Banner ───────────────────────────────────────────────────────────────────

print_banner() {
  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║           secrets-doctor — Health Check Report           ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Repo:      %-44s ║\n' "$(basename "$REPO_ROOT")"
  printf '║  Timestamp: %-44s ║\n' "$TIMESTAMP"
  printf '║  Commands:  %-44s ║\n' "${COMMANDS[*]}"
  _bold '╚═══════════════════════════════════════════════════════════╝'
  printf '\n'
}

# ── Summary ──────────────────────────────────────────────────────────────────

print_summary() {
  printf '\n'
  _bold '┌─────────────────────────────────────────────────────────┐'
  printf '\n'
  _bold '│                    HEALTH REPORT SUMMARY                │'
  printf '\n'
  _bold '├─────────────────────────────────────────────────────────┤'
  printf '\n'
  printf '│  %s %-10s %s %-10s %s %-10s %s %-10s │\n' \
    "$(_green '✓')" "${PASS_COUNT} passed" \
    "$(_yellow '⚠')" "${WARN_COUNT} warnings" \
    "$(_red '✗')" "${FAIL_COUNT} failed" \
    "$(_dim '—')" "${SKIP_COUNT} skipped"
  printf '\n'

  local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT + SKIP_COUNT))
  local status
  if [[ $FAIL_COUNT -gt 0 ]]; then
    status="$(_red 'UNHEALTHY')"
  elif [[ $WARN_COUNT -gt 0 ]]; then
    status="$(_yellow 'DEGRADED')"
  else
    status="$(_green 'HEALTHY')"
  fi
  printf '│  Overall: %s  (%d checks)%*s│\n' "$status" "$total" $((27 - ${#total})) ""
  printf '\n'
  _bold '└─────────────────────────────────────────────────────────┘'
  printf '\n'
}

print_json_summary() {
  local json_results="["
  local first=true
  for r in "${RESULTS[@]}"; do
    local status="${r%%|*}"
    local msg="${r#*|}"
    # Escape quotes in message
    msg="${msg//\"/\\\"}"
    if [[ "$first" == "true" ]]; then
      first=false
    else
      json_results+=","
    fi
    json_results+="{\"status\":\"${status}\",\"message\":\"${msg}\"}"
  done
  json_results+="]"

  local overall="HEALTHY"
  [[ $WARN_COUNT -gt 0 ]] && overall="DEGRADED"
  [[ $FAIL_COUNT -gt 0 ]] && overall="UNHEALTHY"

  cat <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "repository": "$(basename "$REPO_ROOT")",
  "overall": "${overall}",
  "summary": {
    "passed": ${PASS_COUNT},
    "warnings": ${WARN_COUNT},
    "failed": ${FAIL_COUNT},
    "skipped": ${SKIP_COUNT}
  },
  "results": ${json_results}
}
EOF
}

# ── Run checks ───────────────────────────────────────────────────────────────

run_deps_check() {
  if should_skip "deps"; then
    skip "Dependency checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "Dependency Checks"
  source_check "check_deps.sh"
  check_deps
}

run_sops_check() {
  if should_skip "sops"; then
    skip "SOPS checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "SOPS Configuration"
  source_check "check_sops.sh"
  check_sops
}

run_git_check() {
  if should_skip "git"; then
    skip "Git checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "Git Security"
  source_check "check_git.sh"
  check_git
}

run_audit_check() {
  if should_skip "audit"; then
    skip "Audit checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "Secret Audit"
  run_plaintext_scan
}

run_vault_check() {
  if should_skip "vault"; then
    skip "Vault checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "Vault Health"
  source_check "check_vault.sh"
  check_vault
}

run_k8s_check() {
  if should_skip "k8s"; then
    skip "Kubernetes checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "Kubernetes Secrets"
  source_check "check_k8s.sh"
  check_k8s
}

run_certs_check() {
  if should_skip "certs"; then
    skip "Certificate checks (skipped via SECRETS_DOCTOR_SKIP)"
    return
  fi
  section "Certificate Health"
  source_check "check_certs.sh"
  check_certs
}

# ── Built-in plaintext scan ─────────────────────────────────────────────────

run_plaintext_scan() {
  info "Scanning repository for plaintext secrets..."

  # Check for common secret patterns in tracked files
  local patterns=(
    'AKIA[0-9A-Z]{16}'                     # AWS Access Key
    '(?i)password\s*[:=]\s*["\x27][^"\x27]+'  # password assignments
    'ghp_[a-zA-Z0-9]{36}'                  # GitHub PAT
    'sk-[a-zA-Z0-9]{48}'                   # OpenAI API key
    'AGE-SECRET-KEY-'                      # age private key
    '-----BEGIN (RSA |EC )?PRIVATE KEY-----' # PEM private keys
    'vault_token\s*[:=]'                   # Vault tokens in config
    'VAULT_TOKEN\s*[:=]\s*["\x27]s\.'      # Vault token values
  )

  local found_secrets=0

  if command -v gitleaks &>/dev/null; then
    info "Using gitleaks for comprehensive scan..."
    local gitleaks_output
    if gitleaks_output=$(gitleaks detect --source="$REPO_ROOT" --no-git --no-banner 2>&1); then
      pass "No secrets detected by gitleaks"
    else
      if echo "$gitleaks_output" | grep -q "leaks found"; then
        local leak_count
        leak_count=$(echo "$gitleaks_output" | grep -c "Secret:" 2>/dev/null || echo "unknown")
        fail "gitleaks detected ${leak_count} potential secret(s) in repository"
        found_secrets=1
      else
        pass "No secrets detected by gitleaks"
      fi
    fi
  else
    warn "gitleaks not installed — falling back to pattern matching"
    for pattern in "${patterns[@]}"; do
      if grep -rEn "$pattern" "$REPO_ROOT" \
          --include='*.yaml' --include='*.yml' --include='*.json' \
          --include='*.env' --include='*.tf' --include='*.tfvars' \
          --include='*.sh' --include='*.py' --include='*.js' \
          --exclude-dir='.git' --exclude-dir='node_modules' \
          --exclude-dir='.terraform' --exclude-dir='tools' \
          2>/dev/null | head -5 | grep -q .; then
        fail "Potential secret pattern found: ${pattern:0:30}..."
        found_secrets=1
      fi
    done
    [[ $found_secrets -eq 0 ]] && pass "No common secret patterns detected (basic scan)"
  fi

  # Check for unencrypted secret files
  local unencrypted=0
  while IFS= read -r -d '' f; do
    if [[ "$f" == *.yaml || "$f" == *.yml || "$f" == *.json ]]; then
      if ! grep -q 'sops:' "$f" 2>/dev/null && ! grep -q '"sops":' "$f" 2>/dev/null; then
        if grep -qiE '(secret|password|token|apikey|credential)' "$f" 2>/dev/null; then
          # Skip files in tools/ and docs/
          if [[ "$f" != *"/tools/"* && "$f" != *"/docs/"* ]]; then
            warn "Potentially unencrypted secret file: ${f#"$REPO_ROOT"/}"
            unencrypted=$((unencrypted + 1))
          fi
        fi
      fi
    fi
  done < <(find "$REPO_ROOT" -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) \
    -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/tools/*' \
    -not -path '*/.terraform/*' -print0 2>/dev/null)

  [[ $unencrypted -eq 0 ]] && pass "No unencrypted secret files detected"

  # Check for .env files
  local env_files
  env_files=$(find "$REPO_ROOT" -name '.env' -o -name '.env.*' -not -name '.env.example' \
    -not -path '*/.git/*' 2>/dev/null | head -10)
  if [[ -n "$env_files" ]]; then
    local env_count
    env_count=$(echo "$env_files" | wc -l | tr -d ' ')
    warn "${env_count} .env file(s) found — ensure they are in .gitignore"
  else
    pass "No .env files found in repository"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
  print_banner

  for cmd in "${COMMANDS[@]}"; do
    case "$cmd" in
      deps)   run_deps_check ;;
      sops)   run_sops_check ;;
      git)    run_git_check ;;
      audit)  run_audit_check ;;
      vault)  run_vault_check ;;
      k8s)    run_k8s_check ;;
      certs)  run_certs_check ;;
      *)      fail "Unknown command: $cmd" ;;
    esac
  done

  if [[ -n "$JSON_OUTPUT" ]]; then
    print_json_summary
  else
    print_summary
  fi

  [[ $FAIL_COUNT -gt 0 ]] && exit 1
  exit 0
}

main
