#!/usr/bin/env bash
set -euo pipefail

# scan_repo.sh — Comprehensive secret scanning orchestrator.
# Runs gitleaks, plaintext pattern scanner, entropy checks, permission audits,
# and .env file checks. Generates a consolidated report.

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly ROOT_DIR
readonly REPORT_DIR="$ROOT_DIR/logs/scan-reports"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly TIMESTAMP

# Flags
JSON_OUTPUT=0
CI_MODE=0
FIX_MODE=0
VERBOSE=0
ENTROPY_THRESHOLD="4.5"
EXIT_CODE=0

# Colors (disabled in JSON/CI mode or non-TTY)
setup_colors() {
  if [[ -t 1 ]] && [[ $JSON_OUTPUT -eq 0 ]] && [[ $CI_MODE -eq 0 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
  else
    RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''
  fi
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Comprehensive repository secret scanner. Orchestrates multiple scanning tools
and produces a consolidated report.

Options:
  --json              Output JSON report to stdout
  --ci                GitHub Actions annotation format (::warning, ::error)
  --fix               Offer to SOPS-encrypt detected plaintext secrets
  --verbose           Verbose output from sub-scanners
  --threshold FLOAT   Entropy threshold (default: 4.5)
  --help              Show this help message

Exit codes:
  0  Clean — no findings
  1  Findings detected
  2  Scanner error

Scanners:
  1. gitleaks          Pattern-based secret detection (custom config if available)
  2. plaintext scan    check_no_plaintext_secrets.sh patterns
  3. entropy check     Shannon entropy analysis on non-binary files
  4. permission audit  Verify private key file permissions (600/400)
  5. env file check    Ensure .env files are gitignored

Reports:
  Text reports: logs/scan-reports/scan-YYYYMMDDTHHMMSSZ.txt
  JSON reports: logs/scan-reports/scan-YYYYMMDDTHHMMSSZ.json
EOF
  exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)      JSON_OUTPUT=1; shift ;;
    --ci)        CI_MODE=1; shift ;;
    --fix)       FIX_MODE=1; shift ;;
    --verbose)   VERBOSE=1; shift ;;
    --threshold) ENTROPY_THRESHOLD="$2"; shift 2 ;;
    --help)      usage ;;
    *)           echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

setup_colors

# JSON report accumulator
declare -a JSON_SECTIONS=()

log_info() {
  [[ $JSON_OUTPUT -eq 1 ]] && return
  printf "%b[*]%b %s\n" "$GREEN" "$NC" "$1"
}

log_warn() {
  if [[ $CI_MODE -eq 1 ]]; then
    printf "::warning ::%s\n" "$1"
  elif [[ $JSON_OUTPUT -eq 0 ]]; then
    printf "%b[!]%b %s\n" "$YELLOW" "$NC" "$1"
  fi
}

log_error() {
  if [[ $CI_MODE -eq 1 ]]; then
    printf "::error ::%s\n" "$1"
  elif [[ $JSON_OUTPUT -eq 0 ]]; then
    printf "%b[!]%b %s\n" "$RED" "$NC" "$1" >&2
  fi
}

log_section() {
  [[ $JSON_OUTPUT -eq 1 ]] && return
  printf "\n%b══════════════════════════════════════════════════%b\n" "$BOLD" "$NC"
  printf "%b  %s%b\n" "$BOLD" "$1" "$NC"
  printf "%b══════════════════════════════════════════════════%b\n\n" "$BOLD" "$NC"
}

# --------------------------------------------------------------------------
# Scanner 1: gitleaks
# --------------------------------------------------------------------------
run_gitleaks() {
  log_section "Scanner: gitleaks"

  local gitleaks_config="$SCRIPT_DIR/custom-gitleaks.toml"
  local gitleaks_args=("detect" "--source" "$ROOT_DIR" "--no-git" "--exit-code" "0")

  if ! command -v gitleaks &>/dev/null; then
    log_warn "gitleaks not installed — skipping (install: brew install gitleaks)"
    if [[ $JSON_OUTPUT -eq 1 ]]; then
      JSON_SECTIONS+=('{"scanner":"gitleaks","status":"skipped","reason":"not installed","findings":[]}')
    fi
    return
  fi

  if [[ -f "$gitleaks_config" ]]; then
    gitleaks_args+=("--config" "$gitleaks_config")
    log_info "Using custom config: tools/scanning/custom-gitleaks.toml"
  else
    log_info "Custom config not found — using gitleaks built-in rules"
  fi

  local report_file
  report_file=$(mktemp)

  gitleaks_args+=("--report-format" "json" "--report-path" "$report_file")

  gitleaks "${gitleaks_args[@]}" 2>/dev/null || true

  local finding_count=0
  if [[ -f "$report_file" ]] && [[ -s "$report_file" ]]; then
    finding_count=$(python3 -c "import json,sys; d=json.load(open('$report_file')); print(len(d))" 2>/dev/null || echo "0")
  fi

  if [[ "$finding_count" -gt 0 ]]; then
    EXIT_CODE=1
    if [[ $CI_MODE -eq 1 ]]; then
      python3 -c "
import json, sys
for f in json.load(open('$report_file')):
    print(f'::error file={f.get(\"File\",\"?\")},line={f.get(\"StartLine\",0)}::gitleaks: {f.get(\"Description\",\"secret\")} [{f.get(\"RuleID\",\"unknown\")}]')
" 2>/dev/null || true
    elif [[ $JSON_OUTPUT -eq 0 ]]; then
      log_error "gitleaks found $finding_count finding(s)"
      python3 -c "
import json
for f in json.load(open('$report_file')):
    print(f'  {f.get(\"File\",\"?\")}:{f.get(\"StartLine\",\"?\")} — {f.get(\"Description\",\"\")} [{f.get(\"RuleID\",\"\")}]')
" 2>/dev/null || true
    fi
  else
    log_info "gitleaks: clean"
  fi

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    local findings_json="[]"
    if [[ -f "$report_file" ]] && [[ -s "$report_file" ]]; then
      findings_json=$(cat "$report_file")
    fi
    JSON_SECTIONS+=("{\"scanner\":\"gitleaks\",\"status\":\"completed\",\"finding_count\":$finding_count,\"findings\":$findings_json}")
  fi

  rm -f "$report_file"
}

# --------------------------------------------------------------------------
# Scanner 2: Plaintext patterns
# --------------------------------------------------------------------------
run_plaintext_scan() {
  log_section "Scanner: plaintext patterns"

  local scanner="$ROOT_DIR/bootstrap/scripts/check_no_plaintext_secrets.sh"
  if [[ ! -x "$scanner" ]]; then
    log_warn "check_no_plaintext_secrets.sh not found or not executable — skipping"
    if [[ $JSON_OUTPUT -eq 1 ]]; then
      JSON_SECTIONS+=('{"scanner":"plaintext_patterns","status":"skipped","reason":"script not found","findings":[]}')
    fi
    return
  fi

  local output
  local scan_exit=0

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    output=$("$scanner" json 2>/dev/null) || scan_exit=$?
    JSON_SECTIONS+=("{\"scanner\":\"plaintext_patterns\",\"status\":\"completed\",\"exit_code\":$scan_exit,\"findings\":$output}")
  else
    output=$("$scanner" text 2>&1) || scan_exit=$?
    echo "$output"
  fi

  if [[ $scan_exit -ne 0 ]]; then
    EXIT_CODE=1
    if [[ $CI_MODE -eq 1 ]]; then
      echo "$output" | grep -E '^\[!\]' | while IFS= read -r line; do
        printf "::error ::%s\n" "$line"
      done
    fi
  else
    log_info "plaintext scan: clean"
  fi
}

# --------------------------------------------------------------------------
# Scanner 3: Entropy check
# --------------------------------------------------------------------------
run_entropy_check() {
  log_section "Scanner: entropy analysis"

  local entropy_script="$SCRIPT_DIR/entropy_check.sh"
  if [[ ! -x "$entropy_script" ]]; then
    log_warn "entropy_check.sh not found or not executable — skipping"
    if [[ $JSON_OUTPUT -eq 1 ]]; then
      JSON_SECTIONS+=('{"scanner":"entropy","status":"skipped","reason":"script not found","findings":[]}')
    fi
    return
  fi

  local entropy_args=("--threshold" "$ENTROPY_THRESHOLD")
  [[ $VERBOSE -eq 1 ]] && entropy_args+=("--verbose")

  local scan_exit=0

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    local output
    output=$("$entropy_script" "${entropy_args[@]}" --format json 2>/dev/null) || scan_exit=$?
    JSON_SECTIONS+=("{\"scanner\":\"entropy\",\"status\":\"completed\",\"output\":$output}")
  else
    "$entropy_script" "${entropy_args[@]}" --format text 2>&1 || scan_exit=$?
  fi

  if [[ $scan_exit -ne 0 ]]; then
    EXIT_CODE=1
  fi
}

# --------------------------------------------------------------------------
# Scanner 4: File permission audit
# --------------------------------------------------------------------------
run_permission_check() {
  log_section "Scanner: file permission audit"

  local findings=0
  local json_findings=()

  cd "$ROOT_DIR"

  # Find private key files and check permissions
  while IFS= read -r -d '' keyfile; do
    keyfile="${keyfile#./}"
    local perms
    perms=$(stat -f '%A' "$keyfile" 2>/dev/null || stat -c '%a' "$keyfile" 2>/dev/null || echo "unknown")

    if [[ "$perms" != "600" ]] && [[ "$perms" != "400" ]] && [[ "$perms" != "unknown" ]]; then
      findings=$((findings + 1))
      EXIT_CODE=1

      if [[ $CI_MODE -eq 1 ]]; then
        printf "::warning file=%s::Private key has permissive permissions: %s (should be 600 or 400)\n" "$keyfile" "$perms"
      elif [[ $JSON_OUTPUT -eq 0 ]]; then
        log_warn "$keyfile has permissions $perms (should be 600 or 400)"
      fi
      json_findings+=("{\"file\":\"$keyfile\",\"permissions\":\"$perms\",\"expected\":\"600 or 400\"}")

      if [[ $FIX_MODE -eq 1 ]] && [[ $JSON_OUTPUT -eq 0 ]]; then
        printf "  Fix permissions for %s? [y/N] " "$keyfile"
        read -r answer
        if [[ "$answer" =~ ^[Yy] ]]; then
          chmod 600 "$keyfile"
          log_info "Fixed: $keyfile -> 600"
        fi
      fi
    fi
  done < <(find . -type f \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \) -not -path './.git/*' -print0 2>/dev/null)

  if [[ $findings -eq 0 ]]; then
    log_info "permission audit: clean (or no key files found)"
  fi

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    local joined
    joined=$(printf '%s,' "${json_findings[@]+"${json_findings[@]}"}")
    joined="${joined%,}"
    JSON_SECTIONS+=("{\"scanner\":\"permissions\",\"status\":\"completed\",\"finding_count\":$findings,\"findings\":[${joined}]}")
  fi
}

# --------------------------------------------------------------------------
# Scanner 5: .env file audit
# --------------------------------------------------------------------------
run_env_file_check() {
  log_section "Scanner: .env file audit"

  local findings=0
  local json_findings=()

  cd "$ROOT_DIR"

  # Find .env files
  while IFS= read -r -d '' envfile; do
    envfile="${envfile#./}"

    # Check if .env is in .gitignore
    if git check-ignore -q "$envfile" 2>/dev/null; then
      [[ $VERBOSE -eq 1 ]] && log_info "$envfile is gitignored (ok)"
      continue
    fi

    # It's not gitignored — finding
    findings=$((findings + 1))
    EXIT_CODE=1

    if [[ $CI_MODE -eq 1 ]]; then
      printf "::error file=%s::.env file is not in .gitignore — secrets may leak\n" "$envfile"
    elif [[ $JSON_OUTPUT -eq 0 ]]; then
      log_error "$envfile is NOT in .gitignore — potential secret exposure"
    fi
    json_findings+=("{\"file\":\"$envfile\",\"issue\":\"not in .gitignore\"}")

  done < <(find . -name ".env" -o -name ".env.local" -o -name ".env.production" -o -name ".env.staging" | tr '\n' '\0' 2>/dev/null)

  # Check that .gitignore has .env patterns
  if [[ -f "$ROOT_DIR/.gitignore" ]]; then
    if ! grep -qE '^\*?\.env' "$ROOT_DIR/.gitignore"; then
      findings=$((findings + 1))
      log_warn ".gitignore does not contain a .env pattern — add '.env*' or '.env' to .gitignore"
      json_findings+=('{"file":".gitignore","issue":"missing .env pattern"}')
    fi
  fi

  if [[ $findings -eq 0 ]]; then
    log_info ".env audit: clean"
  fi

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    local joined
    joined=$(printf '%s,' "${json_findings[@]+"${json_findings[@]}"}")
    joined="${joined%,}"
    JSON_SECTIONS+=("{\"scanner\":\"env_files\",\"status\":\"completed\",\"finding_count\":$findings,\"findings\":[${joined}]}")
  fi
}

# --------------------------------------------------------------------------
# Fix mode: offer SOPS encryption for detected plaintext secrets
# --------------------------------------------------------------------------
offer_sops_fix() {
  [[ $FIX_MODE -eq 0 ]] && return
  [[ $JSON_OUTPUT -eq 1 ]] && return

  log_section "Fix mode: SOPS encryption"

  if ! command -v sops &>/dev/null; then
    log_warn "sops not installed — cannot offer encryption fixes"
    return
  fi

  cd "$ROOT_DIR"

  # Find unencrypted YAML/JSON in secrets/ directories
  local candidates=()
  while IFS= read -r -d '' f; do
    f="${f#./}"
    [[ "$f" =~ \.enc\. ]] && continue
    if ! head -5 "$f" 2>/dev/null | grep -qE '^sops:|"sops":'; then
      candidates+=("$f")
    fi
  done < <(find . -path '*/secrets/*' \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) -not -path './.git/*' -print0 2>/dev/null)

  if [[ ${#candidates[@]} -eq 0 ]]; then
    log_info "No unencrypted secrets files found to fix"
    return
  fi

  for candidate in "${candidates[@]}"; do
    printf "\n  Found unencrypted secrets file: %b%s%b\n" "$YELLOW" "$candidate" "$NC"
    printf "  Encrypt with SOPS? [y/N] "
    read -r answer
    if [[ "$answer" =~ ^[Yy] ]]; then
      local enc_name="${candidate%.*}.enc.${candidate##*.}"
      if sops encrypt "$candidate" > "$enc_name" 2>/dev/null; then
        log_info "Encrypted: $candidate -> $enc_name"
        printf "  Remove original plaintext file? [y/N] "
        read -r del_answer
        if [[ "$del_answer" =~ ^[Yy] ]]; then
          rm "$candidate"
          log_info "Removed: $candidate"
        fi
      else
        log_error "SOPS encryption failed for $candidate — check .sops.yaml config"
      fi
    fi
  done
}

# --------------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------------
generate_report() {
  mkdir -p "$REPORT_DIR"

  if [[ $JSON_OUTPUT -eq 1 ]]; then
    local joined
    joined=$(printf '%s,' "${JSON_SECTIONS[@]+"${JSON_SECTIONS[@]}"}")
    joined="${joined%,}"
    local report="{\"timestamp\":\"$TIMESTAMP\",\"exit_code\":$EXIT_CODE,\"scanners\":[${joined}]}"
    echo "$report" | python3 -m json.tool 2>/dev/null || echo "$report"

    # Also write to file
    echo "$report" | python3 -m json.tool > "$REPORT_DIR/scan-$TIMESTAMP.json" 2>/dev/null || \
      echo "$report" > "$REPORT_DIR/scan-$TIMESTAMP.json"
  fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
  if [[ $JSON_OUTPUT -eq 0 ]] && [[ $CI_MODE -eq 0 ]]; then
    printf "%b╔══════════════════════════════════════════════════╗%b\n" "$BOLD" "$NC"
    printf "%b║  Secret Scanner — Consolidated Report            ║%b\n" "$BOLD" "$NC"
    printf "%b║  %s                               ║%b\n" "$BOLD" "$TIMESTAMP" "$NC"
    printf "%b╚══════════════════════════════════════════════════╝%b\n" "$BOLD" "$NC"
  fi

  run_gitleaks
  run_plaintext_scan
  run_entropy_check
  run_permission_check
  run_env_file_check
  offer_sops_fix
  generate_report

  if [[ $JSON_OUTPUT -eq 0 ]] && [[ $CI_MODE -eq 0 ]]; then
    log_section "Summary"
    if [[ $EXIT_CODE -eq 0 ]]; then
      printf "%b[PASS]%b All scanners clean\n" "$GREEN" "$NC"
    else
      printf "%b[FAIL]%b Findings detected — review output above\n" "$RED" "$NC"
    fi
  fi

  exit "$EXIT_CODE"
}

main "$@"
