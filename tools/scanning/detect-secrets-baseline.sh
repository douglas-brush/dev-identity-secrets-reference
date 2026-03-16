#!/usr/bin/env bash
set -euo pipefail

# detect-secrets-baseline.sh — Set up Yelp's detect-secrets alongside gitleaks.
# Initializes a .secrets.baseline, configures plugins, and provides audit workflow.
#
# Usage:
#   ./tools/scanning/detect-secrets-baseline.sh [--init|--audit|--scan|--update|--help]
#
# Commands:
#   --init     Install detect-secrets, generate baseline, create config
#   --audit    Interactive audit of the baseline file
#   --scan     Run a scan and compare against baseline
#   --update   Re-scan and update the baseline with new findings
#   --help     Show this help

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly ROOT_DIR

readonly BASELINE_FILE="$ROOT_DIR/.secrets.baseline"
readonly CONFIG_FILE="$ROOT_DIR/.detect-secrets-config.json"
readonly REQUIRED_VERSION="1.4.0"

# Colors (disabled in non-TTY)
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

log_info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$1"; }
log_warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }
log_step()  { printf "${CYAN}[STEP]${NC}  %s\n" "$1"; }

usage() {
  cat <<EOF
${BOLD}detect-secrets-baseline.sh${NC} — Complementary secret scanner setup

${BOLD}USAGE${NC}
  $SCRIPT_NAME [COMMAND]

${BOLD}COMMANDS${NC}
  --init      Install detect-secrets (if needed), generate baseline and config
  --audit     Run interactive audit on the baseline file
  --scan      Scan repo and diff against current baseline
  --update    Re-scan and update the baseline file
  --help      Show this help message

${BOLD}WHY BOTH GITLEAKS AND DETECT-SECRETS?${NC}
  gitleaks excels at regex-based pattern matching for known secret formats.
  detect-secrets adds entropy-based detection, keyword heuristics, and a
  baseline workflow that tracks known/allowed findings over time. Together
  they provide defense-in-depth for secret scanning.

${BOLD}EXAMPLES${NC}
  # First-time setup
  $SCRIPT_NAME --init

  # Audit findings (mark false positives)
  $SCRIPT_NAME --audit

  # Check for new secrets (CI usage)
  $SCRIPT_NAME --scan

  # Update baseline after addressing findings
  $SCRIPT_NAME --update

${BOLD}MAKEFILE INTEGRATION${NC}
  Add to your Makefile:

    detect-secrets-init:    tools/scanning/detect-secrets-baseline.sh --init
    detect-secrets-audit:   tools/scanning/detect-secrets-baseline.sh --audit
    detect-secrets-scan:    tools/scanning/detect-secrets-baseline.sh --scan
    detect-secrets-update:  tools/scanning/detect-secrets-baseline.sh --update
EOF
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

check_python() {
  if command -v python3 &>/dev/null; then
    echo "python3"
  elif command -v python &>/dev/null; then
    echo "python"
  else
    log_error "Python 3 is required but not found."
    log_error "Install Python 3: https://www.python.org/downloads/"
    exit 1
  fi
}

check_detect_secrets() {
  if command -v detect-secrets &>/dev/null; then
    local version
    version="$(detect-secrets --version 2>/dev/null || echo "unknown")"
    log_info "detect-secrets found: $version"
    return 0
  fi
  return 1
}

install_detect_secrets() {
  local python_cmd
  python_cmd="$(check_python)"

  log_warn "detect-secrets is not installed."
  printf "${YELLOW}Install detect-secrets via pip? [y/N]${NC} "
  read -r response
  if [[ "$response" =~ ^[Yy]$ ]]; then
    log_step "Installing detect-secrets >=${REQUIRED_VERSION}..."
    "$python_cmd" -m pip install "detect-secrets>=${REQUIRED_VERSION}" --quiet
    if check_detect_secrets; then
      log_info "detect-secrets installed successfully."
    else
      log_error "Installation failed. Try: pip install detect-secrets"
      exit 1
    fi
  else
    log_error "detect-secrets is required. Install manually: pip install detect-secrets"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------

generate_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    log_info "Config already exists: $CONFIG_FILE"
    return 0
  fi

  log_step "Generating detect-secrets config: $CONFIG_FILE"

  cat > "$CONFIG_FILE" <<'CONFIGEOF'
{
  "comment": "detect-secrets configuration for dev-identity-secrets-reference",
  "plugins_used": [
    { "name": "ArtifactoryDetector" },
    { "name": "AWSKeyDetector" },
    { "name": "AzureStorageKeyDetector" },
    { "name": "BasicAuthDetector" },
    { "name": "CloudantDetector" },
    { "name": "DiscordBotTokenDetector" },
    { "name": "GitHubTokenDetector" },
    { "name": "HexHighEntropyString", "limit": 3.0 },
    { "name": "Base64HighEntropyString", "limit": 4.5 },
    { "name": "IbmCloudIamDetector" },
    { "name": "IbmCosHmacDetector" },
    { "name": "JwtTokenDetector" },
    { "name": "KeywordDetector", "keyword_exclude": "" },
    { "name": "MailchimpDetector" },
    { "name": "NpmDetector" },
    { "name": "PrivateKeyDetector" },
    { "name": "SendGridDetector" },
    { "name": "SlackDetector" },
    { "name": "SoftlayerDetector" },
    { "name": "SquareOAuthDetector" },
    { "name": "StripeDetector" },
    { "name": "TwilioKeyDetector" }
  ],
  "filters_used": [
    { "path": "detect_secrets.filters.allowlist_filter" },
    {
      "path": "detect_secrets.filters.heuristic_filter",
      "model": {
        "limit": 3.7
      }
    },
    { "path": "detect_secrets.filters.regex_filter",
      "pattern": [
        "EXAMPLE",
        "example\\.com",
        "placeholder",
        "changeme",
        "your[-_]?(api[-_]?key|token|secret|password)",
        "insert[-_]?here",
        "TODO",
        "FIXME"
      ]
    }
  ],
  "exclude": {
    "files": "(\\.secrets\\.baseline(\\.example)?|.*\\.sops\\.(yaml|yml|json|env)|.*\\.enc(\\.yaml|\\.json)?|\\.git/.*|node_modules/.*|vendor/.*|\\.venv/.*|logs/.*|evidence/.*)",
    "lines": "(pragma: allowlist secret|nosec|noqa|detect-secrets:ignore)"
  },
  "word_list": {
    "file": null,
    "hash_type": "sha256"
  },
  "generated_at": ""
}
CONFIGEOF

  log_info "Config created: $CONFIG_FILE"
}

# ---------------------------------------------------------------------------
# Baseline operations
# ---------------------------------------------------------------------------

init_baseline() {
  log_step "Scanning repository to generate baseline..."

  cd "$ROOT_DIR"

  local scan_args=(
    scan
    --all-files
  )

  if [[ -f "$CONFIG_FILE" ]]; then
    scan_args+=(--list-all-plugins)
    # Use the config's exclude patterns
    log_info "Using config: $CONFIG_FILE"
  fi

  # Build exclude patterns matching the config
  detect-secrets scan \
    --all-files \
    --exclude-files '(\.secrets\.baseline(\.example)?|.*\.sops\.(yaml|yml|json|env)|.*\.enc(\.(yaml|json))?|\.git/.*|node_modules/.*|vendor/.*|\.venv/.*|logs/.*|evidence/.*)' \
    --exclude-lines '(pragma: allowlist secret|nosec|noqa|detect-secrets:ignore)' \
    --base64-limit 4.5 \
    --hex-limit 3.0 \
    > "$BASELINE_FILE"

  local finding_count
  finding_count="$(python3 -c "
import json, sys
with open('$BASELINE_FILE') as f:
    data = json.load(f)
total = sum(len(v) for v in data.get('results', {}).values())
print(total)
" 2>/dev/null || echo "unknown")"

  log_info "Baseline created: $BASELINE_FILE"
  log_info "Total findings: $finding_count"

  if [[ "$finding_count" != "0" ]] && [[ "$finding_count" != "unknown" ]]; then
    log_warn ""
    log_warn "Run '$SCRIPT_NAME --audit' to review findings and mark false positives."
    log_warn "This is a one-time process — audited findings are tracked in the baseline."
  fi
}

audit_baseline() {
  if [[ ! -f "$BASELINE_FILE" ]]; then
    log_error "No baseline file found. Run '$SCRIPT_NAME --init' first."
    exit 1
  fi

  log_step "Starting interactive audit..."
  log_info ""
  log_info "For each finding, you will be asked:"
  log_info "  y = yes, this is a real secret (true positive)"
  log_info "  n = no, this is a false positive (will be marked as safe)"
  log_info "  s = skip for now"
  log_info "  q = quit audit"
  log_info ""

  cd "$ROOT_DIR"
  detect-secrets audit "$BASELINE_FILE"

  log_info "Audit complete. Baseline updated in place."
}

scan_against_baseline() {
  if [[ ! -f "$BASELINE_FILE" ]]; then
    log_error "No baseline file found. Run '$SCRIPT_NAME --init' first."
    exit 1
  fi

  log_step "Scanning for new secrets not in baseline..."

  cd "$ROOT_DIR"

  local exit_code=0
  detect-secrets scan \
    --all-files \
    --baseline "$BASELINE_FILE" \
    --exclude-files '(\.secrets\.baseline(\.example)?|.*\.sops\.(yaml|yml|json|env)|.*\.enc(\.(yaml|json))?|\.git/.*|node_modules/.*|vendor/.*|\.venv/.*|logs/.*|evidence/.*)' \
    --exclude-lines '(pragma: allowlist secret|nosec|noqa|detect-secrets:ignore)' \
    --base64-limit 4.5 \
    --hex-limit 3.0 \
    || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    log_info "No new secrets detected. All findings are in the baseline."
  else
    log_error "New secrets detected! Review findings and either:"
    log_error "  1. Remove the secret and rotate it"
    log_error "  2. Run '$SCRIPT_NAME --update' then '$SCRIPT_NAME --audit' to mark as false positive"
    exit 1
  fi
}

update_baseline() {
  if [[ ! -f "$BASELINE_FILE" ]]; then
    log_warn "No existing baseline. Running --init instead."
    init_baseline
    return
  fi

  log_step "Updating baseline with current scan results..."

  cd "$ROOT_DIR"

  detect-secrets scan \
    --all-files \
    --baseline "$BASELINE_FILE" \
    --exclude-files '(\.secrets\.baseline(\.example)?|.*\.sops\.(yaml|yml|json|env)|.*\.enc(\.(yaml|json))?|\.git/.*|node_modules/.*|vendor/.*|\.venv/.*|logs/.*|evidence/.*)' \
    --exclude-lines '(pragma: allowlist secret|nosec|noqa|detect-secrets:ignore)' \
    --base64-limit 4.5 \
    --hex-limit 3.0 \
    --update "$BASELINE_FILE" \
    || true

  log_info "Baseline updated: $BASELINE_FILE"
  log_warn "Run '$SCRIPT_NAME --audit' to review any new findings."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  if [[ $# -eq 0 ]]; then
    usage
    exit 0
  fi

  case "${1:-}" in
    --init)
      log_info "=== detect-secrets initialization ==="
      if ! check_detect_secrets; then
        install_detect_secrets
      fi
      generate_config
      init_baseline

      log_info ""
      log_info "=== Setup complete ==="
      log_info ""
      log_info "Suggested Makefile targets:"
      log_info ""
      printf "  ${CYAN}detect-secrets-init:${NC}    tools/scanning/detect-secrets-baseline.sh --init\n"
      printf "  ${CYAN}detect-secrets-audit:${NC}   tools/scanning/detect-secrets-baseline.sh --audit\n"
      printf "  ${CYAN}detect-secrets-scan:${NC}    tools/scanning/detect-secrets-baseline.sh --scan\n"
      printf "  ${CYAN}detect-secrets-update:${NC}  tools/scanning/detect-secrets-baseline.sh --update\n"
      log_info ""
      log_info "For pre-commit integration, add to .pre-commit-config.yaml:"
      log_info ""
      printf "  ${CYAN}- repo: https://github.com/Yelp/detect-secrets${NC}\n"
      printf "  ${CYAN}  rev: v1.4.0${NC}\n"
      printf "  ${CYAN}  hooks:${NC}\n"
      printf "  ${CYAN}    - id: detect-secrets${NC}\n"
      printf "  ${CYAN}      args: ['--baseline', '.secrets.baseline']${NC}\n"
      ;;
    --audit)
      if ! check_detect_secrets; then
        log_error "detect-secrets not installed. Run '$SCRIPT_NAME --init' first."
        exit 1
      fi
      audit_baseline
      ;;
    --scan)
      if ! check_detect_secrets; then
        log_error "detect-secrets not installed. Run '$SCRIPT_NAME --init' first."
        exit 1
      fi
      scan_against_baseline
      ;;
    --update)
      if ! check_detect_secrets; then
        log_error "detect-secrets not installed. Run '$SCRIPT_NAME --init' first."
        exit 1
      fi
      update_baseline
      ;;
    --help|-h)
      usage
      ;;
    *)
      log_error "Unknown command: $1"
      usage
      exit 1
      ;;
  esac
}

main "$@"
