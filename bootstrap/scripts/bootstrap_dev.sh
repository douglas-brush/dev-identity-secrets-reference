#!/usr/bin/env bash
set -euo pipefail

# Dev Identity & Secrets — Developer Workstation Bootstrap
# Detects OS, validates tools, authenticates, retrieves secrets, configures environment.

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[✗]${NC} $*"; }
die()   { fail "$*"; exit 1; }

# --- Configuration ---
: "${VAULT_ADDR:=}"
: "${VAULT_ROLE:=developer}"
: "${VAULT_AUTH_PATH:=oidc}"
: "${APP_NAME:=$(basename "$PWD")}"
: "${ENV:=dev}"
: "${SECRETS_DIR:=/tmp/dev-secrets-$$}"

# --- Cleanup trap ---
cleanup() {
  if [[ -d "$SECRETS_DIR" ]]; then
    info "Cleaning up temporary secrets..."
    find "$SECRETS_DIR" -type f -exec shred -u {} \; 2>/dev/null || rm -rf "$SECRETS_DIR"
    ok "Temporary secrets cleaned"
  fi
}
trap cleanup EXIT INT TERM

# --- OS Detection ---
detect_os() {
  case "$(uname -s)" in
    Darwin) OS="macos"; PKG_MGR="brew" ;;
    Linux)
      if command -v apt-get &>/dev/null; then OS="linux-debian"; PKG_MGR="apt-get"
      elif command -v yum &>/dev/null; then OS="linux-rhel"; PKG_MGR="yum"
      elif command -v apk &>/dev/null; then OS="linux-alpine"; PKG_MGR="apk"
      else OS="linux-unknown"; PKG_MGR="unknown"
      fi ;;
    *) die "Unsupported OS: $(uname -s)" ;;
  esac
  ok "Detected OS: $OS (package manager: $PKG_MGR)"
}

# --- Dependency Check ---
REQUIRED_TOOLS=(vault sops jq git)
OPTIONAL_TOOLS=(age kubectl helm yq gitleaks shellcheck opa)

check_tools() {
  info "Checking required tools..."
  local missing=()
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool $(command -v "$tool")"
    else
      fail "$tool — NOT FOUND"
      missing+=("$tool")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}. Install them first."
  fi

  info "Checking optional tools..."
  for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
      ok "$tool"
    else
      warn "$tool — not found (optional)"
    fi
  done
}

# --- Pre-commit Setup ---
setup_hooks() {
  info "Setting up pre-commit hooks..."
  if command -v pre-commit &>/dev/null; then
    if [[ -f .pre-commit-config.yaml ]]; then
      if pre-commit install --allow-missing-config 2>/dev/null; then
        ok "Pre-commit hooks installed"
      else
        warn "Pre-commit install failed (non-fatal)"
      fi
    else
      warn "No .pre-commit-config.yaml found"
    fi
  else
    warn "pre-commit not installed — run: pip install pre-commit"
  fi
}

# --- Vault Authentication ---
vault_auth() {
  if [[ -z "$VAULT_ADDR" ]]; then
    warn "VAULT_ADDR not set — skipping Vault authentication"
    warn "Set VAULT_ADDR to enable centralized secret retrieval"
    return 0
  fi

  info "Authenticating to Vault at $VAULT_ADDR..."

  # Check for existing valid token
  if vault token lookup &>/dev/null 2>&1; then
    local ttl
    ttl=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.ttl // 0')
    if [[ "$ttl" -gt 300 ]]; then
      ok "Existing Vault token valid (TTL: ${ttl}s)"
      return 0
    fi
    warn "Existing token expiring soon, re-authenticating..."
  fi

  # OIDC login
  info "Starting OIDC authentication (browser will open)..."
  if vault login -method=oidc -path="$VAULT_AUTH_PATH" role="$VAULT_ROLE" 2>/dev/null; then
    ok "Vault authentication successful"
    local policies
    policies=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.policies | join(", ")')
    info "Policies: $policies"
  else
    fail "Vault authentication failed"
    warn "Try: vault login -method=oidc -path=$VAULT_AUTH_PATH role=$VAULT_ROLE"
    return 1
  fi
}

# --- Secret Retrieval ---
fetch_secrets() {
  if [[ -z "$VAULT_ADDR" ]] || ! vault token lookup &>/dev/null 2>&1; then
    warn "No valid Vault session — skipping secret retrieval"
    return 0
  fi

  info "Retrieving secrets for $APP_NAME ($ENV)..."
  mkdir -p "$SECRETS_DIR"
  chmod 0700 "$SECRETS_DIR"

  # KV secrets
  local kv_path="kv/data/$ENV/apps/$APP_NAME/config"
  if vault kv get -format=json "$kv_path" &>/dev/null 2>&1; then
    vault kv get -format=json "$kv_path" | jq -r '.data.data | to_entries[] | "export \(.key)=\"\(.value)\""' > "$SECRETS_DIR/app.env"
    chmod 0600 "$SECRETS_DIR/app.env"
    ok "KV secrets written to $SECRETS_DIR/app.env"
  else
    warn "No KV secrets at $kv_path (might not exist yet)"
  fi

  # Dynamic DB credentials
  local db_role="$ENV-$APP_NAME"
  if vault read -format=json "database/creds/$db_role" &>/dev/null 2>&1; then
    vault read -format=json "database/creds/$db_role" | jq -r '"export DB_USERNAME=\"" + .data.username + "\"\nexport DB_PASSWORD=\"" + .data.password + "\""' > "$SECRETS_DIR/db.env"
    chmod 0600 "$SECRETS_DIR/db.env"
    ok "Dynamic DB credentials written to $SECRETS_DIR/db.env"
  else
    warn "No dynamic DB role $db_role (might not exist yet)"
  fi

  echo ""
  info "To load secrets into your shell:"
  echo "  source $SECRETS_DIR/app.env"
  echo "  source $SECRETS_DIR/db.env"
  echo ""
  warn "Secrets will be cleaned up when this shell exits."
}

# --- SOPS Validation ---
check_sops() {
  info "Checking SOPS configuration..."
  if [[ -f .sops.yaml ]]; then
    ok ".sops.yaml found"
    local rules
    rules=$(grep -c "path_regex" .sops.yaml 2>/dev/null || echo 0)
    info "  $rules creation rules defined"
  else
    warn ".sops.yaml not found — SOPS encryption not configured"
  fi
}

# --- .gitignore Validation ---
check_gitignore() {
  info "Validating .gitignore coverage..."
  local checks=(".env" "*.pem" "*.key" "*.p12" "*.token" "*.secret" ".vault-token")
  local missing=()
  if [[ -f .gitignore ]]; then
    for pattern in "${checks[@]}"; do
      if ! grep -qF "$pattern" .gitignore 2>/dev/null; then
        missing+=("$pattern")
      fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
      warn "Missing .gitignore patterns: ${missing[*]}"
    else
      ok ".gitignore covers all sensitive patterns"
    fi
  else
    fail ".gitignore not found"
  fi
}

# --- Main ---
main() {
  echo ""
  echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║  Dev Identity & Secrets — Workstation Bootstrap  ║${NC}"
  echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
  echo ""

  detect_os
  check_tools
  setup_hooks
  check_sops
  check_gitignore
  vault_auth
  fetch_secrets

  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  Bootstrap complete                  ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
}

# --- Help ---
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
  echo "Usage: bootstrap_dev.sh [OPTIONS]"
  echo ""
  echo "Environment variables:"
  echo "  VAULT_ADDR       Vault server URL"
  echo "  VAULT_ROLE       Vault OIDC role (default: developer)"
  echo "  VAULT_AUTH_PATH  Vault OIDC auth path (default: oidc)"
  echo "  APP_NAME         Application name (default: directory name)"
  echo "  ENV              Environment (default: dev)"
  echo ""
  echo "Options:"
  echo "  -h, --help       Show this help"
  exit 0
fi

main "$@"
