#!/usr/bin/env bash
set -euo pipefail

# Fetch development environment secrets from Vault.
# Writes secrets to temporary files with 0600 permissions.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

APP_NAME="${1:-demo-app}"
ENV="${2:-dev}"
TARGET_DIR="${3:-/tmp/dev-secrets-$$}"
FORMAT="${4:-env}"  # env or json

# Validate Vault connectivity
vault token lookup &>/dev/null 2>&1 || die "No valid Vault token. Run vault_login_oidc.sh first."

# Setup
mkdir -p "$TARGET_DIR"
chmod 0700 "$TARGET_DIR"

# Cleanup trap
cleanup() {
  if [[ -d "$TARGET_DIR" ]]; then
    info "Cleaning up $TARGET_DIR..."
    find "$TARGET_DIR" -type f -exec shred -u {} \; 2>/dev/null || rm -rf "$TARGET_DIR"
  fi
}
trap cleanup EXIT INT TERM

info "Fetching secrets for $APP_NAME ($ENV)..."

# KV Secrets
KV_PATH="kv/data/$ENV/apps/$APP_NAME/config"
if vault kv get -format=json "$KV_PATH" &>/dev/null 2>&1; then
  case "$FORMAT" in
    env)
      vault kv get -format=json "$KV_PATH" | \
        jq -r '.data.data | to_entries[] | "export \(.key)=\u0027\(.value)\u0027"' \
        > "$TARGET_DIR/app.env"
      ;;
    json)
      vault kv get -format=json "$KV_PATH" | jq '.data.data' > "$TARGET_DIR/app.json"
      ;;
  esac
  chmod 0600 "$TARGET_DIR/app.$FORMAT"
  ok "App config -> $TARGET_DIR/app.$FORMAT"
else
  warn "No KV secrets found at $KV_PATH"
fi

# Dynamic Database Credentials
DB_ROLE="$ENV-$APP_NAME"
if vault read -format=json "database/creds/$DB_ROLE" &>/dev/null 2>&1; then
  CREDS=$(vault read -format=json "database/creds/$DB_ROLE")
  USERNAME=$(echo "$CREDS" | jq -r '.data.username')
  PASSWORD=$(echo "$CREDS" | jq -r '.data.password')
  LEASE_ID=$(echo "$CREDS" | jq -r '.lease_id')
  LEASE_TTL=$(echo "$CREDS" | jq -r '.lease_duration')

  case "$FORMAT" in
    env)
      cat > "$TARGET_DIR/db.env" <<DBEOF
export DB_USERNAME='$USERNAME'
export DB_PASSWORD='$PASSWORD'
export DB_LEASE_ID='$LEASE_ID'
# Lease expires in ${LEASE_TTL}s
DBEOF
      ;;
    json)
      echo "$CREDS" | jq '{username: .data.username, password: .data.password, lease_id: .lease_id, lease_duration: .lease_duration}' > "$TARGET_DIR/db.json"
      ;;
  esac
  chmod 0600 "$TARGET_DIR/db.$FORMAT"
  ok "Dynamic DB creds -> $TARGET_DIR/db.$FORMAT (TTL: ${LEASE_TTL}s)"
else
  warn "No database role $DB_ROLE available"
fi

echo ""
ok "Secrets written to $TARGET_DIR/"
info "To load: source $TARGET_DIR/app.env && source $TARGET_DIR/db.env"
warn "Files will be securely deleted when this shell exits."
