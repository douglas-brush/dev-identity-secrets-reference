#!/usr/bin/env bash

#!/usr/bin/env bash
set -euo pipefail

# Vault OIDC Login — authenticate to Vault using organizational SSO.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_AUTH_PATH:=oidc}"
: "${VAULT_ROLE:=developer}"

RENEW=false
[[ "${1:-}" == "--renew" ]] && RENEW=true

# Check for existing valid token
if vault token lookup &>/dev/null 2>&1; then
  TTL=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.ttl // 0')
  POLICIES=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.policies | join(", ")')
  DISPLAY_NAME=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.display_name // "unknown"')

  if [[ "$RENEW" == "true" ]]; then
    info "Renewing existing token..."
    if vault token renew &>/dev/null 2>&1; then
      NEW_TTL=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.ttl // 0')
      ok "Token renewed (TTL: ${NEW_TTL}s)"
      exit 0
    else
      warn "Token renewal failed, re-authenticating..."
    fi
  elif [[ "$TTL" -gt 300 ]]; then
    ok "Already authenticated as $DISPLAY_NAME"
    info "TTL: ${TTL}s | Policies: $POLICIES"
    info "Use --renew to extend token lifetime"
    exit 0
  else
    warn "Token expiring in ${TTL}s, re-authenticating..."
  fi
fi

info "Logging into Vault at $VAULT_ADDR"
info "Role: $VAULT_ROLE | Auth path: $VAULT_AUTH_PATH"
info "Your browser will open for SSO authentication..."
echo ""

if vault login -method=oidc -path="$VAULT_AUTH_PATH" role="$VAULT_ROLE"; then
  echo ""
  ok "Authentication successful"
  TTL=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.ttl // 0')
  POLICIES=$(vault token lookup -format=json 2>/dev/null | jq -r '.data.policies | join(", ")')
  info "TTL: ${TTL}s"
  info "Policies: $POLICIES"
else
  die "Authentication failed. Check VAULT_ADDR, role, and IdP configuration."
fi
