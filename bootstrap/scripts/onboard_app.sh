#!/usr/bin/env bash
set -euo pipefail

# Application Onboarding — creates Vault policy, K8s service account, and secret delivery resources.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

usage() {
  cat <<EOF
Usage: onboard_app.sh <app-name> <environment> [options]

Arguments:
  app-name       Application name (e.g., my-service)
  environment    Target environment (dev, staging, prod)

Options:
  --delivery     Secret delivery method: eso|csi|agent (default: eso)
  --namespace    Kubernetes namespace (default: <app-name>)
  --db-role      Create dynamic database role (default: false)
  --cert         Create cert-manager Certificate (default: false)
  --dry-run      Print resources without applying (default: false)
  -h, --help     Show this help

Examples:
  onboard_app.sh my-api dev --delivery eso --db-role --cert
  onboard_app.sh my-api prod --delivery csi --dry-run
EOF
  exit 0
}

# Defaults
DELIVERY="eso"
NAMESPACE=""
DB_ROLE=false
CERT=false
DRY_RUN=false

# Parse args
[[ $# -lt 2 ]] && usage
APP_NAME="$1"; shift
ENV="$1"; shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --delivery) DELIVERY="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --db-role) DB_ROLE=true; shift ;;
    --cert) CERT=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ -z "$NAMESPACE" ]] && NAMESPACE="$APP_NAME"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Application Onboarding: $APP_NAME${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""
info "Environment: $ENV"
info "Namespace:   $NAMESPACE"
info "Delivery:    $DELIVERY"
info "DB Role:     $DB_ROLE"
info "Certificate: $CERT"
info "Dry Run:     $DRY_RUN"
echo ""

# --- Vault Policy ---
POLICY_NAME="${ENV}-${APP_NAME}"
POLICY_CONTENT=$(cat <<POLICY
# Auto-generated policy for $APP_NAME in $ENV
# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)

path "kv/data/$ENV/apps/$APP_NAME/*" {
  capabilities = ["read", "list"]
}

path "database/creds/$ENV-$APP_NAME" {
  capabilities = ["read"]
}

path "pki_int/sign/$ENV-services" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/$APP_NAME" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/$APP_NAME" {
  capabilities = ["create", "update"]
}
POLICY
)

info "Vault Policy ($POLICY_NAME):"
echo "$POLICY_CONTENT" | sed 's/^/  /'

if [[ "$DRY_RUN" == "false" ]] && command -v vault &>/dev/null && vault token lookup &>/dev/null 2>&1; then
  echo "$POLICY_CONTENT" | vault policy write "$POLICY_NAME" - && ok "Vault policy created: $POLICY_NAME"
else
  [[ "$DRY_RUN" == "true" ]] && info "[dry-run] Would create Vault policy: $POLICY_NAME"
fi

# --- Kubernetes Resources ---
echo ""

# Namespace
NS_YAML=$(cat <<NSEOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
  labels:
    app: $APP_NAME
    env: $ENV
    managed-by: dev-identity-secrets
NSEOF
)

# Service Account
SA_YAML=$(cat <<SAEOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $APP_NAME
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
    env: $ENV
automountServiceAccountToken: false
SAEOF
)

info "Kubernetes Service Account:"
echo "$SA_YAML" | sed 's/^/  /'

# Delivery Resource
case "$DELIVERY" in
  eso)
    DELIVERY_YAML=$(cat <<ESOEOF
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ${APP_NAME}-config
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
    env: $ENV
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: vault-backend
  target:
    name: ${APP_NAME}-config
    creationPolicy: Owner
  data:
    - secretKey: CONFIG
      remoteRef:
        key: $ENV/apps/$APP_NAME/config
ESOEOF
    )
    ;;
  csi)
    DELIVERY_YAML=$(cat <<CSIEOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: ${APP_NAME}-vault
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
    env: $ENV
spec:
  provider: vault
  parameters:
    roleName: $APP_NAME
    vaultAddress: \${VAULT_ADDR}
    objects: |
      - objectName: "config"
        secretPath: "kv/data/$ENV/apps/$APP_NAME/config"
        secretKey: "data"
CSIEOF
    )
    ;;
  agent)
    DELIVERY_YAML="# Vault Agent sidecar configuration — add vault.hashicorp.com annotations to your Deployment"
    ;;
esac

echo ""
info "Secret Delivery ($DELIVERY):"
echo "$DELIVERY_YAML" | sed 's/^/  /'

# Certificate
if [[ "$CERT" == "true" ]]; then
  CERT_YAML=$(cat <<CERTEOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ${APP_NAME}-tls
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
    env: $ENV
spec:
  secretName: ${APP_NAME}-tls
  dnsNames:
    - ${APP_NAME}.${NAMESPACE}.svc.cluster.local
  issuerRef:
    kind: ClusterIssuer
    name: vault-issuer
  privateKey:
    rotationPolicy: Always
    algorithm: ECDSA
    size: 256
  duration: 72h
  renewBefore: 24h
CERTEOF
  )
  echo ""
  info "Certificate:"
  echo "$CERT_YAML" | sed 's/^/  /'
fi

# Apply if not dry-run
if [[ "$DRY_RUN" == "false" ]] && command -v kubectl &>/dev/null; then
  echo "$NS_YAML" | kubectl apply -f - 2>/dev/null && ok "Namespace created"
  echo "$SA_YAML" | kubectl apply -f - 2>/dev/null && ok "Service account created"
  echo "$DELIVERY_YAML" | kubectl apply -f - 2>/dev/null && ok "Secret delivery resource created"
  [[ "$CERT" == "true" ]] && echo "$CERT_YAML" | kubectl apply -f - 2>/dev/null && ok "Certificate created"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Onboarding Summary                              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  App:        $APP_NAME${NC}"
echo -e "${GREEN}║  Env:        $ENV${NC}"
echo -e "${GREEN}║  Namespace:  $NAMESPACE${NC}"
echo -e "${GREEN}║  Policy:     $POLICY_NAME${NC}"
echo -e "${GREEN}║  Delivery:   $DELIVERY${NC}"
echo -e "${GREEN}║  DB Role:    $DB_ROLE${NC}"
echo -e "${GREEN}║  Cert:       $CERT${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
