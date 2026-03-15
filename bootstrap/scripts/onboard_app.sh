#!/usr/bin/env bash

#!/usr/bin/env bash
set -euo pipefail

# Application Onboarding — creates Vault policy and generates platform-specific
# secret delivery resources (Kubernetes, ECS, Lambda, etc.).
# Vault policy creation is platform-agnostic. Platform-specific manifests are
# generated for review and can optionally be applied when the target platform
# CLI is available.

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
  --platform     Target platform: k8s|ecs|lambda|none (default: none)
  --delivery     Secret delivery method (platform-dependent):
                   k8s:    eso|csi|agent
                   ecs:    env|sidecar
                   lambda: env|extension
                   none:   vault-only (Vault policy only, no delivery resources)
  --namespace    Kubernetes namespace (default: <app-name>, k8s only)
  --db-role      Create dynamic database role (default: false)
  --cert         Generate cert-manager Certificate manifest (default: false, k8s only)
  --apply        Apply generated resources (default: false, outputs manifests only)
  --output-dir   Write manifests to directory instead of stdout
  --dry-run      Alias for default behavior (print without applying)
  -h, --help     Show this help

Examples:
  onboard_app.sh my-api dev                                    # Vault policy only
  onboard_app.sh my-api dev --platform k8s --delivery eso      # K8s + ESO manifests
  onboard_app.sh my-api prod --platform k8s --delivery csi     # K8s + CSI manifests
  onboard_app.sh my-api dev --platform ecs --delivery env      # ECS env injection
  onboard_app.sh my-api dev --platform k8s --delivery eso --apply  # Generate and apply
  onboard_app.sh my-api dev --output-dir ./manifests           # Write to files
EOF
  exit 0
}

# Defaults
PLATFORM="none"
DELIVERY=""
NAMESPACE=""
DB_ROLE=false
CERT=false
APPLY=false
OUTPUT_DIR=""
# Parse args
[[ $# -lt 2 ]] && usage
APP_NAME="$1"; shift
ENV="$1"; shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --delivery) DELIVERY="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --db-role) DB_ROLE=true; shift ;;
    --cert) CERT=true; shift ;;
    --apply) APPLY=true; shift ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --dry-run) shift ;;  # Alias for default behavior (manifests only, no apply)
    -h|--help) usage ;;
    *) die "Unknown option: $1" ;;
  esac
done

# Set platform-specific defaults
case "$PLATFORM" in
  k8s)
    [[ -z "$NAMESPACE" ]] && NAMESPACE="$APP_NAME"
    [[ -z "$DELIVERY" ]] && DELIVERY="eso"
    ;;
  ecs)
    [[ -z "$DELIVERY" ]] && DELIVERY="env"
    ;;
  lambda)
    [[ -z "$DELIVERY" ]] && DELIVERY="env"
    ;;
  none)
    [[ -z "$DELIVERY" ]] && DELIVERY="vault-only"
    ;;
  *)
    die "Unknown platform: $PLATFORM (supported: k8s, ecs, lambda, none)"
    ;;
esac

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Application Onboarding: $APP_NAME${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
echo ""
info "Environment: $ENV"
info "Platform:    $PLATFORM"
info "Delivery:    $DELIVERY"
[[ "$PLATFORM" == "k8s" ]] && info "Namespace:   $NAMESPACE"
info "DB Role:     $DB_ROLE"
[[ "$PLATFORM" == "k8s" ]] && info "Certificate: $CERT"
info "Apply:       $APPLY"
[[ -n "$OUTPUT_DIR" ]] && info "Output dir:  $OUTPUT_DIR"
echo ""

# --- Helper: write or display manifest ---
output_manifest() {
  local filename="$1"
  local content="$2"
  local label="$3"

  info "${label}:"
  echo "$content" | sed 's/^/  /'

  if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
    echo "$content" > "${OUTPUT_DIR}/${filename}"
    ok "Written to ${OUTPUT_DIR}/${filename}"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Vault Policy (platform-agnostic — always generated)
# ═══════════════════════════════════════════════════════════════════════════════

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

output_manifest "vault-policy-${POLICY_NAME}.hcl" "$POLICY_CONTENT" "Vault Policy ($POLICY_NAME)"

if [[ "$APPLY" == "true" ]] && command -v vault &>/dev/null && vault token lookup &>/dev/null 2>&1; then
  echo "$POLICY_CONTENT" | vault policy write "$POLICY_NAME" - && ok "Vault policy created: $POLICY_NAME"
elif [[ "$APPLY" == "true" ]]; then
  warn "Vault not available — policy not applied (manifests still generated)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Platform-specific resources
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$PLATFORM" == "k8s" ]]; then
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

  output_manifest "namespace.yaml" "$NS_YAML" "Kubernetes Namespace"
  output_manifest "service-account.yaml" "$SA_YAML" "Kubernetes Service Account"

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
  output_manifest "secret-delivery-${DELIVERY}.yaml" "$DELIVERY_YAML" "Secret Delivery ($DELIVERY)"

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
    output_manifest "certificate.yaml" "$CERT_YAML" "Certificate"
  fi

  # Apply K8s resources if requested
  if [[ "$APPLY" == "true" ]] && command -v kubectl &>/dev/null; then
    echo ""
    info "Applying Kubernetes resources..."
    echo "$NS_YAML" | kubectl apply -f - 2>/dev/null && ok "Namespace applied"
    echo "$SA_YAML" | kubectl apply -f - 2>/dev/null && ok "Service account applied"
    echo "$DELIVERY_YAML" | kubectl apply -f - 2>/dev/null && ok "Secret delivery resource applied"
    [[ "$CERT" == "true" ]] && echo "$CERT_YAML" | kubectl apply -f - 2>/dev/null && ok "Certificate applied"
  elif [[ "$APPLY" == "true" ]]; then
    warn "kubectl not available — Kubernetes resources not applied"
  fi

elif [[ "$PLATFORM" == "ecs" ]]; then
  # --- ECS guidance ---
  echo ""
  ECS_GUIDANCE=$(cat <<ECSEOF
# ECS Secret Delivery for $APP_NAME ($ENV)
#
# Delivery method: $DELIVERY
#
# Recommended approach:
#   1. Store secrets in Vault at: kv/data/$ENV/apps/$APP_NAME/config
#   2. Use one of these delivery methods:
#
#   env (environment variables):
#     - Use Vault Agent as an ECS sidecar container to inject secrets
#       as environment variables into the task definition.
#     - Alternatively, use AWS Secrets Manager as an intermediary:
#       sync Vault secrets to ASM via vault-secrets-sync, then
#       reference ASM ARNs in your ECS task definition.
#
#   sidecar:
#     - Deploy Vault Agent as a sidecar container in your task definition.
#     - Mount a shared volume for secret file delivery.
#     - Configure Vault Agent template to render secrets to the shared volume.
#
# IAM role for ECS task: ${ENV}-${APP_NAME}-task-role
# Vault auth method: aws (IAM-based authentication)
ECSEOF
  )
  output_manifest "ecs-guidance.md" "$ECS_GUIDANCE" "ECS Secret Delivery Guidance"

elif [[ "$PLATFORM" == "lambda" ]]; then
  # --- Lambda guidance ---
  echo ""
  LAMBDA_GUIDANCE=$(cat <<LAMEOF
# Lambda Secret Delivery for $APP_NAME ($ENV)
#
# Delivery method: $DELIVERY
#
# Recommended approach:
#   1. Store secrets in Vault at: kv/data/$ENV/apps/$APP_NAME/config
#   2. Use one of these delivery methods:
#
#   env (environment variables):
#     - Sync Vault secrets to AWS Secrets Manager via vault-secrets-sync.
#     - Reference ASM secrets in Lambda environment configuration.
#     - Use AWS Parameters and Secrets Lambda Extension for caching.
#
#   extension:
#     - Deploy the HashiCorp Vault Lambda Extension as a Lambda layer.
#     - The extension fetches secrets from Vault at function init time.
#     - Configure via VAULT_ADDR, VAULT_AUTH_ROLE, VAULT_SECRET_PATH env vars.
#
# IAM role for Lambda: ${ENV}-${APP_NAME}-lambda-role
# Vault auth method: aws (IAM-based authentication)
LAMEOF
  )
  output_manifest "lambda-guidance.md" "$LAMBDA_GUIDANCE" "Lambda Secret Delivery Guidance"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Onboarding Summary                              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  App:        $APP_NAME${NC}"
echo -e "${GREEN}║  Env:        $ENV${NC}"
echo -e "${GREEN}║  Platform:   $PLATFORM${NC}"
[[ "$PLATFORM" == "k8s" ]] && echo -e "${GREEN}║  Namespace:  $NAMESPACE${NC}"
echo -e "${GREEN}║  Policy:     $POLICY_NAME${NC}"
echo -e "${GREEN}║  Delivery:   $DELIVERY${NC}"
echo -e "${GREEN}║  DB Role:    $DB_ROLE${NC}"
[[ "$PLATFORM" == "k8s" ]] && echo -e "${GREEN}║  Cert:       $CERT${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
if [[ "$APPLY" != "true" && "$PLATFORM" != "none" ]]; then
  echo ""
  info "Manifests generated for review. Use --apply to apply resources directly."
fi
