#!/usr/bin/env bash
# identity_inventory.sh — Non-human identity inventory and audit tool
# Enumerates service accounts, machine identities, and API credentials across platforms
# Usage: identity_inventory.sh [--json] [--namespace <ns>] [--verbose]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_FILE="${REPO_ROOT}/logs/identity-inventory-${TIMESTAMP//[:T]/-}.log"

# ── Defaults ──────────────────────────────────────────────────────────────

JSON_OUTPUT=""
VERBOSE=""
TARGET_NAMESPACE=""
EXIT_CODE=0

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }

# ── Logging ───────────────────────────────────────────────────────────────

log() {
  local level="$1"; shift
  local msg="$*"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local entry="${ts} [${level}] ${msg}"

  case "$level" in
    INFO)  printf '  %s %s\n' "$(_blue 'INFO')" "$msg" ;;
    WARN)  printf '  %s %s\n' "$(_yellow 'WARN')" "$msg" ;;
    ERROR) printf '  %s %s\n' "$(_red 'ERROR')" "$msg" ;;
    OK)    printf '  %s %s\n' "$(_green '  OK')" "$msg" ;;
    SKIP)  printf '  %s %s\n' "$(_dim 'SKIP')" "$msg" ;;
  esac

  mkdir -p "$(dirname "$LOG_FILE")"
  echo "$entry" >> "$LOG_FILE"
}

# ── Data collection ──────────────────────────────────────────────────────

declare -a INVENTORY_ENTRIES=()

add_identity() {
  local source="$1" name="$2" type="$3" scope="$4" risk="${5:-none}" detail="${6:-}"
  INVENTORY_ENTRIES+=("${source}|${name}|${type}|${scope}|${risk}|${detail}")
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'identity_inventory.sh') — Non-human identity inventory

$(_bold 'USAGE')
  identity_inventory.sh [OPTIONS]

$(_bold 'OPTIONS')
  --json               Output inventory as JSON
  --namespace <ns>     Only check specific Kubernetes namespace
  --verbose            Show additional diagnostic info
  -h, --help           Show this help

$(_bold 'DESCRIPTION')
  Enumerates non-human identities across available platforms:
  - Kubernetes: ServiceAccounts, secret bindings, default SA usage
  - Vault: auth methods, roles, policies, overly-broad policies
  - GitHub: App installations, deploy keys, repository secrets (names only)
  - Cloud: AWS IAM roles/users, Azure service principals, GCP service accounts

  Gracefully skips any platform whose CLI is not available.
  All operations are read-only — no changes are made.

$(_bold 'ENVIRONMENT')
  VAULT_ADDR          Vault server address
  VAULT_TOKEN         Vault authentication token
  KUBECONFIG          Kubernetes config path
  GITHUB_TOKEN        GitHub token for gh CLI (or gh auth login)

$(_bold 'EXIT CODES')
  0   Inventory completed (no high-risk findings)
  1   High-risk findings detected
  2   Usage error

$(_bold 'EXAMPLES')
  identity_inventory.sh                     # Text table output
  identity_inventory.sh --json              # JSON for automation
  identity_inventory.sh --namespace prod    # K8s namespace filter
  identity_inventory.sh --verbose           # Extra detail
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage ;;
    --json)          JSON_OUTPUT=1; shift ;;
    --namespace)     TARGET_NAMESPACE="$2"; shift 2 ;;
    --verbose)       VERBOSE=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# ── Kubernetes inventory ─────────────────────────────────────────────────

inventory_kubernetes() {
  printf '\n%s\n' "$(_bold '── Kubernetes Identities ──')"

  if ! command -v kubectl &>/dev/null; then
    log SKIP "kubectl not installed"
    return
  fi

  if ! kubectl cluster-info &>/dev/null 2>&1; then
    log SKIP "Cannot connect to Kubernetes cluster"
    return
  fi

  local namespaces
  if [[ -n "$TARGET_NAMESPACE" ]]; then
    namespaces="$TARGET_NAMESPACE"
  else
    namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "default")
  fi

  local total_sa=0
  local default_sa_usage=0

  for ns in $namespaces; do
    # Skip system namespaces
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    # List ServiceAccounts
    local sa_json
    sa_json=$(kubectl get serviceaccounts -n "$ns" -o json 2>/dev/null || echo '{"items":[]}')
    local sa_count
    sa_count=$(echo "$sa_json" | jq '.items | length' 2>/dev/null || echo "0")

    for ((i = 0; i < sa_count; i++)); do
      local sa_name
      sa_name=$(echo "$sa_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
      total_sa=$((total_sa + 1))

      local risk="none"
      local detail=""

      # Flag default SA usage
      if [[ "$sa_name" == "default" ]]; then
        # Check if any pods use the default SA
        local pod_count
        pod_count=$(kubectl get pods -n "$ns" --field-selector=spec.serviceAccountName=default \
          -o jsonpath='{.items}' 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
        if [[ "$pod_count" -gt 0 ]]; then
          risk="high"
          detail="default SA in use by ${pod_count} pod(s)"
          default_sa_usage=$((default_sa_usage + 1))
          EXIT_CODE=1
        else
          detail="default SA (no pods)"
        fi
      fi

      # Check for secret access (RBAC bindings referencing this SA)
      local secret_access=""
      local bindings
      bindings=$(kubectl get rolebindings,clusterrolebindings -n "$ns" -o json 2>/dev/null || echo '{"items":[]}')
      local has_secret_access
      has_secret_access=$(echo "$bindings" | jq -r --arg sa "$sa_name" --arg ns "$ns" \
        '[.items[] | select(.subjects[]? | select(.kind == "ServiceAccount" and .name == $sa and (.namespace == $ns or .namespace == null)))] | length' \
        2>/dev/null || echo "0")

      if [[ "$has_secret_access" -gt 0 ]]; then
        secret_access="bound to ${has_secret_access} role(s)"
        [[ -z "$detail" ]] && detail="$secret_access" || detail="${detail}; ${secret_access}"
      fi

      # Check for mounted secrets
      local secret_count
      secret_count=$(echo "$sa_json" | jq -r ".items[${i}].secrets | length // 0" 2>/dev/null || echo "0")
      if [[ "$secret_count" -gt 0 ]]; then
        local sec_detail="${secret_count} secret(s) mounted"
        [[ -z "$detail" ]] && detail="$sec_detail" || detail="${detail}; ${sec_detail}"
      fi

      add_identity "k8s" "${ns}/${sa_name}" "ServiceAccount" "$ns" "$risk" "$detail"
    done
  done

  log OK "Enumerated ${total_sa} ServiceAccount(s)"
  if [[ $default_sa_usage -gt 0 ]]; then
    log WARN "${default_sa_usage} namespace(s) with default SA in active use"
  fi
}

# ── Vault inventory ──────────────────────────────────────────────────────

inventory_vault() {
  printf '\n%s\n' "$(_bold '── Vault Identities ──')"

  if ! command -v vault &>/dev/null; then
    log SKIP "vault CLI not installed"
    return
  fi

  if [[ -z "${VAULT_ADDR:-}" ]]; then
    log SKIP "VAULT_ADDR not set"
    return
  fi

  if ! vault token lookup &>/dev/null 2>&1; then
    log SKIP "Cannot authenticate to Vault"
    return
  fi

  # List auth methods
  local auth_methods
  auth_methods=$(vault auth list -format=json 2>/dev/null || echo '{}')

  if [[ "$auth_methods" != "{}" ]]; then
    local method_count
    method_count=$(echo "$auth_methods" | jq 'length' 2>/dev/null || echo "0")
    log OK "Found ${method_count} auth method(s)"

    echo "$auth_methods" | jq -r 'to_entries[] | "\(.key)|\(.value.type)"' 2>/dev/null | while IFS='|' read -r path auth_type; do
      path="${path%/}"
      add_identity "vault" "$path" "auth-method" "global" "none" "type=${auth_type}"

      # List roles for each auth method
      local roles
      roles=$(vault list -format=json "auth/${path}/role" 2>/dev/null || \
              vault list -format=json "auth/${path}/roles" 2>/dev/null || echo '[]')

      if [[ "$roles" != "[]" ]]; then
        echo "$roles" | jq -r '.[]' 2>/dev/null | while read -r role_name; do
          [[ -z "$role_name" ]] && continue
          add_identity "vault" "${path}/role/${role_name}" "auth-role" "$path" "none" ""
        done
      fi
    done
  fi

  # List policies and flag overly-broad ones
  local policies
  policies=$(vault policy list -format=json 2>/dev/null || echo '[]')

  if [[ "$policies" != "[]" ]]; then
    local policy_count
    policy_count=$(echo "$policies" | jq 'length' 2>/dev/null || echo "0")
    log OK "Found ${policy_count} policies"

    echo "$policies" | jq -r '.[]' 2>/dev/null | while read -r policy_name; do
      [[ -z "$policy_name" ]] && continue
      [[ "$policy_name" == "default" || "$policy_name" == "root" ]] && continue

      local risk="none"
      local detail=""

      # Read policy content and check for overly-broad rules
      local policy_content
      policy_content=$(vault policy read "$policy_name" 2>/dev/null || echo "")

      if echo "$policy_content" | grep -q 'path "\*"' 2>/dev/null; then
        risk="high"
        detail="wildcard path access"
        EXIT_CODE=1
      elif echo "$policy_content" | grep -qE 'capabilities.*\[".*sudo.*"\]' 2>/dev/null; then
        risk="medium"
        detail="has sudo capability"
      fi

      local cap_count
      cap_count=$(echo "$policy_content" | grep -c 'path ' 2>/dev/null || echo "0")
      [[ -z "$detail" ]] && detail="${cap_count} path rule(s)" || detail="${detail}; ${cap_count} path rule(s)"

      add_identity "vault" "policy/${policy_name}" "policy" "global" "$risk" "$detail"
    done
  fi
}

# ── GitHub inventory ─────────────────────────────────────────────────────

inventory_github() {
  printf '\n%s\n' "$(_bold '── GitHub Identities ──')"

  if ! command -v gh &>/dev/null; then
    log SKIP "gh CLI not installed"
    return
  fi

  if ! gh auth status &>/dev/null 2>&1; then
    log SKIP "gh CLI not authenticated"
    return
  fi

  # Detect repo from git remote
  local repo_slug=""
  if git -C "$REPO_ROOT" remote get-url origin &>/dev/null 2>&1; then
    repo_slug=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null | sed -E 's#.+github\.com[:/](.+)\.git$#\1#;s#.+github\.com[:/](.+)$#\1#')
  fi

  if [[ -z "$repo_slug" ]]; then
    log SKIP "Could not determine GitHub repository from git remote"
    return
  fi

  [[ -n "$VERBOSE" ]] && log INFO "GitHub repo: ${repo_slug}"

  # List deploy keys
  local deploy_keys
  deploy_keys=$(gh api "repos/${repo_slug}/keys" 2>/dev/null || echo '[]')

  if [[ "$deploy_keys" != "[]" ]]; then
    local key_count
    key_count=$(echo "$deploy_keys" | jq 'length' 2>/dev/null || echo "0")
    log OK "Found ${key_count} deploy key(s)"

    echo "$deploy_keys" | jq -r '.[] | "\(.title)|\(.read_only)"' 2>/dev/null | while IFS='|' read -r title read_only; do
      local risk="none"
      local detail="read_only=${read_only}"
      if [[ "$read_only" == "false" ]]; then
        risk="medium"
        detail="read-write deploy key"
      fi
      add_identity "github" "deploy-key/${title}" "deploy-key" "$repo_slug" "$risk" "$detail"
    done
  else
    log OK "No deploy keys found"
  fi

  # List repository secrets (names only, never values)
  local repo_secrets
  repo_secrets=$(gh api "repos/${repo_slug}/actions/secrets" 2>/dev/null || echo '{"secrets":[]}')

  local secret_count
  secret_count=$(echo "$repo_secrets" | jq '.secrets | length' 2>/dev/null || echo "0")
  if [[ "$secret_count" -gt 0 ]]; then
    log OK "Found ${secret_count} repository secret(s)"
    echo "$repo_secrets" | jq -r '.secrets[].name' 2>/dev/null | while read -r secret_name; do
      [[ -z "$secret_name" ]] && continue
      add_identity "github" "secret/${secret_name}" "actions-secret" "$repo_slug" "none" "name only"
    done
  else
    log OK "No repository secrets found"
  fi

  # List GitHub App installations (org level, may fail on personal repos)
  local installations
  installations=$(gh api "repos/${repo_slug}/installation" 2>/dev/null || echo '{}')
  if [[ "$installations" != "{}" ]] && echo "$installations" | jq -e '.id' &>/dev/null; then
    local app_slug
    app_slug=$(echo "$installations" | jq -r '.app_slug // "unknown"' 2>/dev/null)
    local perms
    perms=$(echo "$installations" | jq -r '.permissions | keys | join(", ")' 2>/dev/null || echo "unknown")
    add_identity "github" "app/${app_slug}" "github-app" "$repo_slug" "none" "permissions: ${perms}"
    log OK "GitHub App installation found: ${app_slug}"
  fi
}

# ── Cloud provider inventory ─────────────────────────────────────────────

inventory_aws() {
  if ! command -v aws &>/dev/null; then
    return
  fi

  printf '\n%s\n' "$(_bold '── AWS Identities ──')"

  if ! aws sts get-caller-identity &>/dev/null 2>&1; then
    log SKIP "Cannot authenticate to AWS"
    return
  fi

  # List IAM users (service accounts are typically IAM users with no console access)
  local iam_users
  iam_users=$(aws iam list-users --output json 2>/dev/null || echo '{"Users":[]}')
  local user_count
  user_count=$(echo "$iam_users" | jq '.Users | length' 2>/dev/null || echo "0")

  if [[ "$user_count" -gt 0 ]]; then
    log OK "Found ${user_count} IAM user(s)"
    echo "$iam_users" | jq -r '.Users[] | "\(.UserName)|\(.CreateDate)|\(.PasswordLastUsed // "never")"' 2>/dev/null | while IFS='|' read -r name created last_used; do
      local risk="none"
      local detail="created=${created}"
      if [[ "$last_used" == "never" ]]; then
        detail="${detail}; no console login (likely service account)"
      fi
      add_identity "aws" "iam-user/${name}" "iam-user" "account" "$risk" "$detail"
    done
  fi

  # List IAM roles
  local iam_roles
  iam_roles=$(aws iam list-roles --output json 2>/dev/null || echo '{"Roles":[]}')
  local role_count
  role_count=$(echo "$iam_roles" | jq '[.Roles[] | select(.RoleName | startswith("aws-") | not)] | length' 2>/dev/null || echo "0")

  if [[ "$role_count" -gt 0 ]]; then
    log OK "Found ${role_count} custom IAM role(s)"
    echo "$iam_roles" | jq -r '.Roles[] | select(.RoleName | startswith("aws-") | not) | "\(.RoleName)|\(.CreateDate)"' 2>/dev/null | while IFS='|' read -r name created; do
      add_identity "aws" "iam-role/${name}" "iam-role" "account" "none" "created=${created}"
    done
  fi
}

inventory_azure() {
  if ! command -v az &>/dev/null; then
    return
  fi

  printf '\n%s\n' "$(_bold '── Azure Identities ──')"

  if ! az account show &>/dev/null 2>&1; then
    log SKIP "Cannot authenticate to Azure"
    return
  fi

  # List service principals
  local sps
  sps=$(az ad sp list --all --query "[?servicePrincipalType=='Application']" --output json 2>/dev/null || echo '[]')
  local sp_count
  sp_count=$(echo "$sps" | jq 'length' 2>/dev/null || echo "0")

  if [[ "$sp_count" -gt 0 ]]; then
    log OK "Found ${sp_count} service principal(s)"
    echo "$sps" | jq -r '.[] | "\(.displayName)|\(.appId)"' 2>/dev/null | head -50 | while IFS='|' read -r name app_id; do
      add_identity "azure" "sp/${name}" "service-principal" "tenant" "none" "appId=${app_id}"
    done
  fi
}

inventory_gcloud() {
  if ! command -v gcloud &>/dev/null; then
    return
  fi

  printf '\n%s\n' "$(_bold '── GCP Identities ──')"

  if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &>/dev/null 2>&1; then
    log SKIP "Cannot authenticate to GCP"
    return
  fi

  local project
  project=$(gcloud config get-value project 2>/dev/null || echo "")
  if [[ -z "$project" ]]; then
    log SKIP "No GCP project set"
    return
  fi

  # List service accounts
  local sas
  sas=$(gcloud iam service-accounts list --format=json --project="$project" 2>/dev/null || echo '[]')
  local sa_count
  sa_count=$(echo "$sas" | jq 'length' 2>/dev/null || echo "0")

  if [[ "$sa_count" -gt 0 ]]; then
    log OK "Found ${sa_count} GCP service account(s)"
    echo "$sas" | jq -r '.[] | "\(.email)|\(.displayName // "none")"' 2>/dev/null | while IFS='|' read -r email display; do
      add_identity "gcp" "sa/${email}" "service-account" "$project" "none" "display=${display}"
    done
  fi
}

# ── Output formatters ────────────────────────────────────────────────────

output_text() {
  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║                          NON-HUMAN IDENTITY INVENTORY                                       ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Generated: %-80s ║\n' "$TIMESTAMP"
  _bold '╚═══════════════════════════════════════════════════════════════════════════════════════════════╝'
  printf '\n'

  if [[ ${#INVENTORY_ENTRIES[@]} -eq 0 ]]; then
    printf '\n  %s\n\n' "$(_dim 'No identities found. Ensure CLI tools are installed and authenticated.')"
    return
  fi

  # Table header
  printf '\n  %-8s %-35s %-18s %-12s %-8s %s\n' "SOURCE" "NAME" "TYPE" "SCOPE" "RISK" "DETAIL"
  printf '  %s\n' "$(printf '%.0s─' {1..110})"

  local high_count=0 medium_count=0

  for entry in "${INVENTORY_ENTRIES[@]}"; do
    IFS='|' read -r source name type scope risk detail <<< "$entry"

    local risk_display
    case "$risk" in
      high)   risk_display="$(_red 'HIGH')"; high_count=$((high_count + 1)) ;;
      medium) risk_display="$(_yellow 'MED')"; medium_count=$((medium_count + 1)) ;;
      none)   risk_display="$(_dim '—')" ;;
      *)      risk_display="$risk" ;;
    esac

    # Truncate long names
    local display_name="$name"
    if [[ ${#display_name} -gt 33 ]]; then
      display_name="...${display_name: -30}"
    fi

    local display_detail="$detail"
    if [[ ${#display_detail} -gt 40 ]]; then
      display_detail="${display_detail:0:37}..."
    fi

    printf '  %-8s %-35s %-18s %-12s %s  %s\n' \
      "$source" "$display_name" "$type" "$scope" "$risk_display" "$display_detail"
  done

  # Summary
  printf '\n  %s\n' "$(printf '%.0s─' {1..110})"
  printf '  Total identities: %d' "${#INVENTORY_ENTRIES[@]}"
  if [[ $high_count -gt 0 ]]; then
    printf ' | %s' "$(_red "High risk: ${high_count}")"
  fi
  if [[ $medium_count -gt 0 ]]; then
    printf ' | %s' "$(_yellow "Medium risk: ${medium_count}")"
  fi
  printf '\n'

  if [[ $high_count -gt 0 ]]; then
    printf '\n  %s\n' "$(_red 'ACTION REQUIRED: High-risk identity findings detected. Review and remediate.')"
  fi
  printf '\n'
}

output_json() {
  local entries="["
  local first=true

  for entry in "${INVENTORY_ENTRIES[@]}"; do
    IFS='|' read -r source name type scope risk detail <<< "$entry"
    name="${name//\"/\\\"}"
    detail="${detail//\"/\\\"}"

    if [[ "$first" == "true" ]]; then
      first=false
    else
      entries+=","
    fi
    entries+="{\"source\":\"${source}\",\"name\":\"${name}\",\"type\":\"${type}\",\"scope\":\"${scope}\",\"risk\":\"${risk}\",\"detail\":\"${detail}\"}"
  done
  entries+="]"

  cat <<EOF
{
  "report": "non_human_identity_inventory",
  "timestamp": "${TIMESTAMP}",
  "total_identities": ${#INVENTORY_ENTRIES[@]},
  "identities": ${entries}
}
EOF
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  if [[ -z "$JSON_OUTPUT" ]]; then
    printf '\n%s\n' "$(_bold '═══ Non-Human Identity Inventory ═══')"
  fi

  log INFO "Inventory started at ${TIMESTAMP}"

  # Run all platform inventories (each skips gracefully if unavailable)
  inventory_kubernetes
  inventory_vault
  inventory_github
  inventory_aws
  inventory_azure
  inventory_gcloud

  # Output
  if [[ -n "$JSON_OUTPUT" ]]; then
    output_json
  else
    output_text
    log INFO "Log file: ${LOG_FILE}"
  fi

  exit $EXIT_CODE
}

main
