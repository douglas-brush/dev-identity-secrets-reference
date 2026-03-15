#!/usr/bin/env bash

#!/usr/bin/env bash
# credential_age_report.sh — Credential age audit and compliance reporter
# Checks age of secrets in Vault and Kubernetes, flags policy violations
# Usage: credential_age_report.sh [--max-age <days>] [--format <text|json|csv>] [--namespace <ns>] [--vault-only] [--k8s-only]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

MAX_AGE_DAYS=90          # Default policy: rotate every 90 days
OUTPUT_FORMAT="text"
TARGET_NAMESPACE=""
VAULT_ONLY=""
K8S_ONLY=""
EXIT_CODE=0

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }

# ── Data collection ──────────────────────────────────────────────────────

declare -a REPORT_ENTRIES=()

add_entry() {
  local source="$1" name="$2" created="$3" age_days="$4" status="$5" detail="${6:-}"
  REPORT_ENTRIES+=("${source}|${name}|${created}|${age_days}|${status}|${detail}")
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'credential_age_report.sh') — Credential age audit

$(_bold 'USAGE')
  credential_age_report.sh [OPTIONS]

$(_bold 'OPTIONS')
  --max-age <days>     Maximum allowed age in days (default: 90)
  --format <format>    Output format: text, json, csv (default: text)
  --namespace <ns>     Only check specific Kubernetes namespace
  --vault-only         Only check Vault secrets
  --k8s-only           Only check Kubernetes secrets
  -h, --help           Show this help

$(_bold 'ENVIRONMENT')
  VAULT_ADDR           Vault server address
  VAULT_TOKEN          Vault authentication token
  KUBECONFIG           Kubernetes config path
  CREDENTIAL_MAX_AGE   Override default max age (days)

$(_bold 'EXIT CODES')
  0   All credentials within policy
  1   One or more credentials exceed max age
  2   Usage error

$(_bold 'EXAMPLES')
  credential_age_report.sh                          # Default 90-day check
  credential_age_report.sh --max-age 30 --k8s-only  # 30-day policy, K8s only
  credential_age_report.sh --format json             # JSON output for CI/CD
  credential_age_report.sh --format csv > report.csv # CSV export
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage ;;
    --max-age)       MAX_AGE_DAYS="$2"; shift 2 ;;
    --format)        OUTPUT_FORMAT="$2"; shift 2 ;;
    --namespace)     TARGET_NAMESPACE="$2"; shift 2 ;;
    --vault-only)    VAULT_ONLY=1; shift ;;
    --k8s-only)      K8S_ONLY=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

# Override from environment
MAX_AGE_DAYS="${CREDENTIAL_MAX_AGE:-$MAX_AGE_DAYS}"

# ── Date utilities ────────────────────────────────────────────────────────

# Calculate days between two ISO timestamps
days_since() {
  local timestamp="$1"
  local now_epoch then_epoch

  # Handle both GNU and BSD date
  if date --version &>/dev/null 2>&1; then
    # GNU date
    now_epoch=$(date +%s)
    then_epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo "0")
  else
    # BSD date (macOS)
    now_epoch=$(date +%s)
    # Try parsing ISO format
    local clean_ts="${timestamp%%Z*}"
    clean_ts="${clean_ts%%+*}"
    then_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$clean_ts" +%s 2>/dev/null || \
                 date -j -f "%Y-%m-%d" "${clean_ts:0:10}" +%s 2>/dev/null || echo "0")
  fi

  if [[ "$then_epoch" -eq 0 ]]; then
    echo "unknown"
    return
  fi

  local diff=$((now_epoch - then_epoch))
  echo $((diff / 86400))
}

# ── Vault secret age check ───────────────────────────────────────────────

check_vault_secrets() {
  if [[ -n "$K8S_ONLY" ]]; then
    return
  fi

  if ! command -v vault &>/dev/null; then
    printf '  %s %s\n' "$(_dim 'SKIP')" "vault CLI not installed"
    return
  fi

  if [[ -z "${VAULT_ADDR:-}" ]]; then
    printf '  %s %s\n' "$(_dim 'SKIP')" "VAULT_ADDR not set"
    return
  fi

  # Verify connectivity
  if ! vault token lookup &>/dev/null 2>&1; then
    printf '  %s %s\n' "$(_yellow 'WARN')" "Cannot authenticate to Vault"
    return
  fi

  printf '  %s\n' "$(_blue 'Scanning Vault secrets...')"

  # List KV v2 mounts
  local mounts
  mounts=$(vault secrets list -format=json 2>/dev/null || echo '{}')
  local kv_mounts
  kv_mounts=$(echo "$mounts" | jq -r 'to_entries[] | select(.value.type == "kv") | .key' 2>/dev/null || echo "")

  if [[ -z "$kv_mounts" ]]; then
    # Try common paths
    kv_mounts="secret/"
  fi

  for mount in $kv_mounts; do
    mount="${mount%/}"

    # List secrets recursively (top level)
    local secrets_list
    secrets_list=$(vault kv list -format=json "${mount}/" 2>/dev/null || echo '[]')

    if [[ "$secrets_list" == "[]" ]]; then
      continue
    fi

    echo "$secrets_list" | jq -r '.[]' 2>/dev/null | while read -r secret_path; do
      [[ -z "$secret_path" ]] && continue

      # Skip directories (ending in /)
      if [[ "$secret_path" == */ ]]; then
        # Recurse one level
        local sub_list
        sub_list=$(vault kv list -format=json "${mount}/${secret_path}" 2>/dev/null || echo '[]')
        echo "$sub_list" | jq -r '.[]' 2>/dev/null | while read -r sub_path; do
          [[ -z "$sub_path" || "$sub_path" == */ ]] && continue
          check_vault_secret_age "${mount}" "${secret_path}${sub_path}"
        done
      else
        check_vault_secret_age "${mount}" "$secret_path"
      fi
    done
  done
}

check_vault_secret_age() {
  local mount="$1" path="$2"
  local full_path="${mount}/${path}"

  # Get metadata
  local metadata
  metadata=$(vault kv metadata get -format=json "${full_path}" 2>/dev/null || echo '{}')

  if [[ "$metadata" == "{}" ]]; then
    return
  fi

  local created_time updated_time current_version
  created_time=$(echo "$metadata" | jq -r '.data.created_time // empty' 2>/dev/null || echo "")
  updated_time=$(echo "$metadata" | jq -r '.data.versions | to_entries | sort_by(.key | tonumber) | last | .value.created_time // empty' 2>/dev/null || echo "")
  current_version=$(echo "$metadata" | jq -r '.data.current_version // 0' 2>/dev/null || echo "0")

  # Use the most recent update time
  local effective_time="${updated_time:-$created_time}"

  if [[ -z "$effective_time" ]]; then
    add_entry "vault" "$full_path" "unknown" "unknown" "WARN" "Cannot determine age"
    return
  fi

  local age
  age=$(days_since "$effective_time")

  local status="OK"
  if [[ "$age" == "unknown" ]]; then
    status="WARN"
  elif [[ "$age" -gt "$MAX_AGE_DAYS" ]]; then
    status="FAIL"
    EXIT_CODE=1
  elif [[ "$age" -gt $((MAX_AGE_DAYS * 3 / 4)) ]]; then
    status="WARN"
  fi

  add_entry "vault" "$full_path" "$effective_time" "$age" "$status" "v${current_version}"
}

# ── Kubernetes secret age check ──────────────────────────────────────────

check_k8s_secrets() {
  if [[ -n "$VAULT_ONLY" ]]; then
    return
  fi

  if ! command -v kubectl &>/dev/null; then
    printf '  %s %s\n' "$(_dim 'SKIP')" "kubectl not installed"
    return
  fi

  if ! kubectl cluster-info &>/dev/null 2>&1; then
    printf '  %s %s\n' "$(_dim 'SKIP')" "Cannot connect to Kubernetes cluster"
    return
  fi

  printf '  %s\n' "$(_blue 'Scanning Kubernetes secrets...')"

  local namespaces
  if [[ -n "$TARGET_NAMESPACE" ]]; then
    namespaces="$TARGET_NAMESPACE"
  else
    namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "default")
  fi

  for ns in $namespaces; do
    # Skip system namespaces
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    local secrets_json
    secrets_json=$(kubectl get secrets -n "$ns" -o json 2>/dev/null || echo '{"items":[]}')
    local secret_count
    secret_count=$(echo "$secrets_json" | jq '.items | length' 2>/dev/null || echo "0")

    for ((i = 0; i < secret_count; i++)); do
      local name type created
      name=$(echo "$secrets_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
      type=$(echo "$secrets_json" | jq -r ".items[${i}].type" 2>/dev/null)
      created=$(echo "$secrets_json" | jq -r ".items[${i}].metadata.creationTimestamp" 2>/dev/null)

      # Skip helm and SA tokens
      [[ "$name" == sh.helm.release.* ]] && continue
      [[ "$type" == "kubernetes.io/service-account-token" ]] && continue

      local age
      age=$(days_since "$created")

      local status="OK"
      local detail="${type}"

      if [[ "$age" == "unknown" ]]; then
        status="WARN"
      elif [[ "$age" -gt "$MAX_AGE_DAYS" ]]; then
        status="FAIL"
        EXIT_CODE=1
      elif [[ "$age" -gt $((MAX_AGE_DAYS * 3 / 4)) ]]; then
        status="WARN"
      fi

      # Check if managed by ESO
      local owner_kind
      owner_kind=$(echo "$secrets_json" | jq -r ".items[${i}].metadata.ownerReferences[0].kind // empty" 2>/dev/null)
      [[ "$owner_kind" == "ExternalSecret" ]] && detail="${detail}, ESO-managed"

      add_entry "k8s" "${ns}/${name}" "$created" "$age" "$status" "$detail"
    done
  done
}

# ── SOPS file age check ─────────────────────────────────────────────────

check_sops_file_ages() {
  if [[ -n "$VAULT_ONLY" || -n "$K8S_ONLY" ]]; then
    return
  fi

  printf '  %s\n' "$(_blue 'Scanning SOPS-encrypted files...')"

  while IFS= read -r -d '' f; do
    if grep -q 'sops:' "$f" 2>/dev/null; then
      local lastmod
      # Extract lastmodified from SOPS metadata
      if command -v yq &>/dev/null; then
        lastmod=$(yq eval '.sops.lastmodified' "$f" 2>/dev/null || echo "")
      else
        lastmod=$(grep 'lastmodified:' "$f" 2>/dev/null | head -1 | sed 's/.*lastmodified: *//' | tr -d '"' || echo "")
      fi

      local relative="${f#"$REPO_ROOT"/}"

      if [[ -z "$lastmod" || "$lastmod" == "null" ]]; then
        add_entry "sops" "$relative" "unknown" "unknown" "WARN" "Cannot determine last modified"
        continue
      fi

      local age
      age=$(days_since "$lastmod")

      local status="OK"
      if [[ "$age" == "unknown" ]]; then
        status="WARN"
      elif [[ "$age" -gt "$MAX_AGE_DAYS" ]]; then
        status="FAIL"
        EXIT_CODE=1
      elif [[ "$age" -gt $((MAX_AGE_DAYS * 3 / 4)) ]]; then
        status="WARN"
      fi

      add_entry "sops" "$relative" "$lastmod" "$age" "$status" ""
    fi
  done < <(find "$REPO_ROOT" -type f \( -name '*.enc.yaml' -o -name '*.enc.yml' -o -name '*.enc.json' \
    -o -name '*.sops.yaml' -o -name '*.sops.yml' \) \
    -not -path '*/.git/*' -not -path '*/node_modules/*' -print0 2>/dev/null)
}

# ── Output formatters ────────────────────────────────────────────────────

output_text() {
  printf '\n'
  _bold '╔═══════════════════════════════════════════════════════════════════════════════╗'
  printf '\n'
  _bold '║                      CREDENTIAL AGE REPORT                                   ║'
  printf '\n'
  _bold '╠═══════════════════════════════════════════════════════════════════════════════╣'
  printf '\n'
  printf '║  Generated: %-64s ║\n' "$TIMESTAMP"
  printf '║  Policy:    Max age %s days%*s║\n' "$MAX_AGE_DAYS" $((54 - ${#MAX_AGE_DAYS})) ""
  _bold '╚═══════════════════════════════════════════════════════════════════════════════╝'
  printf '\n'

  if [[ ${#REPORT_ENTRIES[@]} -eq 0 ]]; then
    printf '\n  %s\n\n' "$(_dim 'No credentials found to report on.')"
    return
  fi

  # Header
  printf '\n  %-8s %-40s %-12s %-8s %s\n' "SOURCE" "NAME" "AGE (days)" "STATUS" "DETAIL"
  printf '  %s\n' "$(printf '%.0s─' {1..90})"

  local ok_count=0 warn_count=0 fail_count=0

  for entry in "${REPORT_ENTRIES[@]}"; do
    IFS='|' read -r source name created age status detail <<< "$entry"

    local status_display
    case "$status" in
      OK)   status_display="$(_green 'OK')"; ok_count=$((ok_count + 1)) ;;
      WARN) status_display="$(_yellow 'WARN')"; warn_count=$((warn_count + 1)) ;;
      FAIL) status_display="$(_red 'FAIL')"; fail_count=$((fail_count + 1)) ;;
      *)    status_display="$status" ;;
    esac

    # Truncate name if too long
    local display_name="$name"
    if [[ ${#display_name} -gt 38 ]]; then
      display_name="...${display_name: -35}"
    fi

    printf '  %-8s %-40s %-12s %s  %s\n' "$source" "$display_name" "$age" "$status_display" "$detail"
  done

  # Summary
  printf '\n  %s\n' "$(printf '%.0s─' {1..90})"
  printf '  Total: %d | ' "${#REPORT_ENTRIES[@]}"
  printf '%s %d | ' "$(_green 'OK:')" "$ok_count"
  printf '%s %d | ' "$(_yellow 'WARN:')" "$warn_count"
  printf '%s %d\n' "$(_red 'FAIL:')" "$fail_count"

  if [[ $fail_count -gt 0 ]]; then
    printf '\n  %s\n' "$(_red 'ACTION REQUIRED: Credentials exceeding maximum age policy detected.')"
    printf '  %s\n\n' "Rotate these credentials and update the secrets store."
  elif [[ $warn_count -gt 0 ]]; then
    printf '\n  %s\n\n' "$(_yellow 'Some credentials are approaching maximum age — plan rotation.')"
  else
    printf '\n  %s\n\n' "$(_green 'All credentials are within policy.')"
  fi
}

output_json() {
  local entries="["
  local first=true

  for entry in "${REPORT_ENTRIES[@]}"; do
    IFS='|' read -r source name created age status detail <<< "$entry"
    # Escape quotes
    name="${name//\"/\\\"}"
    detail="${detail//\"/\\\"}"

    if [[ "$first" == "true" ]]; then
      first=false
    else
      entries+=","
    fi
    entries+="{\"source\":\"${source}\",\"name\":\"${name}\",\"created\":\"${created}\",\"age_days\":\"${age}\",\"status\":\"${status}\",\"detail\":\"${detail}\"}"
  done
  entries+="]"

  local overall="COMPLIANT"
  [[ $EXIT_CODE -ne 0 ]] && overall="NON_COMPLIANT"

  cat <<EOF
{
  "report": "credential_age_audit",
  "timestamp": "${TIMESTAMP}",
  "policy_max_age_days": ${MAX_AGE_DAYS},
  "overall_status": "${overall}",
  "total_credentials": ${#REPORT_ENTRIES[@]},
  "credentials": ${entries}
}
EOF
}

output_csv() {
  printf 'source,name,created,age_days,status,detail\n'
  for entry in "${REPORT_ENTRIES[@]}"; do
    IFS='|' read -r source name created age status detail <<< "$entry"
    # Escape CSV fields
    name="${name//\"/\"\"}"
    detail="${detail//\"/\"\"}"
    printf '"%s","%s","%s","%s","%s","%s"\n' "$source" "$name" "$created" "$age" "$status" "$detail"
  done
}

# ── Main ──────────────────────────────────────────────────────────────────

main() {
  if [[ "$OUTPUT_FORMAT" == "text" ]]; then
    printf '\n%s\n' "$(_bold '═══ Credential Age Audit ═══')"
    printf '  Policy: credentials older than %s days will be flagged\n' "$MAX_AGE_DAYS"
  fi

  check_vault_secrets
  check_k8s_secrets
  check_sops_file_ages

  case "$OUTPUT_FORMAT" in
    text) output_text ;;
    json) output_json ;;
    csv)  output_csv ;;
    *)
      printf 'Error: unknown format: %s\n' "$OUTPUT_FORMAT" >&2
      exit 2
      ;;
  esac

  exit $EXIT_CODE
}

main
