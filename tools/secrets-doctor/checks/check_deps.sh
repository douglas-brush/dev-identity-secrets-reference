#!/usr/bin/env bash
# check_deps.sh — Dependency checker for secrets infrastructure tooling
# Sourced by doctor.sh — uses pass/warn/fail/skip/info functions from parent
set -euo pipefail

# Required tools — absence is a failure
REQUIRED_TOOLS=(
  "vault:HashiCorp Vault CLI"
  "sops:Mozilla SOPS"
  "age:age encryption"
  "jq:JSON processor"
  "yq:YAML processor"
)

# Recommended tools — absence is a warning
RECOMMENDED_TOOLS=(
  "kubectl:Kubernetes CLI"
  "helm:Helm package manager"
  "gitleaks:Secret scanner"
  "opa:Open Policy Agent"
  "terraform:Terraform CLI"
  "age-keygen:age key generator"
  "git:Git version control"
  "openssl:OpenSSL toolkit"
  "gpg:GnuPG"
)

# Minimum version requirements (tool:minimum_version)
MIN_VERSIONS=(
  "vault:1.12.0"
  "sops:3.7.0"
  "terraform:1.3.0"
  "helm:3.10.0"
)

# Compare semantic versions: returns 0 if $1 >= $2
version_gte() {
  local v1="$1" v2="$2"
  # Strip leading 'v' if present
  v1="${v1#v}"
  v2="${v2#v}"

  if [[ "$v1" == "$v2" ]]; then
    return 0
  fi

  local IFS='.'
  local i
  # shellcheck disable=SC2206
  local v1_parts=($v1) v2_parts=($v2)

  for ((i = 0; i < ${#v2_parts[@]}; i++)); do
    local a="${v1_parts[i]:-0}"
    local b="${v2_parts[i]:-0}"
    # Strip non-numeric suffixes
    a="${a%%[!0-9]*}"
    b="${b%%[!0-9]*}"
    if ((a > b)); then return 0; fi
    if ((a < b)); then return 1; fi
  done
  return 0
}

# Extract version string from tool output
get_version() {
  local tool="$1"
  local version=""

  case "$tool" in
    vault)
      version=$(vault version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    sops)
      version=$(sops --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    age)
      version=$(age --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    jq)
      version=$(jq --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+[0-9.]*' | head -1) ;;
    yq)
      version=$(yq --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    kubectl)
      version=$(kubectl version --client --short 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 ||
                kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    helm)
      version=$(helm version --short 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    gitleaks)
      version=$(gitleaks version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    opa)
      version=$(opa version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    terraform)
      version=$(terraform version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    git)
      version=$(git --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    openssl)
      version=$(openssl version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    gpg)
      version=$(gpg --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
    *)
      version=$("$tool" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ;;
  esac

  echo "${version:-unknown}"
}

# Check minimum version for a tool
check_min_version() {
  local tool="$1"
  local current_version="$2"

  for entry in "${MIN_VERSIONS[@]}"; do
    local t="${entry%%:*}"
    local min="${entry#*:}"
    if [[ "$t" == "$tool" ]]; then
      if [[ "$current_version" == "unknown" ]]; then
        warn "${tool}: version unknown — minimum required is ${min}"
        return
      fi
      if version_gte "$current_version" "$min"; then
        info "${tool}: version ${current_version} meets minimum ${min}"
      else
        warn "${tool}: version ${current_version} is below minimum ${min}"
      fi
      return
    fi
  done
}

check_deps() {
  # Check required tools
  for entry in "${REQUIRED_TOOLS[@]}"; do
    local tool="${entry%%:*}"
    local desc="${entry#*:}"

    if command -v "$tool" &>/dev/null; then
      local ver
      ver=$(get_version "$tool")
      pass "${desc} (${tool}) installed — version ${ver}"
      check_min_version "$tool" "$ver"
    else
      fail "${desc} (${tool}) is NOT installed — required"
    fi
  done

  # Check recommended tools
  for entry in "${RECOMMENDED_TOOLS[@]}"; do
    local tool="${entry%%:*}"
    local desc="${entry#*:}"

    if command -v "$tool" &>/dev/null; then
      local ver
      ver=$(get_version "$tool")
      pass "${desc} (${tool}) installed — version ${ver}"
      check_min_version "$tool" "$ver"
    else
      warn "${desc} (${tool}) not installed — recommended"
    fi
  done

  # Check PATH sanity
  if [[ ":$PATH:" == *":/usr/local/bin:"* ]] || [[ ":$PATH:" == *":/opt/homebrew/bin:"* ]]; then
    pass "PATH includes standard tool directories"
  else
    warn "PATH may not include /usr/local/bin or /opt/homebrew/bin"
  fi

  # Check for age key
  local age_key_file="${SOPS_AGE_KEY_FILE:-${HOME}/.config/sops/age/keys.txt}"
  if [[ -f "$age_key_file" ]]; then
    local perms
    perms=$(stat -f '%A' "$age_key_file" 2>/dev/null || stat -c '%a' "$age_key_file" 2>/dev/null || echo "unknown")
    if [[ "$perms" == "600" || "$perms" == "400" ]]; then
      pass "age key file exists with secure permissions (${perms})"
    else
      warn "age key file exists but permissions are ${perms} — should be 600 or 400"
    fi
  else
    warn "age key file not found at ${age_key_file}"
  fi
}
