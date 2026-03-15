#!/usr/bin/env bash
set -euo pipefail

# Devcontainer bootstrap — installs security tooling for development.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*"; }

ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
OS="linux"

# Versions — pin for reproducibility
VAULT_VERSION="1.15.4"
SOPS_VERSION="3.8.1"
AGE_VERSION="1.1.1"
YQ_VERSION="4.40.5"
GITLEAKS_VERSION="8.18.1"
OPA_VERSION="0.60.0"

info "Architecture: ${ARCH}"
info "Installing security tooling..."
echo ""

# --- HashiCorp Vault CLI ---
if ! command -v vault &>/dev/null; then
  info "Installing Vault ${VAULT_VERSION}..."
  curl -fsSL "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_${OS}_${ARCH}.zip" -o /tmp/vault.zip
  sudo unzip -o /tmp/vault.zip -d /usr/local/bin/
  rm -f /tmp/vault.zip
  sudo chmod +x /usr/local/bin/vault
  ok "Vault $(vault version)"
else
  ok "Vault already installed: $(vault version)"
fi

# --- SOPS ---
if ! command -v sops &>/dev/null; then
  info "Installing SOPS ${SOPS_VERSION}..."
  curl -fsSL "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.${OS}.${ARCH}" -o /tmp/sops
  sudo install -m 0755 /tmp/sops /usr/local/bin/sops
  rm -f /tmp/sops
  ok "SOPS $(sops --version 2>&1 | head -1)"
else
  ok "SOPS already installed: $(sops --version 2>&1 | head -1)"
fi

# --- age ---
if ! command -v age &>/dev/null; then
  info "Installing age ${AGE_VERSION}..."
  curl -fsSL "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-${OS}-${ARCH}.tar.gz" -o /tmp/age.tar.gz
  tar -xzf /tmp/age.tar.gz -C /tmp/
  sudo install -m 0755 /tmp/age/age /usr/local/bin/age
  sudo install -m 0755 /tmp/age/age-keygen /usr/local/bin/age-keygen
  rm -rf /tmp/age.tar.gz /tmp/age/
  ok "age $(age --version 2>&1)"
else
  ok "age already installed: $(age --version 2>&1)"
fi

# --- jq ---
if ! command -v jq &>/dev/null; then
  info "Installing jq..."
  sudo apt-get update -qq && sudo apt-get install -yqq jq
  ok "jq $(jq --version)"
else
  ok "jq already installed: $(jq --version)"
fi

# --- yq ---
if ! command -v yq &>/dev/null; then
  info "Installing yq ${YQ_VERSION}..."
  curl -fsSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_${OS}_${ARCH}" -o /tmp/yq
  sudo install -m 0755 /tmp/yq /usr/local/bin/yq
  rm -f /tmp/yq
  ok "yq $(yq --version 2>&1)"
else
  ok "yq already installed: $(yq --version 2>&1)"
fi

# --- gitleaks ---
if ! command -v gitleaks &>/dev/null; then
  info "Installing gitleaks ${GITLEAKS_VERSION}..."
  curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH}.tar.gz" -o /tmp/gitleaks.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /tmp/ gitleaks
  sudo install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks
  rm -f /tmp/gitleaks.tar.gz /tmp/gitleaks
  ok "gitleaks $(gitleaks version 2>&1)"
else
  ok "gitleaks already installed: $(gitleaks version 2>&1)"
fi

# --- OPA ---
if ! command -v opa &>/dev/null; then
  info "Installing OPA ${OPA_VERSION}..."
  curl -fsSL "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_${OS}_${ARCH}_static" -o /tmp/opa
  sudo install -m 0755 /tmp/opa /usr/local/bin/opa
  rm -f /tmp/opa
  ok "OPA $(opa version 2>&1 | head -1)"
else
  ok "OPA already installed: $(opa version 2>&1 | head -1)"
fi

# --- ShellCheck ---
if ! command -v shellcheck &>/dev/null; then
  info "Installing ShellCheck..."
  sudo apt-get update -qq && sudo apt-get install -yqq shellcheck
  ok "ShellCheck $(shellcheck --version 2>&1 | grep version: | head -1)"
else
  ok "ShellCheck already installed"
fi

# --- pre-commit ---
if ! command -v pre-commit &>/dev/null; then
  info "Installing pre-commit..."
  pip3 install --user pre-commit 2>/dev/null || sudo pip3 install pre-commit
  ok "pre-commit $(pre-commit --version 2>&1)"
else
  ok "pre-commit already installed: $(pre-commit --version 2>&1)"
fi

# --- Setup age key directory ---
AGE_KEY_DIR="${HOME}/.config/sops/age"
if [[ ! -d "$AGE_KEY_DIR" ]]; then
  mkdir -p "$AGE_KEY_DIR"
  chmod 0700 "$AGE_KEY_DIR"
  info "Created age key directory: $AGE_KEY_DIR"
fi

# --- Install pre-commit hooks if config exists ---
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." 2>/dev/null && pwd)"
if [[ -f "${WORKSPACE_DIR}/.pre-commit-config.yaml" ]]; then
  cd "$WORKSPACE_DIR"
  pre-commit install --allow-missing-config 2>/dev/null && ok "Pre-commit hooks installed" || warn "Pre-commit install failed (non-fatal)"
fi

echo ""
ok "Devcontainer bootstrap complete"
info "Tools installed: vault, sops, age, jq, yq, gitleaks, opa, shellcheck, pre-commit"
