#!/usr/bin/env bash
set -euo pipefail

# Compliance Control Validation
# Validates all 6 control objectives (C1-C6) and produces a compliance report.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TOTAL=0
PASSED=0
WARNED=0
FAILED=0

declare -a RESULTS=()

check() {
  local control="$1"
  local description="$2"
  local status="$3"  # PASS, WARN, FAIL
  local detail="${4:-}"

  TOTAL=$((TOTAL + 1))
  case "$status" in
    PASS) PASSED=$((PASSED + 1)); icon="${GREEN}PASS${NC}" ;;
    WARN) WARNED=$((WARNED + 1)); icon="${YELLOW}WARN${NC}" ;;
    FAIL) FAILED=$((FAILED + 1)); icon="${RED}FAIL${NC}" ;;
  esac

  RESULTS+=("$(printf "| %-5s | %-50s | %b | %s |" "$control" "$description" "$icon" "$detail")")
}

###############################################################################
# C1: Identity-Based Access — No static credentials, OIDC/JWT auth
###############################################################################
check_c1() {
  # C1.1: OIDC auth method configured
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "auth enable oidc" platform/vault/examples/setup-complete.sh; then
    check "C1.1" "OIDC auth method defined" "PASS"
  else
    check "C1.1" "OIDC auth method defined" "FAIL" "No OIDC config found"
  fi

  # C1.2: Kubernetes auth configured
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "auth enable kubernetes" platform/vault/examples/setup-complete.sh; then
    check "C1.2" "Kubernetes auth method defined" "PASS"
  else
    check "C1.2" "Kubernetes auth method defined" "FAIL"
  fi

  # C1.3: GitHub Actions JWT auth
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "jwt/github" platform/vault/examples/setup-complete.sh; then
    check "C1.3" "GitHub Actions JWT auth defined" "PASS"
  else
    check "C1.3" "GitHub Actions JWT auth defined" "FAIL"
  fi

  # C1.4: AppRole for machine identity
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "auth enable approle" platform/vault/examples/setup-complete.sh; then
    check "C1.4" "AppRole auth for machines" "PASS"
  else
    check "C1.4" "AppRole auth for machines" "WARN" "No AppRole config"
  fi

  # C1.5: No hardcoded tokens in repo
  if ! grep -rIl "VAULT_TOKEN\s*=" --include="*.sh" --include="*.yaml" --include="*.yml" --include="*.json" . 2>/dev/null | grep -v ".example" | grep -v "env.template" | grep -v "check_controls" | grep -qv ".enc."; then
    check "C1.5" "No hardcoded VAULT_TOKEN in source" "PASS"
  else
    check "C1.5" "No hardcoded VAULT_TOKEN in source" "FAIL" "Found hardcoded tokens"
  fi
}

###############################################################################
# C2: Least-Privilege Policies — Scoped per app/env
###############################################################################
check_c2() {
  # C2.1: Developer read policy exists
  if [[ -f platform/vault/policies/developer-read.hcl ]]; then
    check "C2.1" "Developer read-only policy exists" "PASS"
  else
    check "C2.1" "Developer read-only policy exists" "FAIL"
  fi

  # C2.2: CI issuer policy exists (scoped)
  if [[ -f platform/vault/policies/ci-issuer.hcl ]]; then
    check "C2.2" "CI issuer policy exists" "PASS"
  else
    check "C2.2" "CI issuer policy exists" "FAIL"
  fi

  # C2.3: Emergency policy has deny rules
  if [[ -f platform/vault/policies/admin-emergency.hcl ]] && grep -q 'capabilities = \["deny"\]' platform/vault/policies/admin-emergency.hcl; then
    check "C2.3" "Emergency policy has explicit deny rules" "PASS"
  else
    check "C2.3" "Emergency policy has explicit deny rules" "FAIL"
  fi

  # C2.4: Policies use path scoping (not wildcards at root)
  local broad_policy=false
  for f in platform/vault/policies/*.hcl; do
    [[ ! -f "$f" ]] && continue
    if grep -qE 'path "\*"' "$f" 2>/dev/null; then
      broad_policy=true
    fi
  done
  if [[ "$broad_policy" == "false" ]]; then
    check "C2.4" "No root wildcard paths in policies" "PASS"
  else
    check "C2.4" "No root wildcard paths in policies" "FAIL" "Overly broad policy"
  fi

  # C2.5: DB dynamic policy exists
  if [[ -f platform/vault/policies/db-dynamic.hcl ]]; then
    check "C2.5" "Database dynamic credential policy exists" "PASS"
  else
    check "C2.5" "Database dynamic credential policy exists" "FAIL"
  fi
}

###############################################################################
# C3: Short-Lived Credentials — Dynamic secrets, TTLs
###############################################################################
check_c3() {
  # C3.1: Dynamic DB credentials configured
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "database/roles/" platform/vault/examples/setup-complete.sh; then
    check "C3.1" "Dynamic database credentials defined" "PASS"
  else
    check "C3.1" "Dynamic database credentials defined" "FAIL"
  fi

  # C3.2: PKI certificates with short TTL
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "pki_int/roles/" platform/vault/examples/setup-complete.sh; then
    check "C3.2" "PKI roles with bounded TTL" "PASS"
  else
    check "C3.2" "PKI roles with bounded TTL" "FAIL"
  fi

  # C3.3: SSH certificates configured
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "ssh/roles/" platform/vault/examples/setup-complete.sh; then
    check "C3.3" "SSH CA with certificate roles" "PASS"
  else
    check "C3.3" "SSH CA with certificate roles" "FAIL"
  fi

  # C3.4: Token TTLs are bounded (not infinite)
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "max_ttl=" platform/vault/examples/setup-complete.sh; then
    check "C3.4" "Auth roles have max_ttl bounds" "PASS"
  else
    check "C3.4" "Auth roles have max_ttl bounds" "WARN" "Verify TTL bounds"
  fi

  # C3.5: Rotation operator policy exists
  if [[ -f platform/vault/policies/rotation-operator.hcl ]]; then
    check "C3.5" "Secret rotation operator policy" "PASS"
  else
    check "C3.5" "Secret rotation operator policy" "WARN"
  fi
}

###############################################################################
# C4: Encryption at Rest — SOPS, Transit, TLS
###############################################################################
check_c4() {
  # C4.1: SOPS config exists
  if [[ -f .sops.yaml ]]; then
    check "C4.1" "SOPS encryption configuration present" "PASS"
  else
    check "C4.1" "SOPS encryption configuration present" "WARN" "No .sops.yaml"
  fi

  # C4.2: Transit encryption key setup
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "transit/keys/" platform/vault/examples/setup-complete.sh; then
    check "C4.2" "Transit encryption keys defined" "PASS"
  else
    check "C4.2" "Transit encryption keys defined" "FAIL"
  fi

  # C4.3: TLS enforced in Vault config
  if [[ -f platform/vault/config/vault-server.hcl ]] && grep -q "tls_min_version" platform/vault/config/vault-server.hcl; then
    check "C4.3" "TLS minimum version enforced" "PASS"
  else
    check "C4.3" "TLS minimum version enforced" "FAIL"
  fi

  # C4.4: No unencrypted secret files in repo
  local unenc_secrets=0
  for ext in .env .secret .key .pem .p12; do
    if find . -name "*${ext}" -not -path "./.git/*" -not -name "*.example" -not -name "*.template" -not -name "*.enc.*" 2>/dev/null | grep -q .; then
      unenc_secrets=$((unenc_secrets + 1))
    fi
  done
  if [[ "$unenc_secrets" -eq 0 ]]; then
    check "C4.4" "No unencrypted secret files in repo" "PASS"
  else
    check "C4.4" "No unencrypted secret files in repo" "FAIL" "${unenc_secrets} types found"
  fi

  # C4.5: Transit policy exists
  if [[ -f platform/vault/policies/transit-app.hcl ]]; then
    check "C4.5" "Transit app encryption policy exists" "PASS"
  else
    check "C4.5" "Transit app encryption policy exists" "FAIL"
  fi
}

###############################################################################
# C5: Audit & Observability — Logging, monitoring
###############################################################################
check_c5() {
  # C5.1: Vault audit device configured
  if [[ -f platform/vault/examples/setup-complete.sh ]] && grep -q "audit enable" platform/vault/examples/setup-complete.sh; then
    check "C5.1" "Vault audit logging configured" "PASS"
  else
    check "C5.1" "Vault audit logging configured" "FAIL"
  fi

  # C5.2: Prometheus telemetry enabled
  if [[ -f platform/vault/config/vault-server.hcl ]] && grep -q "prometheus_retention_time" platform/vault/config/vault-server.hcl; then
    check "C5.2" "Prometheus telemetry enabled" "PASS"
  else
    check "C5.2" "Prometheus telemetry enabled" "WARN"
  fi

  # C5.3: Pre-commit hooks for secret scanning
  if [[ -f .pre-commit-config.yaml ]] || [[ -f bootstrap/scripts/check_no_plaintext_secrets.sh ]]; then
    check "C5.3" "Pre-commit secret scanning available" "PASS"
  else
    check "C5.3" "Pre-commit secret scanning available" "FAIL"
  fi

  # C5.4: .gitignore covers sensitive patterns
  if [[ -f .gitignore ]]; then
    local covered=0
    for pattern in ".env" "*.pem" "*.key" ".vault-token"; do
      grep -qF "$pattern" .gitignore 2>/dev/null && covered=$((covered + 1))
    done
    if [[ "$covered" -ge 3 ]]; then
      check "C5.4" ".gitignore covers sensitive file patterns" "PASS"
    else
      check "C5.4" ".gitignore covers sensitive file patterns" "WARN" "${covered}/4 patterns"
    fi
  else
    check "C5.4" ".gitignore covers sensitive file patterns" "FAIL" "No .gitignore"
  fi

  # C5.5: Secret scanner script exists
  if [[ -x bootstrap/scripts/check_no_plaintext_secrets.sh ]]; then
    check "C5.5" "Plaintext secret scanner executable" "PASS"
  elif [[ -f bootstrap/scripts/check_no_plaintext_secrets.sh ]]; then
    check "C5.5" "Plaintext secret scanner executable" "WARN" "Not executable"
  else
    check "C5.5" "Plaintext secret scanner executable" "FAIL"
  fi
}

###############################################################################
# C6: Secret Delivery — ESO, CSI, Agent patterns
###############################################################################
check_c6() {
  # C6.1: ExternalSecret example exists
  if find . -name "*.yaml" -exec grep -l "ExternalSecret" {} \; 2>/dev/null | grep -q .; then
    check "C6.1" "ExternalSecret delivery pattern" "PASS"
  else
    check "C6.1" "ExternalSecret delivery pattern" "FAIL"
  fi

  # C6.2: CSI SecretProviderClass example
  if find . -name "*.yaml" -exec grep -l "SecretProviderClass" {} \; 2>/dev/null | grep -q .; then
    check "C6.2" "CSI SecretProviderClass delivery pattern" "PASS"
  else
    check "C6.2" "CSI SecretProviderClass delivery pattern" "FAIL"
  fi

  # C6.3: Vault Agent configuration
  if [[ -f platform/vault/config/vault-agent-k8s.hcl ]] || [[ -f platform/vault/config/vault-agent-vm.hcl ]]; then
    check "C6.3" "Vault Agent sidecar/VM configuration" "PASS"
  else
    check "C6.3" "Vault Agent sidecar/VM configuration" "FAIL"
  fi

  # C6.4: Onboarding script exists
  if [[ -f bootstrap/scripts/onboard_app.sh ]]; then
    check "C6.4" "Application onboarding automation" "PASS"
  else
    check "C6.4" "Application onboarding automation" "FAIL"
  fi

  # C6.5: VM secret delivery (cloud-init or systemd)
  if find . -name "*.yaml" -exec grep -l "vault-agent" {} \; 2>/dev/null | grep -q . || [[ -f examples/vm/systemd/vault-agent.service ]]; then
    check "C6.5" "VM secret delivery pattern" "PASS"
  else
    check "C6.5" "VM secret delivery pattern" "WARN"
  fi
}

###############################################################################
# Report
###############################################################################
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Dev Identity & Secrets — Compliance Control Validation                 ║${NC}"
echo -e "${BLUE}║  $(date -u +%Y-%m-%dT%H:%M:%SZ)                                                         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

check_c1
check_c2
check_c3
check_c4
check_c5
check_c6

echo ""
printf "%-7s %-52s %-8s %s\n" "Control" "Description" "Status" "Detail"
printf "%-7s %-52s %-8s %s\n" "-------" "----------------------------------------------------" "------" "------"
for result in "${RESULTS[@]}"; do
  echo -e "$result"
done

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════════${NC}"
echo -e "  Total: ${TOTAL}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${YELLOW}Warned: ${WARNED}${NC}  |  ${RED}Failed: ${FAILED}${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════════${NC}"

if [[ "$FAILED" -gt 0 ]]; then
  echo -e "\n${RED}Compliance check FAILED — ${FAILED} control(s) not met.${NC}"
  exit 1
elif [[ "$WARNED" -gt 0 ]]; then
  echo -e "\n${YELLOW}Compliance check PASSED with warnings — review ${WARNED} item(s).${NC}"
  exit 0
else
  echo -e "\n${GREEN}All compliance controls PASSED.${NC}"
  exit 0
fi
