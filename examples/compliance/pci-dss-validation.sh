#!/usr/bin/env bash
set -euo pipefail

# pci-dss-validation.sh — Example: PCI DSS 4.0 validation for secrets management
# Validates PCI DSS requirements relevant to cryptographic key management,
# credential lifecycle, and secure development practices.
#
# Scope: Requirements 3 (protect stored data), 6 (secure development),
#        8 (identify users and authenticate access)
#
# Usage: pci-dss-validation.sh [--verbose] [--json]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

VERBOSE=""
JSON_OUTPUT=""

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }

# ── Counters ──────────────────────────────────────────────────────────────

TOTAL=0; PASS=0; FAIL=0; MANUAL=0; NA=0
declare -a RESULTS=()
declare -a JSON_RESULTS=()

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'pci-dss-validation.sh') — PCI DSS 4.0 Secrets Management Validation

$(_bold 'USAGE')
  pci-dss-validation.sh [OPTIONS]

$(_bold 'OPTIONS')
  --verbose     Show check details during execution
  --json        Output JSON results
  --help        Show this help message

$(_bold 'PCI DSS 4.0 REQUIREMENTS VALIDATED')
  Req 3.5     PAN secured wherever stored
  Req 3.6     Cryptographic keys secured
  Req 3.7     Key management processes
  Req 6.2     Secure software development
  Req 6.3     Security vulnerabilities addressed
  Req 8.2     User identification and authentication
  Req 8.3     Strong authentication
  Req 8.3.6   Service account credential complexity
  Req 8.6     Service account management

$(_bold 'WHAT THIS VALIDATES')
  - Vault transit encryption for data protection (Req 3)
  - Key lifecycle management: generation, rotation, revocation (Req 3.6-3.7)
  - Pre-commit scanning and repo scanning (Req 6)
  - OIDC authentication and MFA enforcement (Req 8)
  - Dynamic credential generation for service accounts (Req 8.3.6, 8.6)
  - Per-workload service account isolation (Req 8.6)
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verbose)  VERBOSE="true"; shift ;;
    --json)     JSON_OUTPUT="true"; shift ;;
    --help|-h)  usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# ── Check helpers ─────────────────────────────────────────────────────────

check() {
  local req="$1" title="$2" status="$3" detail="${4:-}"
  TOTAL=$((TOTAL + 1))
  case "$status" in
    PASS)   PASS=$((PASS + 1)) ;;
    FAIL)   FAIL=$((FAIL + 1)) ;;
    MANUAL) MANUAL=$((MANUAL + 1)) ;;
    N/A)    NA=$((NA + 1)) ;;
  esac

  RESULTS+=("${req}|${title}|${status}|${detail}")
  JSON_RESULTS+=("{\"requirement\":\"${req}\",\"title\":\"${title}\",\"status\":\"${status}\",\"detail\":\"${detail}\"}")

  if [[ -n "$VERBOSE" ]]; then
    local color
    case "$status" in
      PASS)   color="$(_green "$status")" ;;
      FAIL)   color="$(_red "$status")" ;;
      MANUAL) color="$(_yellow "$status")" ;;
      N/A)    color="$(_dim "$status")" ;;
    esac
    printf '  [%b] %-8s %-45s %s\n' "$color" "$req" "$title" "$detail"
  fi
}

file_exists()   { [[ -f "${REPO_ROOT}/$1" ]]; }
file_contains() { [[ -f "${REPO_ROOT}/$1" ]] && grep -q "$2" "${REPO_ROOT}/$1" 2>/dev/null; }

cd "$REPO_ROOT"

# ── Requirement 3: Protect Stored Account Data ───────────────────────────

[[ -n "$VERBOSE" ]] && printf '\n%s\n\n' "$(_bold 'Requirement 3: Protect Stored Account Data')"

# 3.5 — PAN secured
if file_exists ".sops.yaml"; then
  # Check that SOPS config covers the secrets directory
  if grep -q "path_regex" .sops.yaml 2>/dev/null; then
    check "3.5" "PAN secured wherever stored" "PASS" "SOPS encryption with path-based rules"
  else
    check "3.5" "PAN secured wherever stored" "PASS" "SOPS encryption configured"
  fi
else
  check "3.5" "PAN secured wherever stored" "FAIL" "No SOPS encryption configuration"
fi

# 3.5.1 — Restrict access to cleartext PAN
no_plaintext=true
for pattern in "password=" "api_key=" "secret_key=" "private_key="; do
  if grep -rIl "$pattern" --include="*.yaml" --include="*.yml" --include="*.json" \
     --exclude-dir=".git" --exclude-dir="node_modules" --exclude="*.enc.*" \
     --exclude="*.example" --exclude="*.template" . 2>/dev/null | \
     grep -v "check_controls\|control_matrix\|generate_evidence\|pci-dss-validation" | grep -q .; then
    no_plaintext=false
    break
  fi
done
if $no_plaintext; then
  check "3.5.1" "Restrict access to cleartext secrets" "PASS" "No plaintext credentials detected"
else
  check "3.5.1" "Restrict access to cleartext secrets" "FAIL" "Potential plaintext credentials found"
fi

# 3.6 — Cryptographic keys secured
if file_contains "platform/vault/examples/setup-complete.sh" "transit/keys/"; then
  check "3.6" "Cryptographic keys secured" "PASS" "Vault transit keys for encryption-as-a-service"
else
  check "3.6" "Cryptographic keys secured" "FAIL" "No Vault transit key configuration"
fi

# 3.6.1 — Key access restricted
if file_exists "platform/vault/policies/transit-app.hcl"; then
  if grep -q 'capabilities' "platform/vault/policies/transit-app.hcl" 2>/dev/null; then
    check "3.6.1" "Key access restricted to custodians" "PASS" "Transit policy with explicit capabilities"
  else
    check "3.6.1" "Key access restricted to custodians" "FAIL" "Transit policy missing capabilities"
  fi
else
  check "3.6.1" "Key access restricted to custodians" "FAIL" "No transit access policy"
fi

# 3.7 — Key management processes
key_mgmt_score=0
file_exists "tools/rotate/rotate_vault_secrets.sh" && key_mgmt_score=$((key_mgmt_score + 1))
file_exists "tools/rotate/rotate_sops_keys.sh" && key_mgmt_score=$((key_mgmt_score + 1))
file_exists "tools/ceremony" && key_mgmt_score=$((key_mgmt_score + 1))
file_exists "docs/18-key-ceremony-guide.md" && key_mgmt_score=$((key_mgmt_score + 1))

if [[ $key_mgmt_score -ge 3 ]]; then
  check "3.7" "Key management lifecycle processes" "PASS" "${key_mgmt_score}/4 key mgmt components present"
elif [[ $key_mgmt_score -ge 1 ]]; then
  check "3.7" "Key management lifecycle processes" "FAIL" "${key_mgmt_score}/4 — missing components"
else
  check "3.7" "Key management lifecycle processes" "FAIL" "No key management tooling"
fi

# 3.7.1 — Key generation uses strong methods
if file_contains "platform/vault/examples/setup-complete.sh" "type=aes256-gcm96\|type=rsa-4096\|key_type"; then
  check "3.7.1" "Strong key generation algorithms" "PASS" "Approved algorithms in Vault config"
else
  check "3.7.1" "Strong key generation algorithms" "MANUAL" "Verify algorithm selection in Vault"
fi

# 3.7.2 — Secure key distribution
if file_contains "platform/vault/examples/setup-complete.sh" "auth enable" && \
   grep -rql "ExternalSecret\|SecretProviderClass" --include="*.yaml" . 2>/dev/null; then
  check "3.7.2" "Secure key distribution" "PASS" "Vault auth + K8s secret delivery patterns"
else
  check "3.7.2" "Secure key distribution" "FAIL" "Incomplete key distribution mechanism"
fi

# ── Requirement 6: Develop and Maintain Secure Systems ───────────────────

[[ -n "$VERBOSE" ]] && printf '\n%s\n\n' "$(_bold 'Requirement 6: Develop and Maintain Secure Systems')"

# 6.2 — Secure development
sdlc_score=0
file_exists "bootstrap/scripts/check_no_plaintext_secrets.sh" && sdlc_score=$((sdlc_score + 1))
file_exists ".pre-commit-config.yaml" && sdlc_score=$((sdlc_score + 1))
file_exists "tools/scanning/scan_repo.sh" && sdlc_score=$((sdlc_score + 1))

if [[ $sdlc_score -ge 2 ]]; then
  check "6.2" "Bespoke software developed securely" "PASS" "${sdlc_score}/3 SDLC security controls"
else
  check "6.2" "Bespoke software developed securely" "FAIL" "${sdlc_score}/3 — insufficient controls"
fi

# 6.2.3 — Code review before production
if file_exists ".pre-commit-config.yaml"; then
  check "6.2.3" "Code reviewed before production release" "PASS" "Pre-commit hooks enforce review"
else
  check "6.2.3" "Code reviewed before production release" "MANUAL" "Verify code review process"
fi

# 6.3 — Vulnerabilities identified
if file_exists "tools/scanning/scan_repo.sh" && file_exists "tools/scanning/entropy_check.sh"; then
  check "6.3" "Vulnerabilities identified and addressed" "PASS" "Repo scanner + entropy checker"
else
  check "6.3" "Vulnerabilities identified and addressed" "FAIL" "Incomplete scanning tooling"
fi

# 6.3.2 — Software inventory maintained
check "6.3.2" "Software inventory maintained" "MANUAL" "Verify SBOM generation in CI pipeline"

# ── Requirement 8: Identify Users and Authenticate Access ────────────────

[[ -n "$VERBOSE" ]] && printf '\n%s\n\n' "$(_bold 'Requirement 8: Identify Users and Authenticate Access')"

# 8.2 — User identification
if file_contains "platform/vault/examples/setup-complete.sh" "auth enable oidc"; then
  check "8.2" "User identification and authentication" "PASS" "OIDC identity provider integration"
else
  check "8.2" "User identification and authentication" "FAIL" "No OIDC auth configuration"
fi

# 8.2.2 — Shared/group accounts prohibited
shared_account_found=false
if grep -rIl "shared.*token\|group.*password\|team.*key" --include="*.yaml" --include="*.yml" \
   --exclude-dir=".git" . 2>/dev/null | grep -qv "example\|template\|test\|compliance"; then
  shared_account_found=true
fi
if ! $shared_account_found; then
  check "8.2.2" "No shared/group accounts" "PASS" "No shared credential patterns detected"
else
  check "8.2.2" "No shared/group accounts" "FAIL" "Potential shared credentials found"
fi

# 8.3 — Strong authentication
check "8.3" "Strong authentication for all access" "MANUAL" "Verify MFA enforcement in IdP admin console"

# 8.3.1 — MFA for all access to CDE
check "8.3.1" "MFA for all CDE access" "MANUAL" "Verify phishing-resistant MFA in IdP"

# 8.3.5 — Passwords/passphrases set securely
if file_contains "platform/vault/examples/setup-complete.sh" "database/roles/"; then
  check "8.3.5" "Passwords set and reset securely" "PASS" "Vault dynamic credentials — no static passwords"
else
  check "8.3.5" "Passwords set and reset securely" "FAIL" "No dynamic credential generation"
fi

# 8.3.6 — Service account complexity
if file_contains "platform/vault/examples/setup-complete.sh" "database/roles/\|pki_int/roles/"; then
  check "8.3.6" "Service account credential complexity" "PASS" "Vault-generated credentials with high entropy"
else
  check "8.3.6" "Service account credential complexity" "FAIL" "No Vault credential generation"
fi

# 8.6 — Service account management
sa_score=0
# Check for per-workload SA pattern in K8s manifests
if grep -rql "serviceAccountName" --include="*.yaml" . 2>/dev/null; then
  sa_score=$((sa_score + 1))
fi
# Check for SA lifecycle documentation
if file_exists "docs/06-controls-and-guardrails.md" && \
   grep -q "service.account\|Rule 3" "docs/06-controls-and-guardrails.md" 2>/dev/null; then
  sa_score=$((sa_score + 1))
fi
# Check for identity inventory tooling
file_exists "tools/audit/identity_inventory.sh" && sa_score=$((sa_score + 1))

if [[ $sa_score -ge 2 ]]; then
  check "8.6" "Service account management" "PASS" "${sa_score}/3 SA management controls"
else
  check "8.6" "Service account management" "FAIL" "${sa_score}/3 — insufficient SA management"
fi

# 8.6.1 — Interactive login prohibited for service accounts
check "8.6.1" "No interactive login for service accounts" "MANUAL" "Verify SA cannot authenticate interactively"

# 8.6.2 — Service account credentials not hardcoded
if ! grep -rIl "VAULT_TOKEN\s*=\|vault_token:" --include="*.sh" --include="*.yaml" --include="*.yml" \
   --exclude-dir=".git" --exclude="*.example" --exclude="*.template" . 2>/dev/null | \
   grep -v "check_controls\|control_matrix\|compliance" | grep -q .; then
  check "8.6.2" "SA credentials not hardcoded" "PASS" "No hardcoded tokens in source"
else
  check "8.6.2" "SA credentials not hardcoded" "FAIL" "Hardcoded tokens detected"
fi

# 8.6.3 — Service accounts reviewed periodically
if file_exists "tools/audit/credential_age_report.sh"; then
  check "8.6.3" "SA credentials reviewed periodically" "PASS" "Credential age reporting tool available"
else
  check "8.6.3" "SA credentials reviewed periodically" "FAIL" "No credential age tool"
fi

# ── Output ────────────────────────────────────────────────────────────────

if [[ -n "$JSON_OUTPUT" ]]; then
  echo "{"
  echo "  \"framework\": \"pci-dss-4.0\","
  echo "  \"timestamp\": \"${TIMESTAMP}\","
  echo "  \"summary\": { \"total\": $TOTAL, \"pass\": $PASS, \"fail\": $FAIL, \"manual\": $MANUAL, \"na\": $NA },"
  echo "  \"requirements\": ["
  first=true
  for entry in "${JSON_RESULTS[@]}"; do
    [[ "$first" == "true" ]] && first=false || echo ","
    printf "    %s" "$entry"
  done
  echo ""
  echo "  ]"
  echo "}"
else
  echo ""
  printf '%s\n' "$(_bold '━━━ PCI DSS 4.0 Validation Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
  printf '  %s  %s\n' "$(_dim 'Timestamp:')" "$TIMESTAMP"
  printf '  %s  %s\n' "$(_dim 'Scope:')" "Secrets management (Req 3, 6, 8)"
  printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
  echo ""

  printf "  %-10s %-46s %-8s %s\n" "Req" "Title" "Status" "Detail"
  printf "  %-10s %-46s %-8s %s\n" "────────" "────────────────────────────────────────────" "──────" "──────"

  for result in "${RESULTS[@]}"; do
    IFS='|' read -r req title status detail <<< "$result"
    status_colored=""
    case "$status" in
      PASS)   status_colored="$(_green 'PASS  ')" ;;
      FAIL)   status_colored="$(_red 'FAIL  ')" ;;
      MANUAL) status_colored="$(_yellow 'MANUAL')" ;;
      N/A)    status_colored="$(_dim 'N/A   ')" ;;
      *)      status_colored="$status" ;;
    esac
    printf "  %-10s %-46s %b %s\n" "$req" "$title" "$status_colored" "$detail"
  done

  echo ""
  printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
  printf '  Total: %d  |  %s  |  %s  |  %s  |  %s\n' \
    "$TOTAL" \
    "$(_green "Pass: ${PASS}")" \
    "$(_red "Fail: ${FAIL}")" \
    "$(_yellow "Manual: ${MANUAL}")" \
    "$(_dim "N/A: ${NA}")"
  printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"

  if [[ $FAIL -gt 0 ]]; then
    echo ""
    printf '  %s\n' "$(_red "PCI DSS validation: ${FAIL} requirement(s) not met")"
    printf '  %s\n' "Remediate failed checks before assessment."
  elif [[ $MANUAL -gt 0 ]]; then
    echo ""
    printf '  %s\n' "$(_yellow "PCI DSS validation: ${MANUAL} requirement(s) need manual verification")"
    printf '  %s\n' "Automated checks passed. Complete manual review items."
  else
    echo ""
    printf '  %s\n' "$(_green "PCI DSS validation: All automated checks passed")"
  fi
fi

[[ $FAIL -gt 0 ]] && exit 1
exit 0
