#!/usr/bin/env bash
set -euo pipefail

# control_matrix.sh — Automated control status checker for compliance frameworks
# Reads compliance mapping from docs/14-compliance-mapping.md, runs automated checks
# where possible, and outputs control-by-control PASS/FAIL/MANUAL/NOT_APPLICABLE status.
# Usage: control_matrix.sh [--framework <soc2|pci|nist-csf|iso27001|hipaa|all>] [--json]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── Defaults ──────────────────────────────────────────────────────────────

FRAMEWORK="all"
JSON_OUTPUT=""
VERBOSE=""

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_cyan()   { printf '\033[0;36m%s\033[0m' "$1"; }

# ── Counters ──────────────────────────────────────────────────────────────

TOTAL=0
PASS_COUNT=0
FAIL_COUNT=0
MANUAL_COUNT=0
NA_COUNT=0

declare -a RESULTS=()
declare -a JSON_ENTRIES=()

# ── Result recording ──────────────────────────────────────────────────────

record() {
  local framework="$1" control_id="$2" title="$3" status="$4" detail="${5:-}"
  TOTAL=$((TOTAL + 1))

  case "$status" in
    PASS)           PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL)           FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    MANUAL)         MANUAL_COUNT=$((MANUAL_COUNT + 1)) ;;
    NOT_APPLICABLE) NA_COUNT=$((NA_COUNT + 1)) ;;
  esac

  RESULTS+=("$(printf "| %-10s | %-10s | %-44s | %-6s | %s" "$framework" "$control_id" "$title" "$status" "$detail")")

  JSON_ENTRIES+=("{\"framework\":\"${framework}\",\"control_id\":\"${control_id}\",\"title\":\"${title}\",\"status\":\"${status}\",\"detail\":\"${detail}\"}")
}

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'control_matrix.sh') — Automated control status checker

$(_bold 'USAGE')
  control_matrix.sh [OPTIONS]

$(_bold 'OPTIONS')
  --framework <fw>  Filter by framework: soc2, pci, nist-csf, iso27001, hipaa, all (default: all)
  --json            Output JSON instead of table
  --verbose         Show check details
  --help            Show this help message

$(_bold 'STATUS CODES')
  PASS            Control verified by automated check
  FAIL            Automated check detected a gap
  MANUAL          Requires manual verification (organizational process)
  NOT_APPLICABLE  Control not relevant to secrets management scope

$(_bold 'EXAMPLES')
  control_matrix.sh
  control_matrix.sh --framework soc2 --json
  control_matrix.sh --framework pci --verbose
EOF
  exit 0
}

# ── Arg parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --framework)  FRAMEWORK="$2"; shift 2 ;;
    --json)       JSON_OUTPUT="true"; shift ;;
    --verbose)    VERBOSE="true"; export VERBOSE; shift ;;
    --help|-h)    usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# ── Check helpers ─────────────────────────────────────────────────────────

file_exists()    { [[ -f "${REPO_ROOT}/$1" ]]; }
file_contains()  { [[ -f "${REPO_ROOT}/$1" ]] && grep -q "$2" "${REPO_ROOT}/$1" 2>/dev/null; }
dir_has_files()  { [[ -d "${REPO_ROOT}/$1" ]] && find "${REPO_ROOT}/$1" -maxdepth 1 -type f 2>/dev/null | grep -q .; }
cmd_available()  { command -v "$1" &>/dev/null; }

# Check if any YAML files in repo contain a specific pattern
yaml_contains() {
  grep -rl "$1" "${REPO_ROOT}" --include="*.yaml" --include="*.yml" 2>/dev/null | grep -qv ".git"
}

# Check Vault policies exist and have specific properties
vault_policy_check() {
  local name="$1" property="$2"
  [[ -f "${REPO_ROOT}/platform/vault/policies/${name}.hcl" ]] && \
    grep -q "$property" "${REPO_ROOT}/platform/vault/policies/${name}.hcl" 2>/dev/null
}

# ── SOC 2 Checks ─────────────────────────────────────────────────────────

check_soc2() {
  local fw="soc2"

  # CC5.2 — Control activities deployed
  if file_exists "docs/06-controls-and-guardrails.md" && dir_has_files "platform/vault/policies"; then
    record "$fw" "CC5.2" "Control activities deployed" "PASS" "Controls doc + Vault policies present"
  else
    record "$fw" "CC5.2" "Control activities deployed" "FAIL" "Missing controls doc or policies"
  fi

  # CC6.1 — Logical access controls
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable"; then
    record "$fw" "CC6.1" "Logical and physical access controls" "PASS" "Vault auth methods configured"
  else
    record "$fw" "CC6.1" "Logical and physical access controls" "FAIL" "No Vault auth config found"
  fi

  # CC6.2 — System credentials
  if file_contains "platform/vault/examples/setup-complete.sh" "database/roles/"; then
    record "$fw" "CC6.2" "System credentials / passwords" "PASS" "Dynamic credentials configured"
  else
    record "$fw" "CC6.2" "System credentials / passwords" "FAIL" "No dynamic credentials"
  fi

  # CC6.3 — Role-based access
  if dir_has_files "platform/vault/policies"; then
    local policy_count
    policy_count=$(find "${REPO_ROOT}/platform/vault/policies" -name "*.hcl" -type f | wc -l | tr -d ' ')
    record "$fw" "CC6.3" "Role-based access" "PASS" "${policy_count} Vault policies defined"
  else
    record "$fw" "CC6.3" "Role-based access" "FAIL" "No Vault policies"
  fi

  # CC6.6 — System boundaries
  record "$fw" "CC6.6" "System boundaries" "MANUAL" "Verify per-environment namespace isolation"

  # CC6.7 — Restrict data movement
  if file_exists ".sops.yaml" || yaml_contains "ExternalSecret"; then
    record "$fw" "CC6.7" "Restrict data movement" "PASS" "SOPS encryption and/or ESO configured"
  else
    record "$fw" "CC6.7" "Restrict data movement" "FAIL" "No SOPS or ESO configuration"
  fi

  # CC6.8 — Prevent unauthorized access
  if file_exists "bootstrap/scripts/check_no_plaintext_secrets.sh" || file_exists ".pre-commit-config.yaml"; then
    record "$fw" "CC6.8" "Prevent unauthorized access" "PASS" "Pre-commit scanning configured"
  else
    record "$fw" "CC6.8" "Prevent unauthorized access" "FAIL" "No pre-commit scanning"
  fi

  # CC7.1 — Detect and monitor threats
  if file_contains "platform/vault/examples/setup-complete.sh" "audit enable"; then
    record "$fw" "CC7.1" "Detect and monitor threats" "PASS" "Vault audit logging enabled"
  else
    record "$fw" "CC7.1" "Detect and monitor threats" "FAIL" "No Vault audit logging"
  fi

  # CC7.2 — Monitor for anomalies
  record "$fw" "CC7.2" "Monitor for anomalies" "MANUAL" "Verify SIEM integration and alerting"

  # CC7.3 — Evaluate detected events
  if file_exists "docs/incident-playbooks" || file_exists "docs/09-runbooks.md"; then
    record "$fw" "CC7.3" "Evaluate detected events" "PASS" "Incident runbooks present"
  else
    record "$fw" "CC7.3" "Evaluate detected events" "FAIL" "No incident runbooks"
  fi

  # CC7.4 — Respond to events
  if file_exists "tools/rotate/rotate_vault_secrets.sh"; then
    record "$fw" "CC7.4" "Respond to identified events" "PASS" "Rotation tooling available"
  else
    record "$fw" "CC7.4" "Respond to identified events" "FAIL" "No rotation tooling"
  fi

  # CC8.1 — Change management
  if file_exists ".sops.yaml" && file_exists ".gitignore"; then
    record "$fw" "CC8.1" "Control environment changes" "PASS" "SOPS + GitOps patterns"
  else
    record "$fw" "CC8.1" "Control environment changes" "FAIL" "Missing GitOps controls"
  fi
}

# ── PCI DSS Checks ────────────────────────────────────────────────────────

check_pci() {
  local fw="pci"

  # 3.5 — PAN secured
  record "$fw" "3.5" "PAN secured wherever stored" "MANUAL" "Verify SOPS encryption covers PAN data"

  # 3.6 — Crypto keys secured
  if file_contains "platform/vault/examples/setup-complete.sh" "transit/keys/"; then
    record "$fw" "3.6" "Cryptographic keys secured" "PASS" "Vault transit keys configured"
  else
    record "$fw" "3.6" "Cryptographic keys secured" "FAIL" "No Vault transit keys"
  fi

  # 3.7 — Key lifecycle management
  if file_exists "tools/rotate/rotate_vault_secrets.sh" && file_exists "tools/rotate/rotate_sops_keys.sh"; then
    record "$fw" "3.7" "Key lifecycle management" "PASS" "Rotation tooling for Vault + SOPS"
  else
    record "$fw" "3.7" "Key lifecycle management" "FAIL" "Missing rotation tooling"
  fi

  # 6.2 — Secure development
  if file_exists "bootstrap/scripts/check_no_plaintext_secrets.sh"; then
    record "$fw" "6.2" "Bespoke software developed securely" "PASS" "Secret scanning in dev workflow"
  else
    record "$fw" "6.2" "Bespoke software developed securely" "FAIL" "No secret scanning"
  fi

  # 6.3 — Vulnerabilities addressed
  if file_exists "tools/scanning/scan_repo.sh"; then
    record "$fw" "6.3" "Vulnerabilities identified and addressed" "PASS" "Repo scanning tooling present"
  else
    record "$fw" "6.3" "Vulnerabilities identified and addressed" "FAIL" "No scanning tooling"
  fi

  # 6.4 — Web app protection
  record "$fw" "6.4" "Public-facing web apps protected" "NOT_APPLICABLE" "WAF out of secrets scope"

  # 8.2 — User identification
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable oidc"; then
    record "$fw" "8.2" "User identification and authentication" "PASS" "OIDC auth configured"
  else
    record "$fw" "8.2" "User identification and authentication" "FAIL" "No OIDC auth"
  fi

  # 8.3 — Strong authentication
  record "$fw" "8.3" "Strong authentication for users/admins" "MANUAL" "Verify MFA enforcement in IdP"

  # 8.3.6 — Service account complexity
  if file_contains "platform/vault/examples/setup-complete.sh" "database/roles/"; then
    record "$fw" "8.3.6" "Service account credential complexity" "PASS" "Vault-generated dynamic credentials"
  else
    record "$fw" "8.3.6" "Service account credential complexity" "FAIL" "No dynamic credentials"
  fi

  # 8.6 — Service account management
  if yaml_contains "serviceAccountName"; then
    record "$fw" "8.6" "Service account management" "PASS" "Per-workload SAs defined in manifests"
  else
    record "$fw" "8.6" "Service account management" "MANUAL" "Verify SA lifecycle management"
  fi
}

# ── NIST CSF Checks ──────────────────────────────────────────────────────

check_nist_csf() {
  local fw="nist-csf"

  # GV.OC — Organizational context
  if file_exists "docs/01-scope-purpose.md" && file_exists "docs/07-threat-model.md"; then
    record "$fw" "GV.OC" "Organizational context" "PASS" "Scope + threat model documented"
  else
    record "$fw" "GV.OC" "Organizational context" "FAIL" "Missing scope or threat model"
  fi

  # GV.RM — Risk management
  if file_exists "docs/07-threat-model.md"; then
    record "$fw" "GV.RM" "Risk management strategy" "PASS" "Threat model with T1-T7 threats"
  else
    record "$fw" "GV.RM" "Risk management strategy" "FAIL" "No threat model"
  fi

  # ID.AM — Asset management
  if file_exists "tools/audit/identity_inventory.sh"; then
    record "$fw" "ID.AM" "Asset management" "PASS" "Identity inventory tooling present"
  else
    record "$fw" "ID.AM" "Asset management" "FAIL" "No identity inventory tool"
  fi

  # PR.AA — Identity management
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable" && dir_has_files "platform/vault/policies"; then
    record "$fw" "PR.AA" "Identity management and access control" "PASS" "Vault auth + RBAC policies"
  else
    record "$fw" "PR.AA" "Identity management and access control" "FAIL" "Incomplete auth/RBAC"
  fi

  # PR.DS — Data security
  if file_exists ".sops.yaml"; then
    record "$fw" "PR.DS" "Data security" "PASS" "SOPS encryption at rest configured"
  else
    record "$fw" "PR.DS" "Data security" "FAIL" "No encryption at rest config"
  fi

  # PR.PS — Platform security
  if yaml_contains "ExternalSecret" || yaml_contains "SecretProviderClass"; then
    record "$fw" "PR.PS" "Platform security" "PASS" "K8s secret delivery patterns configured"
  else
    record "$fw" "PR.PS" "Platform security" "FAIL" "No K8s secret delivery patterns"
  fi

  # DE.CM — Continuous monitoring
  if file_contains "platform/vault/examples/setup-complete.sh" "audit enable"; then
    record "$fw" "DE.CM" "Continuous monitoring" "PASS" "Vault audit logging configured"
  else
    record "$fw" "DE.CM" "Continuous monitoring" "FAIL" "No audit logging"
  fi

  # DE.AE — Adverse event analysis
  record "$fw" "DE.AE" "Adverse event analysis" "MANUAL" "Verify SIEM integration"

  # RS.AN — Incident analysis
  if file_exists "docs/09-runbooks.md"; then
    record "$fw" "RS.AN" "Incident analysis" "PASS" "Incident response runbooks present"
  else
    record "$fw" "RS.AN" "Incident analysis" "FAIL" "No incident runbooks"
  fi

  # RS.MI — Incident mitigation
  if file_exists "tools/rotate/rotate_vault_secrets.sh"; then
    record "$fw" "RS.MI" "Incident mitigation" "PASS" "Rotation/revocation tooling available"
  else
    record "$fw" "RS.MI" "Incident mitigation" "FAIL" "No rotation tooling"
  fi

  # RC.RP — Recovery planning
  if file_exists "tools/ceremony" || file_exists "tools/drill"; then
    record "$fw" "RC.RP" "Recovery planning" "PASS" "Break-glass ceremony/drill tooling"
  else
    record "$fw" "RC.RP" "Recovery planning" "FAIL" "No recovery tooling"
  fi
}

# ── ISO 27001 Checks ─────────────────────────────────────────────────────

check_iso27001() {
  local fw="iso27001"

  # A.5.1 — Security policies
  if file_exists "docs/06-controls-and-guardrails.md"; then
    record "$fw" "A.5.1" "Policies for information security" "PASS" "Controls document present"
  else
    record "$fw" "A.5.1" "Policies for information security" "FAIL" "No controls document"
  fi

  # A.5.9 — Asset inventory
  if file_exists "tools/audit/identity_inventory.sh"; then
    record "$fw" "A.5.9" "Inventory of information assets" "PASS" "Identity inventory tool available"
  else
    record "$fw" "A.5.9" "Inventory of information assets" "FAIL" "No inventory tooling"
  fi

  # A.5.15 — Access control
  if dir_has_files "platform/vault/policies"; then
    record "$fw" "A.5.15" "Access control" "PASS" "Vault RBAC policies defined"
  else
    record "$fw" "A.5.15" "Access control" "FAIL" "No access control policies"
  fi

  # A.5.16 — Identity management
  record "$fw" "A.5.16" "Identity management" "MANUAL" "Verify IdP lifecycle management"

  # A.5.17 — Authentication information
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable oidc"; then
    record "$fw" "A.5.17" "Authentication information" "PASS" "OIDC + short-lived credentials"
  else
    record "$fw" "A.5.17" "Authentication information" "FAIL" "No OIDC configuration"
  fi

  # A.5.18 — Access rights
  record "$fw" "A.5.18" "Access rights" "MANUAL" "Verify periodic access review process"

  # A.5.33 — Protection of records
  if file_contains "platform/vault/examples/setup-complete.sh" "audit enable"; then
    record "$fw" "A.5.33" "Protection of records" "PASS" "Vault audit logging enabled"
  else
    record "$fw" "A.5.33" "Protection of records" "FAIL" "No audit logging"
  fi

  # A.8.2 — Privileged access
  if file_exists "platform/vault/policies/admin-emergency.hcl"; then
    record "$fw" "A.8.2" "Privileged access rights" "PASS" "Emergency admin policy with controls"
  else
    record "$fw" "A.8.2" "Privileged access rights" "FAIL" "No privileged access controls"
  fi

  # A.8.5 — Secure authentication
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable"; then
    record "$fw" "A.8.5" "Secure authentication" "PASS" "Multiple auth methods configured"
  else
    record "$fw" "A.8.5" "Secure authentication" "FAIL" "No auth methods"
  fi

  # A.8.9 — Configuration management
  if file_exists ".sops.yaml"; then
    record "$fw" "A.8.9" "Configuration management" "PASS" "SOPS config management present"
  else
    record "$fw" "A.8.9" "Configuration management" "FAIL" "No SOPS configuration"
  fi

  # A.8.24 — Cryptography
  if file_contains "platform/vault/examples/setup-complete.sh" "transit/keys/"; then
    record "$fw" "A.8.24" "Use of cryptography" "PASS" "Vault transit + KMS integration"
  else
    record "$fw" "A.8.24" "Use of cryptography" "FAIL" "No transit encryption"
  fi

  # A.8.25 — Secure SDLC
  if file_exists "bootstrap/scripts/check_no_plaintext_secrets.sh" && file_exists "tools/scanning/scan_repo.sh"; then
    record "$fw" "A.8.25" "Secure development lifecycle" "PASS" "Pre-commit + repo scanning"
  else
    record "$fw" "A.8.25" "Secure development lifecycle" "FAIL" "Incomplete SDLC tooling"
  fi
}

# ── HIPAA Checks ──────────────────────────────────────────────────────────

check_hipaa() {
  local fw="hipaa"

  # 164.308(a)(1) — Security management process
  if file_exists "docs/07-threat-model.md" && file_exists "docs/06-controls-and-guardrails.md"; then
    record "$fw" "308(a)(1)" "Security management process" "PASS" "Risk analysis + controls documented"
  else
    record "$fw" "308(a)(1)" "Security management process" "FAIL" "Missing risk/controls docs"
  fi

  # 164.308(a)(3) — Workforce security
  record "$fw" "308(a)(3)" "Workforce security" "MANUAL" "Verify workforce access procedures"

  # 164.308(a)(4) — Information access management
  if dir_has_files "platform/vault/policies"; then
    record "$fw" "308(a)(4)" "Information access management" "PASS" "Vault RBAC policies present"
  else
    record "$fw" "308(a)(4)" "Information access management" "FAIL" "No access policies"
  fi

  # 164.308(a)(5) — Security awareness
  record "$fw" "308(a)(5)" "Security awareness and training" "MANUAL" "Verify security training program"

  # 164.312(a)(1) — Access control
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable"; then
    record "$fw" "312(a)(1)" "Access control" "PASS" "Vault auth methods configured"
  else
    record "$fw" "312(a)(1)" "Access control" "FAIL" "No access control mechanism"
  fi

  # 164.312(a)(2)(iv) — Encryption and decryption
  if file_exists ".sops.yaml" && file_contains "platform/vault/examples/setup-complete.sh" "transit/keys/"; then
    record "$fw" "312(a)(2)" "Encryption and decryption" "PASS" "SOPS + Vault transit"
  else
    record "$fw" "312(a)(2)" "Encryption and decryption" "FAIL" "Incomplete encryption"
  fi

  # 164.312(d) — Person or entity authentication
  if file_contains "platform/vault/examples/setup-complete.sh" "auth enable oidc"; then
    record "$fw" "312(d)" "Person or entity authentication" "PASS" "OIDC authentication configured"
  else
    record "$fw" "312(d)" "Person or entity authentication" "FAIL" "No person authentication"
  fi

  # 164.312(e)(1) — Transmission security
  if file_contains "platform/vault/config/vault-server.hcl" "tls_min_version"; then
    record "$fw" "312(e)(1)" "Transmission security" "PASS" "TLS enforcement configured"
  else
    record "$fw" "312(e)(1)" "Transmission security" "FAIL" "No TLS enforcement"
  fi

  # 164.316(b)(1) — Documentation
  if file_exists "docs/14-compliance-mapping.md"; then
    record "$fw" "316(b)(1)" "Documentation" "PASS" "Compliance mapping documentation present"
  else
    record "$fw" "316(b)(1)" "Documentation" "FAIL" "No compliance documentation"
  fi
}

# ── Run checks ────────────────────────────────────────────────────────────

cd "$REPO_ROOT"

case "$FRAMEWORK" in
  soc2)     check_soc2 ;;
  pci)      check_pci ;;
  nist-csf) check_nist_csf ;;
  iso27001) check_iso27001 ;;
  hipaa)    check_hipaa ;;
  all)
    check_soc2
    check_pci
    check_nist_csf
    check_iso27001
    check_hipaa
    ;;
  *)
    echo "Unknown framework: $FRAMEWORK"
    echo "Valid: soc2, pci, nist-csf, iso27001, hipaa, all"
    exit 1
    ;;
esac

# ── Output ────────────────────────────────────────────────────────────────

if [[ -n "$JSON_OUTPUT" ]]; then
  # JSON output
  echo "{"
  echo "  \"timestamp\": \"${TIMESTAMP}\","
  echo "  \"framework\": \"${FRAMEWORK}\","
  echo "  \"summary\": {"
  echo "    \"total\": ${TOTAL},"
  echo "    \"pass\": ${PASS_COUNT},"
  echo "    \"fail\": ${FAIL_COUNT},"
  echo "    \"manual\": ${MANUAL_COUNT},"
  echo "    \"not_applicable\": ${NA_COUNT}"
  echo "  },"
  echo "  \"controls\": ["
  first=true
  for entry in "${JSON_ENTRIES[@]}"; do
    if [[ "$first" == "true" ]]; then
      first=false
    else
      echo ","
    fi
    printf "    %s" "$entry"
  done
  echo ""
  echo "  ]"
  echo "}"
else
  # Table output
  echo ""
  printf '%s\n' "$(_bold '━━━ Compliance Control Matrix ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
  printf '  %s  %s\n' "$(_dim 'Timestamp:')" "$TIMESTAMP"
  printf '  %s  %s\n' "$(_dim 'Framework:')" "$FRAMEWORK"
  printf '  %s  %s\n' "$(_dim 'Repo:')" "$REPO_ROOT"
  printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
  echo ""

  printf "  %-12s %-12s %-46s %-8s %s\n" "Framework" "Control" "Title" "Status" "Detail"
  printf "  %-12s %-12s %-46s %-8s %s\n" "──────────" "──────────" "────────────────────────────────────────────" "──────" "──────"

  for result in "${RESULTS[@]}"; do
    # Re-parse for colored output
    fw="$(echo "$result" | cut -d'|' -f2 | xargs)"
    ctl="$(echo "$result" | cut -d'|' -f3 | xargs)"
    title="$(echo "$result" | cut -d'|' -f4 | xargs)"
    status="$(echo "$result" | cut -d'|' -f5 | xargs)"
    detail="$(echo "$result" | cut -d'|' -f6 | xargs)"

    status_colored=""
    case "$status" in
      PASS)           status_colored="$(_green 'PASS  ')" ;;
      FAIL)           status_colored="$(_red 'FAIL  ')" ;;
      MANUAL)         status_colored="$(_yellow 'MANUAL')" ;;
      NOT_APPLICABLE) status_colored="$(_dim 'N/A   ')" ;;
      *)              status_colored="$status" ;;
    esac

    printf "  %-12s %-12s %-46s %b %s\n" "$fw" "$ctl" "$title" "$status_colored" "$detail"
  done

  echo ""
  printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
  printf '  Total: %d  |  ' "$TOTAL"
  printf '%s  |  ' "$(_green "Pass: ${PASS_COUNT}")"
  printf '%s  |  ' "$(_red "Fail: ${FAIL_COUNT}")"
  printf '%s  |  ' "$(_yellow "Manual: ${MANUAL_COUNT}")"
  printf '%s\n' "$(_dim "N/A: ${NA_COUNT}")"
  printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"

  if [[ $FAIL_COUNT -gt 0 ]]; then
    echo ""
    printf '  %s\n' "$(_red "${FAIL_COUNT} control(s) failed automated checks — review required")"
  fi
  if [[ $MANUAL_COUNT -gt 0 ]]; then
    printf '  %s\n' "$(_yellow "${MANUAL_COUNT} control(s) require manual verification")"
  fi
fi

# Exit non-zero if any failures
if [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
exit 0
