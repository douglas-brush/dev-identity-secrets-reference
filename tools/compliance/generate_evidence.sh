#!/usr/bin/env bash
set -euo pipefail

# generate_evidence.sh — Automated compliance evidence collection for audit prep
# Collects secrets-doctor output, cert inventory, credential age report, scan results,
# and policy inventory. Generates timestamped evidence packages with SHA-256 manifests.
# Usage: generate_evidence.sh --framework <soc2|pci|nist-csf|iso27001|hipaa|all> [OPTIONS]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DATE_STAMP="$(date -u +%Y%m%d)"

# ── Defaults ──────────────────────────────────────────────────────────────

FRAMEWORK=""
OUTPUT_DIR=""
DRY_RUN=""
VERBOSE=""
EXIT_CODE=0

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { printf '\033[1m%s\033[0m' "$1"; }
_dim()    { printf '\033[2m%s\033[0m' "$1"; }

# ── Logging ───────────────────────────────────────────────────────────────

log_info()  { printf '  %s %s\n' "$(_blue 'INFO')" "$1"; }
log_ok()    { printf '  %s %s\n' "$(_green '  OK')" "$1"; }
log_warn()  { printf '  %s %s\n' "$(_yellow 'WARN')" "$1"; }
log_error() { printf '  %s %s\n' "$(_red 'ERROR')" "$1"; }
log_dry()   { printf '  %s %s\n' "$(_dim ' DRY')" "$1"; }
verbose()   { [[ -n "$VERBOSE" ]] && printf '  %s %s\n' "$(_dim 'VERB')" "$1" || true; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'generate_evidence.sh') — Automated compliance evidence collection

$(_bold 'USAGE')
  generate_evidence.sh --framework <framework> [OPTIONS]

$(_bold 'FRAMEWORKS')
  soc2        SOC 2 Type II Trust Service Criteria
  pci         PCI DSS 4.0 requirements
  nist-csf    NIST Cybersecurity Framework 2.0
  iso27001    ISO 27001:2022 Annex A controls
  hipaa       HIPAA Security Rule safeguards
  all         Collect evidence for all frameworks

$(_bold 'OPTIONS')
  --framework <fw>    Target framework (required)
  --output-dir <dir>  Override output directory (default: evidence/<fw>-<date>/)
  --dry-run           Show what would be collected without executing
  --verbose           Enable verbose output
  --help              Show this help message

$(_bold 'EXAMPLES')
  generate_evidence.sh --framework soc2
  generate_evidence.sh --framework all --output-dir /tmp/audit-2024
  generate_evidence.sh --framework pci --dry-run --verbose

$(_bold 'OUTPUT')
  Creates evidence/<framework>-<date>/ containing:
    index.json          Manifest with SHA-256 hashes and control mappings
    secrets-doctor.txt  Infrastructure health diagnostic
    cert-inventory.txt  Certificate inventory and expiry status
    credential-age.txt  Credential age report with policy violations
    scan-results.txt    Repository secret scan results
    policy-inventory/   Vault policies and SOPS configurations
    control-matrix.txt  Automated control check results
EOF
  exit 0
}

# ── Arg parsing ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --framework)  FRAMEWORK="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --dry-run)    DRY_RUN="true"; shift ;;
    --verbose)    VERBOSE="true"; shift ;;
    --help|-h)    usage ;;
    *) log_error "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "$FRAMEWORK" ]]; then
  log_error "Missing required --framework argument"
  echo ""
  usage
fi

VALID_FRAMEWORKS="soc2 pci nist-csf iso27001 hipaa all"
if ! echo "$VALID_FRAMEWORKS" | grep -qw "$FRAMEWORK"; then
  log_error "Invalid framework: $FRAMEWORK"
  log_info "Valid frameworks: $VALID_FRAMEWORKS"
  exit 1
fi

# ── Framework-to-control mapping ──────────────────────────────────────────

# Maps each evidence artifact to the control IDs it satisfies per framework.
# Format: artifact_name -> "CTRL-1,CTRL-2,..."

declare -A SOC2_MAP=(
  ["secrets-doctor"]="CC6.1,CC6.8,CC8.1"
  ["cert-inventory"]="CC6.1,CC6.7,CC7.1"
  ["credential-age"]="CC6.2,CC6.3,CC7.2"
  ["scan-results"]="CC6.8,CC7.1,CC8.1"
  ["policy-inventory"]="CC5.2,CC6.1,CC6.3"
  ["control-matrix"]="CC5.2,CC6.1,CC6.2,CC6.3,CC6.6,CC6.7,CC6.8,CC7.1"
)

declare -A PCI_MAP=(
  ["secrets-doctor"]="8.2,8.3,8.6"
  ["cert-inventory"]="3.6,3.7,6.2"
  ["credential-age"]="8.3.6,8.6"
  ["scan-results"]="6.2,6.3,11.3"
  ["policy-inventory"]="3.6,3.7,7.2"
  ["control-matrix"]="3.5,3.6,3.7,6.2,8.2,8.3,8.6"
)

declare -A NIST_CSF_MAP=(
  ["secrets-doctor"]="PR.AA,PR.DS,PR.PS"
  ["cert-inventory"]="ID.AM,PR.DS,DE.CM"
  ["credential-age"]="PR.AA,DE.CM"
  ["scan-results"]="PR.PS,DE.CM,DE.AE"
  ["policy-inventory"]="GV.OC,GV.RM,PR.AA"
  ["control-matrix"]="GV.OC,PR.AA,PR.DS,PR.PS,DE.CM"
)

declare -A ISO27001_MAP=(
  ["secrets-doctor"]="A.5.15,A.5.17,A.8.5"
  ["cert-inventory"]="A.5.17,A.8.24,A.8.25"
  ["credential-age"]="A.5.16,A.5.17,A.5.18"
  ["scan-results"]="A.5.10,A.8.4,A.8.25"
  ["policy-inventory"]="A.5.1,A.5.15,A.8.24"
  ["control-matrix"]="A.5.1,A.5.15,A.5.16,A.5.17,A.8.2,A.8.24"
)

declare -A HIPAA_MAP=(
  ["secrets-doctor"]="164.312(a)(1),164.312(d)"
  ["cert-inventory"]="164.312(a)(2)(iv),164.312(e)(1)"
  ["credential-age"]="164.312(d),164.308(a)(5)(ii)(D)"
  ["scan-results"]="164.308(a)(1)(ii)(D),164.312(a)(1)"
  ["policy-inventory"]="164.308(a)(1)(ii)(B),164.316(b)(1)"
  ["control-matrix"]="164.308(a)(1),164.312(a)(1),164.312(d),164.312(e)(1)"
)

# Get control mapping for a given framework and artifact
get_controls() {
  local fw="$1" artifact="$2"
  case "$fw" in
    soc2)     echo "${SOC2_MAP[$artifact]:-N/A}" ;;
    pci)      echo "${PCI_MAP[$artifact]:-N/A}" ;;
    nist-csf) echo "${NIST_CSF_MAP[$artifact]:-N/A}" ;;
    iso27001) echo "${ISO27001_MAP[$artifact]:-N/A}" ;;
    hipaa)    echo "${HIPAA_MAP[$artifact]:-N/A}" ;;
    *)        echo "N/A" ;;
  esac
}

# ── Evidence collectors ───────────────────────────────────────────────────

collect_secrets_doctor() {
  local out_file="$1"
  log_info "Collecting secrets-doctor diagnostic..."
  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would run: tools/secrets-doctor/doctor.sh all --no-color"
    return 0
  fi
  if [[ -x "${REPO_ROOT}/tools/secrets-doctor/doctor.sh" ]]; then
    (cd "$REPO_ROOT" && bash tools/secrets-doctor/doctor.sh all --no-color 2>&1) > "$out_file" || true
    log_ok "Secrets-doctor: $(wc -l < "$out_file" | tr -d ' ') lines captured"
  else
    echo "# secrets-doctor not available — tool not found at tools/secrets-doctor/doctor.sh" > "$out_file"
    log_warn "secrets-doctor not found, placeholder generated"
  fi
}

collect_cert_inventory() {
  local out_file="$1"
  log_info "Collecting certificate inventory..."
  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would enumerate Vault PKI certs, K8s TLS secrets, cert-manager certificates"
    return 0
  fi

  {
    echo "# Certificate Inventory — ${TIMESTAMP}"
    echo "# Generated by generate_evidence.sh"
    echo ""

    # Vault PKI certs (if Vault available)
    if command -v vault &>/dev/null && [[ -n "${VAULT_ADDR:-}" ]]; then
      echo "## Vault PKI Certificates"
      echo ""
      for mount in pki pki_int; do
        if vault secrets list -format=json 2>/dev/null | jq -e ".[\"${mount}/\"]" &>/dev/null; then
          echo "### Mount: ${mount}"
          vault list "${mount}/certs" 2>/dev/null || echo "  (no certs or access denied)"
          echo ""
        fi
      done
    else
      echo "## Vault PKI: Vault CLI not available or VAULT_ADDR not set"
      echo ""
    fi

    # Kubernetes TLS secrets (if kubectl available)
    if command -v kubectl &>/dev/null; then
      echo "## Kubernetes TLS Secrets"
      echo ""
      kubectl get secrets --all-namespaces --field-selector type=kubernetes.io/tls \
        -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,CREATED:.metadata.creationTimestamp' \
        2>/dev/null || echo "  (kubectl not configured or no TLS secrets found)"
      echo ""

      # cert-manager certificates
      if kubectl api-resources 2>/dev/null | grep -q certificates.cert-manager.io; then
        echo "## cert-manager Certificates"
        echo ""
        kubectl get certificates --all-namespaces \
          -o custom-columns='NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.conditions[0].status,EXPIRY:.status.notAfter' \
          2>/dev/null || echo "  (no cert-manager certificates found)"
        echo ""
      fi
    else
      echo "## Kubernetes: kubectl not available"
      echo ""
    fi

    # Local certificate files in repo
    echo "## Local Certificate Files"
    echo ""
    find "${REPO_ROOT}" -type f \( -name "*.pem" -o -name "*.crt" -o -name "*.cert" \) \
      -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null | while read -r f; do
      printf "  %s  (%s)\n" "$f" "$(stat -f '%Sm' "$f" 2>/dev/null || stat -c '%y' "$f" 2>/dev/null || echo 'unknown')"
    done
    echo ""
  } > "$out_file"

  log_ok "Cert inventory: $(wc -l < "$out_file" | tr -d ' ') lines captured"
}

collect_credential_age() {
  local out_file="$1"
  log_info "Collecting credential age report..."
  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would run: tools/audit/credential_age_report.sh --format text"
    return 0
  fi
  if [[ -x "${REPO_ROOT}/tools/audit/credential_age_report.sh" ]]; then
    (cd "$REPO_ROOT" && bash tools/audit/credential_age_report.sh --format text 2>&1) > "$out_file" || true
    log_ok "Credential age: $(wc -l < "$out_file" | tr -d ' ') lines captured"
  else
    echo "# credential_age_report.sh not available" > "$out_file"
    log_warn "credential_age_report.sh not found, placeholder generated"
  fi
}

collect_scan_results() {
  local out_file="$1"
  log_info "Collecting repository scan results..."
  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would run: tools/scanning/scan_repo.sh"
    return 0
  fi
  if [[ -x "${REPO_ROOT}/tools/scanning/scan_repo.sh" ]]; then
    (cd "$REPO_ROOT" && bash tools/scanning/scan_repo.sh 2>&1) > "$out_file" || true
    log_ok "Scan results: $(wc -l < "$out_file" | tr -d ' ') lines captured"
  else
    echo "# scan_repo.sh not available" > "$out_file"
    log_warn "scan_repo.sh not found, placeholder generated"
  fi
}

collect_policy_inventory() {
  local out_dir="$1"
  log_info "Collecting policy inventory..."
  mkdir -p "$out_dir"
  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would copy Vault policies, SOPS configs, and compliance docs"
    return 0
  fi

  local count=0

  # Vault HCL policies
  if [[ -d "${REPO_ROOT}/platform/vault/policies" ]]; then
    for f in "${REPO_ROOT}"/platform/vault/policies/*.hcl; do
      [[ -f "$f" ]] || continue
      cp "$f" "${out_dir}/$(basename "$f")"
      count=$((count + 1))
    done
    verbose "Copied $count Vault policies"
  fi

  # SOPS configuration
  if [[ -f "${REPO_ROOT}/.sops.yaml" ]]; then
    cp "${REPO_ROOT}/.sops.yaml" "${out_dir}/sops-config.yaml"
    count=$((count + 1))
  fi

  # Pre-commit config
  if [[ -f "${REPO_ROOT}/.pre-commit-config.yaml" ]]; then
    cp "${REPO_ROOT}/.pre-commit-config.yaml" "${out_dir}/pre-commit-config.yaml"
    count=$((count + 1))
  fi

  # Controls and guardrails doc
  if [[ -f "${REPO_ROOT}/docs/06-controls-and-guardrails.md" ]]; then
    cp "${REPO_ROOT}/docs/06-controls-and-guardrails.md" "${out_dir}/controls-and-guardrails.md"
    count=$((count + 1))
  fi

  # Compliance mapping
  if [[ -f "${REPO_ROOT}/docs/14-compliance-mapping.md" ]]; then
    cp "${REPO_ROOT}/docs/14-compliance-mapping.md" "${out_dir}/compliance-mapping.md"
    count=$((count + 1))
  fi

  log_ok "Policy inventory: ${count} artifacts collected"
}

collect_control_matrix() {
  local out_file="$1" fw="$2"
  log_info "Running automated control matrix check..."
  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would run: tools/compliance/control_matrix.sh --framework ${fw}"
    return 0
  fi
  if [[ -x "${SCRIPT_DIR}/control_matrix.sh" ]]; then
    (cd "$REPO_ROOT" && bash "${SCRIPT_DIR}/control_matrix.sh" --framework "$fw" 2>&1) > "$out_file" || true
    log_ok "Control matrix: $(wc -l < "$out_file" | tr -d ' ') lines captured"
  elif [[ -x "${REPO_ROOT}/tests/compliance/check_controls.sh" ]]; then
    (cd "$REPO_ROOT" && bash tests/compliance/check_controls.sh 2>&1) > "$out_file" || true
    log_ok "Control matrix (fallback): $(wc -l < "$out_file" | tr -d ' ') lines captured"
  else
    echo "# No control matrix tool available" > "$out_file"
    log_warn "No control matrix tool found"
  fi
}

# ── SHA-256 hash computation ──────────────────────────────────────────────

compute_sha256() {
  local file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  fi
}

# ── Manifest generation ──────────────────────────────────────────────────

generate_manifest() {
  local evidence_dir="$1" fw="$2" manifest_file="${1}/index.json"

  log_info "Generating evidence manifest..."

  local artifacts_json="["
  local first=true

  # Hash all files in the evidence directory (excluding index.json itself)
  while IFS= read -r -d '' file; do
    local relpath="${file#${evidence_dir}/}"
    [[ "$relpath" == "index.json" ]] && continue
    [[ -d "$file" ]] && continue

    local hash
    hash="$(compute_sha256 "$file")"
    local size
    size="$(wc -c < "$file" | tr -d ' ')"
    local controls
    # Derive artifact key from filename
    local artifact_key="${relpath%%.*}"
    artifact_key="${artifact_key%%/*}"
    artifact_key="${artifact_key//-/_}"
    # Normalize to match our mapping keys
    case "$artifact_key" in
      secrets_doctor) artifact_key="secrets-doctor" ;;
      cert_inventory) artifact_key="cert-inventory" ;;
      credential_age) artifact_key="credential-age" ;;
      scan_results)   artifact_key="scan-results" ;;
      policy_inventory) artifact_key="policy-inventory" ;;
      control_matrix) artifact_key="control-matrix" ;;
      *) artifact_key="$relpath" ;;
    esac

    if [[ "$fw" == "all" ]]; then
      controls="\"soc2\": \"$(get_controls soc2 "$artifact_key")\", \"pci\": \"$(get_controls pci "$artifact_key")\", \"nist-csf\": \"$(get_controls nist-csf "$artifact_key")\", \"iso27001\": \"$(get_controls iso27001 "$artifact_key")\", \"hipaa\": \"$(get_controls hipaa "$artifact_key")\""
    else
      controls="\"${fw}\": \"$(get_controls "$fw" "$artifact_key")\""
    fi

    [[ "$first" == "true" ]] && first=false || artifacts_json+=","
    artifacts_json+="
    {
      \"path\": \"${relpath}\",
      \"sha256\": \"${hash}\",
      \"size_bytes\": ${size},
      \"collected_at\": \"${TIMESTAMP}\",
      \"control_mappings\": { ${controls} }
    }"
  done < <(find "$evidence_dir" -type f -print0 | sort -z)

  artifacts_json+="
  ]"

  cat > "$manifest_file" <<EOF
{
  "evidence_package": {
    "framework": "${fw}",
    "generated_at": "${TIMESTAMP}",
    "generated_by": "generate_evidence.sh",
    "repo_root": "${REPO_ROOT}",
    "git_commit": "$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(cd "$REPO_ROOT" && git branch --show-current 2>/dev/null || echo 'unknown')"
  },
  "artifacts": ${artifacts_json}
}
EOF

  log_ok "Manifest written: ${manifest_file}"
}

# ── Main collection ──────────────────────────────────────────────────────

collect_for_framework() {
  local fw="$1"
  local evidence_dir

  if [[ -n "$OUTPUT_DIR" ]]; then
    evidence_dir="$OUTPUT_DIR"
  else
    evidence_dir="${REPO_ROOT}/evidence/${fw}-${DATE_STAMP}"
  fi

  echo ""
  printf '  %s\n' "$(_bold "Collecting evidence for framework: ${fw}")"
  printf '  %s\n' "$(_dim "Output: ${evidence_dir}")"
  echo ""

  if [[ -n "$DRY_RUN" ]]; then
    log_dry "Would create directory: ${evidence_dir}"
  else
    mkdir -p "${evidence_dir}/policy-inventory"
  fi

  collect_secrets_doctor "${evidence_dir}/secrets-doctor.txt"
  collect_cert_inventory "${evidence_dir}/cert-inventory.txt"
  collect_credential_age "${evidence_dir}/credential-age.txt"
  collect_scan_results   "${evidence_dir}/scan-results.txt"
  collect_policy_inventory "${evidence_dir}/policy-inventory"
  collect_control_matrix "${evidence_dir}/control-matrix.txt" "$fw"

  if [[ -z "$DRY_RUN" ]]; then
    generate_manifest "$evidence_dir" "$fw"
  else
    log_dry "Would generate index.json manifest with SHA-256 hashes"
  fi

  echo ""
  log_ok "Evidence collection complete for ${fw}"
  log_info "Package: ${evidence_dir}"
}

# ── Entry point ───────────────────────────────────────────────────────────

echo ""
printf '%s\n' "$(_bold '━━━ Compliance Evidence Collection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
printf '  %s  %s\n' "$(_dim 'Timestamp:')" "$TIMESTAMP"
printf '  %s  %s\n' "$(_dim 'Framework:')" "$FRAMEWORK"
[[ -n "$DRY_RUN" ]] && printf '  %s  %s\n' "$(_dim 'Mode:')" "$(_yellow 'DRY RUN')"
printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"

if [[ "$FRAMEWORK" == "all" ]]; then
  for fw in soc2 pci nist-csf iso27001 hipaa; do
    collect_for_framework "$fw"
  done
else
  collect_for_framework "$FRAMEWORK"
fi

echo ""
printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"
if [[ -n "$DRY_RUN" ]]; then
  log_info "Dry run complete — no files were written"
else
  log_ok "All evidence collection complete"
fi
printf '%s\n' "$(_bold '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')"

exit $EXIT_CODE
