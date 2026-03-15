#!/usr/bin/env bash

#!/usr/bin/env bash
# check_certs.sh — Certificate hygiene and lifecycle validator
# Sourced by doctor.sh — uses pass/warn/fail/skip/info functions from parent
set -euo pipefail

check_certs() {
  # ── Private key files in repo ──────────────────────────────────────────

  local private_key_files=()
  while IFS= read -r -d '' f; do
    private_key_files+=("$f")
  done < <(find "$REPO_ROOT" -type f \( -name '*.key' -o -name '*.p12' -o -name '*.pfx' \) \
    -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -not -path '*/.terraform/*' -print0 2>/dev/null)

  # Also scan .pem files for embedded private keys
  local pem_with_privkey=()
  while IFS= read -r -d '' f; do
    if grep -q 'PRIVATE KEY' "$f" 2>/dev/null; then
      pem_with_privkey+=("$f")
    fi
  done < <(find "$REPO_ROOT" -type f -name '*.pem' \
    -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -not -path '*/.terraform/*' -print0 2>/dev/null)

  local total_privkeys=$(( ${#private_key_files[@]} + ${#pem_with_privkey[@]} ))

  if [[ $total_privkeys -gt 0 ]]; then
    fail "${total_privkeys} private key file(s) found in repository — remove and rotate immediately"
    for f in "${private_key_files[@]}"; do
      info "Private key file: ${f#"$REPO_ROOT"/}"
    done
    for f in "${pem_with_privkey[@]}"; do
      info "PEM with private key: ${f#"$REPO_ROOT"/}"
    done
  else
    pass "No private key files found in repository"
  fi

  # ── Certificate files in repo ──────────────────────────────────────────

  local cert_files=()
  while IFS= read -r -d '' f; do
    cert_files+=("$f")
  done < <(find "$REPO_ROOT" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cert' \) \
    -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -not -path '*/.terraform/*' -print0 2>/dev/null)

  # Filter out files that are actually private keys (already reported above)
  local public_cert_files=()
  for f in "${cert_files[@]}"; do
    if ! grep -q 'PRIVATE KEY' "$f" 2>/dev/null; then
      public_cert_files+=("$f")
    fi
  done

  if [[ ${#public_cert_files[@]} -eq 0 ]]; then
    info "No certificate files (.pem/.crt/.cert) found in repository"
  else
    info "${#public_cert_files[@]} certificate file(s) found — checking expiration"

    if ! command -v openssl &>/dev/null; then
      skip "openssl not installed — cannot check certificate expiration"
    else
      local expired=0
      local expiring_soon=0
      local valid=0

      for f in "${public_cert_files[@]}"; do
        local rel_path="${f#"$REPO_ROOT"/}"

        # Attempt to parse as x509 certificate
        local end_date
        end_date=$(openssl x509 -enddate -noout -in "$f" 2>/dev/null || echo "")
        if [[ -z "$end_date" ]]; then
          info "Cannot parse as x509: ${rel_path}"
          continue
        fi

        # Extract the date portion: notAfter=Mon DD HH:MM:SS YYYY GMT
        local date_str="${end_date#notAfter=}"

        # Check if already expired
        if ! openssl x509 -checkend 0 -noout -in "$f" &>/dev/null; then
          fail "EXPIRED certificate: ${rel_path} (expired: ${date_str})"
          expired=$((expired + 1))
        elif ! openssl x509 -checkend 2592000 -noout -in "$f" &>/dev/null; then
          # 2592000 = 30 days in seconds
          warn "Certificate expiring within 30 days: ${rel_path} (expires: ${date_str})"
          expiring_soon=$((expiring_soon + 1))
        else
          pass "Certificate valid: ${rel_path} (expires: ${date_str})"
          valid=$((valid + 1))
        fi
      done

      if [[ $expired -eq 0 && $expiring_soon -eq 0 && $valid -gt 0 ]]; then
        info "All ${valid} parseable certificate(s) are valid and not expiring soon"
      fi
    fi
  fi

  # ── Kubernetes cert-manager checks ─────────────────────────────────────

  if ! command -v kubectl &>/dev/null; then
    skip "kubectl not installed — skipping cert-manager checks"
    return
  fi

  if ! kubectl cluster-info &>/dev/null 2>&1; then
    skip "Cannot connect to Kubernetes cluster — skipping cert-manager checks"
    return
  fi

  if ! kubectl get crd certificates.cert-manager.io &>/dev/null 2>&1; then
    info "cert-manager CRDs not installed — skipping cert-manager checks"
    return
  fi

  pass "cert-manager CRDs installed"

  # ── cert-manager pod health ──────────────────────────────────────────

  local cm_pods
  cm_pods=$(kubectl get pods -A -l app.kubernetes.io/instance=cert-manager -o json 2>/dev/null || echo '{"items":[]}')
  local cm_pod_count
  cm_pod_count=$(echo "$cm_pods" | jq '.items | length' 2>/dev/null || echo "0")

  if [[ "$cm_pod_count" -gt 0 ]]; then
    local cm_ready=0
    for ((i = 0; i < cm_pod_count; i++)); do
      local phase
      phase=$(echo "$cm_pods" | jq -r ".items[${i}].status.phase" 2>/dev/null)
      [[ "$phase" == "Running" ]] && cm_ready=$((cm_ready + 1))
    done

    if [[ $cm_ready -eq $cm_pod_count ]]; then
      pass "cert-manager: ${cm_ready}/${cm_pod_count} pod(s) running"
    else
      fail "cert-manager: only ${cm_ready}/${cm_pod_count} pod(s) running"
    fi
  else
    warn "cert-manager CRDs installed but no cert-manager pods found"
  fi

  # ── Certificate resources ──────────────────────────────────────────────

  local certs_json
  certs_json=$(kubectl get certificates -A -o json 2>/dev/null || echo '{"items":[]}')
  local cert_count
  cert_count=$(echo "$certs_json" | jq '.items | length' 2>/dev/null || echo "0")

  if [[ "$cert_count" -eq 0 ]]; then
    info "No cert-manager Certificate resources found"
    return
  fi

  local failed_certs=0
  local missing_renew_before=0
  local expiring_7d=0
  local now_epoch
  now_epoch=$(date +%s)
  local seven_days=604800

  for ((i = 0; i < cert_count; i++)); do
    local cert_name cert_ns
    cert_name=$(echo "$certs_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
    cert_ns=$(echo "$certs_json" | jq -r ".items[${i}].metadata.namespace" 2>/dev/null)

    # Check Ready condition
    local ready_status
    ready_status=$(echo "$certs_json" | jq -r ".items[${i}].status.conditions[]? | select(.type==\"Ready\") | .status" 2>/dev/null)
    if [[ "$ready_status" != "True" ]]; then
      local ready_msg
      ready_msg=$(echo "$certs_json" | jq -r ".items[${i}].status.conditions[]? | select(.type==\"Ready\") | .message // \"unknown\"" 2>/dev/null)
      fail "Certificate not ready: ${cert_ns}/${cert_name} — ${ready_msg}"
      failed_certs=$((failed_certs + 1))
    fi

    # Check renewBefore specification
    local renew_before
    renew_before=$(echo "$certs_json" | jq -r ".items[${i}].spec.renewBefore // empty" 2>/dev/null)
    if [[ -z "$renew_before" ]]; then
      missing_renew_before=$((missing_renew_before + 1))
      info "No renewBefore set: ${cert_ns}/${cert_name}"
    fi

    # Check expiration (notAfter from status)
    local not_after
    not_after=$(echo "$certs_json" | jq -r ".items[${i}].status.notAfter // empty" 2>/dev/null)
    if [[ -n "$not_after" ]]; then
      local expire_epoch
      # notAfter is RFC3339 format
      expire_epoch=$(date -jf "%Y-%m-%dT%H:%M:%SZ" "$not_after" +%s 2>/dev/null || \
                     date -d "$not_after" +%s 2>/dev/null || echo "")
      if [[ -n "$expire_epoch" ]]; then
        local remaining=$(( expire_epoch - now_epoch ))
        if [[ $remaining -le 0 ]]; then
          fail "Certificate EXPIRED: ${cert_ns}/${cert_name} (expired: ${not_after})"
          expiring_7d=$((expiring_7d + 1))
        elif [[ $remaining -le $seven_days ]]; then
          warn "Certificate expiring within 7 days: ${cert_ns}/${cert_name} (expires: ${not_after})"
          expiring_7d=$((expiring_7d + 1))
        fi
      fi
    fi
  done

  if [[ $failed_certs -eq 0 ]]; then
    pass "All ${cert_count} cert-manager Certificate(s) are Ready"
  fi

  if [[ $missing_renew_before -gt 0 ]]; then
    warn "${missing_renew_before}/${cert_count} Certificate(s) missing renewBefore specification"
  else
    pass "All ${cert_count} Certificate(s) have renewBefore configured"
  fi

  if [[ $expiring_7d -eq 0 ]]; then
    pass "No cert-manager Certificates expiring within 7 days"
  fi
}
