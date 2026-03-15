#!/usr/bin/env bash
# check_sops.sh — SOPS configuration validator
# Sourced by doctor.sh — uses pass/warn/fail/skip/info functions from parent
set -euo pipefail

check_sops() {
  local sops_config="${REPO_ROOT}/.sops.yaml"

  # ── File existence ───────────────────────────────────────────────────────

  if [[ ! -f "$sops_config" ]]; then
    fail ".sops.yaml not found at repository root"
    return
  fi
  pass ".sops.yaml exists"

  # ── YAML validity ────────────────────────────────────────────────────────

  if command -v yq &>/dev/null; then
    if yq eval '.' "$sops_config" >/dev/null 2>&1; then
      pass ".sops.yaml is valid YAML"
    else
      fail ".sops.yaml contains invalid YAML"
      return
    fi
  else
    skip "yq not available — cannot validate YAML syntax"
  fi

  # ── creation_rules present ───────────────────────────────────────────────

  if command -v yq &>/dev/null; then
    local rule_count
    rule_count=$(yq eval '.creation_rules | length' "$sops_config" 2>/dev/null || echo "0")

    if [[ "$rule_count" -gt 0 ]]; then
      pass "creation_rules defined (${rule_count} rule(s))"
    else
      fail "No creation_rules defined in .sops.yaml"
      return
    fi

    # ── encrypted_regex ──────────────────────────────────────────────────

    local rules_with_regex=0
    local rules_without_regex=0
    for ((i = 0; i < rule_count; i++)); do
      local regex
      regex=$(yq eval ".creation_rules[${i}].encrypted_regex" "$sops_config" 2>/dev/null || echo "null")
      if [[ "$regex" != "null" && -n "$regex" ]]; then
        rules_with_regex=$((rules_with_regex + 1))
      else
        rules_without_regex=$((rules_without_regex + 1))
      fi
    done

    if [[ $rules_with_regex -gt 0 ]]; then
      pass "encrypted_regex set on ${rules_with_regex} rule(s)"
    fi
    if [[ $rules_without_regex -gt 0 ]]; then
      warn "${rules_without_regex} rule(s) missing encrypted_regex — entire files will be encrypted"
    fi

    # ── Environment separation ───────────────────────────────────────────

    local has_dev=false has_staging=false has_prod=false
    for ((i = 0; i < rule_count; i++)); do
      local path_regex
      path_regex=$(yq eval ".creation_rules[${i}].path_regex" "$sops_config" 2>/dev/null || echo "")
      case "$path_regex" in
        *dev*)     has_dev=true ;;
        *staging*) has_staging=true ;;
        *prod*)    has_prod=true ;;
      esac
    done

    if [[ "$has_prod" == "true" ]]; then
      pass "Production environment rule detected"
    else
      warn "No production-specific path_regex rule found"
    fi

    if [[ "$has_dev" == "true" || "$has_staging" == "true" ]]; then
      pass "Non-production environment rule(s) detected"
    else
      info "No explicit dev/staging path_regex rules (may use catch-all)"
    fi

    # Verify production and non-production use different keys
    if [[ "$has_prod" == "true" && ("$has_dev" == "true" || "$has_staging" == "true") ]]; then
      local prod_keys="" nonprod_keys=""
      for ((i = 0; i < rule_count; i++)); do
        local path_regex age_recipients
        path_regex=$(yq eval ".creation_rules[${i}].path_regex" "$sops_config" 2>/dev/null || echo "")
        age_recipients=$(yq eval ".creation_rules[${i}].age" "$sops_config" 2>/dev/null || echo "")

        if [[ "$path_regex" == *"prod"* ]]; then
          prod_keys="$age_recipients"
        elif [[ "$path_regex" == *"dev"* || "$path_regex" == *"staging"* ]]; then
          nonprod_keys="$age_recipients"
        fi
      done

      if [[ -n "$prod_keys" && -n "$nonprod_keys" && "$prod_keys" != "$nonprod_keys" ]]; then
        pass "Production and non-production use different encryption keys"
      elif [[ -n "$prod_keys" && -n "$nonprod_keys" ]]; then
        warn "Production and non-production appear to use the same encryption keys"
      fi
    fi

    # ── Placeholder detection ────────────────────────────────────────────

    local placeholders_found=false
    local placeholder_patterns=(
      "REPLACE_ME"
      "TODO"
      "CHANGEME"
      "your-key-here"
      "INSERT"
      "PLACEHOLDER"
      "xxx"
      "example"
    )

    local sops_content
    sops_content=$(cat "$sops_config")

    for pattern in "${placeholder_patterns[@]}"; do
      if echo "$sops_content" | grep -qi "$pattern"; then
        # Check if it's in a production rule
        # Simple heuristic: check lines near "prod" context
        local context_lines
        context_lines=$(grep -n -i "$pattern" "$sops_config" 2>/dev/null || true)
        if [[ -n "$context_lines" ]]; then
          fail "Placeholder '${pattern}' found in .sops.yaml — replace before use"
          placeholders_found=true
        fi
      fi
    done

    [[ "$placeholders_found" == "false" ]] && pass "No placeholder recipients detected"

    # ── age recipient validation ─────────────────────────────────────────

    local age_recipients_found=0
    while IFS= read -r line; do
      if [[ "$line" =~ age1[a-z0-9]{58} ]]; then
        age_recipients_found=$((age_recipients_found + 1))
      fi
    done < "$sops_config"

    if [[ $age_recipients_found -gt 0 ]]; then
      pass "${age_recipients_found} age recipient(s) configured"
    else
      # Check for KMS, PGP, or other backends
      if grep -qE '(kms:|pgp:|gcp_kms:|azure_kv:|hc_vault_transit:)' "$sops_config" 2>/dev/null; then
        pass "Non-age encryption backend configured (KMS/PGP/Vault)"
      else
        fail "No encryption recipients configured in .sops.yaml"
      fi
    fi

    # ── Verify .enc.yaml files are actually encrypted ────────────────────

    local enc_files
    enc_files=$(find "$REPO_ROOT" -name '*.enc.yaml' -o -name '*.enc.yml' -o -name '*.enc.json' 2>/dev/null | head -20)
    if [[ -n "$enc_files" ]]; then
      local encrypted_count=0 unencrypted_count=0
      while IFS= read -r f; do
        if grep -q 'sops:' "$f" 2>/dev/null || grep -q '"sops":' "$f" 2>/dev/null; then
          encrypted_count=$((encrypted_count + 1))
        else
          fail "File appears unencrypted despite .enc extension: ${f#"$REPO_ROOT"/}"
          unencrypted_count=$((unencrypted_count + 1))
        fi
      done <<< "$enc_files"

      [[ $encrypted_count -gt 0 ]] && pass "${encrypted_count} .enc.* file(s) verified as encrypted"
    else
      info "No .enc.yaml/.enc.yml/.enc.json files found to verify"
    fi

  else
    # Fallback without yq
    if grep -q 'creation_rules:' "$sops_config" 2>/dev/null; then
      pass "creation_rules section found (install yq for detailed validation)"
    else
      fail "creation_rules not found in .sops.yaml"
    fi

    if grep -q 'encrypted_regex:' "$sops_config" 2>/dev/null; then
      pass "encrypted_regex found in .sops.yaml"
    else
      warn "encrypted_regex not found — install yq for detailed check"
    fi
  fi
}
