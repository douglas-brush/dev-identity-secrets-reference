#!/usr/bin/env bash
# check_vault.sh — Vault connectivity and configuration validator
# Sourced by doctor.sh — uses pass/warn/fail/skip/info functions from parent
set -euo pipefail

check_vault() {
  # ── Vault CLI availability ─────────────────────────────────────────────

  if ! command -v vault &>/dev/null; then
    skip "vault CLI not installed — skipping Vault checks"
    return
  fi

  # ── VAULT_ADDR ─────────────────────────────────────────────────────────

  if [[ -z "${VAULT_ADDR:-}" ]]; then
    skip "VAULT_ADDR not set — skipping Vault connectivity checks"
    return
  fi

  info "Vault address: ${VAULT_ADDR}"

  # ── Connectivity ───────────────────────────────────────────────────────

  local health_response
  if health_response=$(vault status -format=json 2>/dev/null); then
    pass "Vault server reachable at ${VAULT_ADDR}"
  else
    # vault status returns non-zero when sealed, but still reachable
    if health_response=$(curl -sk "${VAULT_ADDR}/v1/sys/health" 2>/dev/null); then
      pass "Vault server reachable at ${VAULT_ADDR}"
    else
      fail "Cannot reach Vault server at ${VAULT_ADDR}"
      return
    fi
  fi

  # ── Seal status ────────────────────────────────────────────────────────

  local sealed initialized
  if [[ -n "$health_response" ]]; then
    sealed=$(echo "$health_response" | jq -r '.sealed // empty' 2>/dev/null || echo "unknown")
    initialized=$(echo "$health_response" | jq -r '.initialized // empty' 2>/dev/null || echo "unknown")

    if [[ "$initialized" == "true" ]]; then
      pass "Vault is initialized"
    elif [[ "$initialized" == "false" ]]; then
      fail "Vault is NOT initialized"
      return
    fi

    if [[ "$sealed" == "false" ]]; then
      pass "Vault is unsealed"
    elif [[ "$sealed" == "true" ]]; then
      fail "Vault is SEALED — cannot perform operations"
      return
    fi

    # Cluster info
    local cluster_name
    cluster_name=$(echo "$health_response" | jq -r '.cluster_name // empty' 2>/dev/null || echo "")
    [[ -n "$cluster_name" ]] && info "Cluster: ${cluster_name}"

    local version
    version=$(echo "$health_response" | jq -r '.version // empty' 2>/dev/null || echo "")
    [[ -n "$version" ]] && info "Vault version: ${version}"
  fi

  # ── Token validity ────────────────────────────────────────────────────

  if [[ -z "${VAULT_TOKEN:-}" ]]; then
    # Check for token helper
    if [[ -f "${HOME}/.vault-token" ]]; then
      info "Using token from ~/.vault-token"
    else
      warn "No VAULT_TOKEN set and no ~/.vault-token found"
      skip "Cannot validate token — no credentials available"
      return
    fi
  fi

  local token_info
  if token_info=$(vault token lookup -format=json 2>/dev/null); then
    pass "Vault token is valid"

    # Check token TTL
    local ttl
    ttl=$(echo "$token_info" | jq -r '.data.ttl // 0' 2>/dev/null || echo "0")
    if [[ "$ttl" -eq 0 ]]; then
      info "Token has no TTL (root or infinite)"
    elif [[ "$ttl" -lt 3600 ]]; then
      warn "Token TTL is less than 1 hour (${ttl}s) — consider renewing"
    else
      local hours=$((ttl / 3600))
      pass "Token TTL: ${hours}h remaining"
    fi

    # Check if root token
    local policies
    policies=$(echo "$token_info" | jq -r '.data.policies[]? // empty' 2>/dev/null || echo "")
    if echo "$policies" | grep -q "root"; then
      warn "Using root token — not recommended for production"
    else
      info "Token policies: ${policies//$'\n'/, }"
    fi

    # Token type
    local token_type
    token_type=$(echo "$token_info" | jq -r '.data.type // empty' 2>/dev/null || echo "")
    [[ -n "$token_type" ]] && info "Token type: ${token_type}"

    # Orphan check
    local orphan
    orphan=$(echo "$token_info" | jq -r '.data.orphan // empty' 2>/dev/null || echo "")
    [[ "$orphan" == "true" ]] && info "Token is orphan (no parent)"
  else
    fail "Vault token is invalid or expired"
    return
  fi

  # ── Auth methods ──────────────────────────────────────────────────────

  local auth_methods
  if auth_methods=$(vault auth list -format=json 2>/dev/null); then
    local method_count
    method_count=$(echo "$auth_methods" | jq 'length' 2>/dev/null || echo "0")
    pass "${method_count} auth method(s) enabled"

    # Check for recommended auth methods
    if echo "$auth_methods" | jq -r 'keys[]' 2>/dev/null | grep -q "kubernetes/"; then
      pass "Kubernetes auth method enabled"
    else
      info "Kubernetes auth method not enabled"
    fi

    if echo "$auth_methods" | jq -r 'keys[]' 2>/dev/null | grep -q "oidc/"; then
      pass "OIDC auth method enabled"
    else
      info "OIDC auth method not enabled"
    fi

    if echo "$auth_methods" | jq -r 'keys[]' 2>/dev/null | grep -q "approle/"; then
      pass "AppRole auth method enabled"
    fi

    # List all methods for verbose output
    if [[ -n "$VERBOSE" ]]; then
      echo "$auth_methods" | jq -r 'keys[]' 2>/dev/null | while read -r method; do
        local type
        type=$(echo "$auth_methods" | jq -r ".[\"${method}\"].type // empty" 2>/dev/null || echo "unknown")
        info "  Auth: ${method} (type: ${type})"
      done
    fi
  else
    warn "Cannot list auth methods — insufficient permissions"
  fi

  # ── Secrets engines ───────────────────────────────────────────────────

  local secrets_engines
  if secrets_engines=$(vault secrets list -format=json 2>/dev/null); then
    local engine_count
    engine_count=$(echo "$secrets_engines" | jq 'length' 2>/dev/null || echo "0")
    pass "${engine_count} secrets engine(s) mounted"

    # Check for KV v2
    if echo "$secrets_engines" | jq -r '.[] | select(.type == "kv") | .options.version // empty' 2>/dev/null | grep -q "2"; then
      pass "KV v2 secrets engine detected (versioning enabled)"
    fi

    # Check for transit engine
    if echo "$secrets_engines" | jq -r 'keys[]' 2>/dev/null | grep -q "transit/"; then
      pass "Transit secrets engine enabled (encryption-as-a-service)"
    fi
  else
    warn "Cannot list secrets engines — insufficient permissions"
  fi

  # ── Audit devices ─────────────────────────────────────────────────────

  local audit_devices
  if audit_devices=$(vault audit list -format=json 2>/dev/null); then
    local audit_count
    audit_count=$(echo "$audit_devices" | jq 'length' 2>/dev/null || echo "0")
    if [[ "$audit_count" -gt 0 ]]; then
      pass "${audit_count} audit device(s) enabled"
    else
      warn "No audit devices enabled — all Vault operations are unaudited"
    fi
  else
    info "Cannot check audit devices — may require sudo capability"
  fi

  # ── Policy check ──────────────────────────────────────────────────────

  local policies_list
  if policies_list=$(vault policy list -format=json 2>/dev/null); then
    local policy_count
    policy_count=$(echo "$policies_list" | jq 'length' 2>/dev/null || echo "0")
    pass "${policy_count} policies defined"

    # Check for overly permissive policies
    if echo "$policies_list" | jq -r '.[]' 2>/dev/null | grep -qE '^(admin|root|superuser)$'; then
      warn "Broad admin/root/superuser policy exists — review for least-privilege"
    fi
  else
    info "Cannot list policies — insufficient permissions"
  fi
}
