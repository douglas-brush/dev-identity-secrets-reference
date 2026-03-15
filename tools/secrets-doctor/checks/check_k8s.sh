#!/usr/bin/env bash
# check_k8s.sh — Kubernetes secrets configuration validator
# Sourced by doctor.sh — uses pass/warn/fail/skip/info functions from parent
set -euo pipefail

check_k8s() {
  # ── kubectl availability ───────────────────────────────────────────────

  if ! command -v kubectl &>/dev/null; then
    skip "kubectl not installed — skipping Kubernetes checks"
    return
  fi

  # ── Cluster connectivity ───────────────────────────────────────────────

  local cluster_info
  if ! cluster_info=$(kubectl cluster-info 2>/dev/null | head -1); then
    skip "Cannot connect to Kubernetes cluster — skipping K8s checks"
    return
  fi

  pass "Kubernetes cluster reachable"
  info "${cluster_info}"

  local current_context
  current_context=$(kubectl config current-context 2>/dev/null || echo "unknown")
  info "Context: ${current_context}"

  # ── Get target namespaces ─────────────────────────────────────────────

  local namespaces
  namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "default")
  local ns_count
  ns_count=$(echo "$namespaces" | wc -w | tr -d ' ')
  info "Checking ${ns_count} namespace(s)"

  # ── Secrets not managed by ESO or CSI ─────────────────────────────────

  local unmanaged_secrets=0
  local total_secrets=0

  for ns in $namespaces; do
    # Skip system namespaces
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    local secrets_json
    secrets_json=$(kubectl get secrets -n "$ns" -o json 2>/dev/null || echo '{"items":[]}')
    local ns_secret_count
    ns_secret_count=$(echo "$secrets_json" | jq '.items | length' 2>/dev/null || echo "0")
    total_secrets=$((total_secrets + ns_secret_count))

    if [[ "$ns_secret_count" -eq 0 ]]; then
      continue
    fi

    # Check each secret for management labels/annotations
    local unmanaged_in_ns=0
    for ((i = 0; i < ns_secret_count; i++)); do
      local secret_name secret_type
      secret_name=$(echo "$secrets_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
      secret_type=$(echo "$secrets_json" | jq -r ".items[${i}].type" 2>/dev/null)

      # Skip service account tokens and TLS secrets managed by cert-manager
      case "$secret_type" in
        kubernetes.io/service-account-token) continue ;;
        kubernetes.io/dockerconfigjson) continue ;;
      esac

      # Skip helm release secrets
      [[ "$secret_name" == sh.helm.release.* ]] && continue

      # Check for ESO ownership
      local eso_managed=false
      local owner_kind
      owner_kind=$(echo "$secrets_json" | jq -r ".items[${i}].metadata.ownerReferences[0].kind // empty" 2>/dev/null)
      [[ "$owner_kind" == "ExternalSecret" ]] && eso_managed=true

      # Check for ESO annotations
      local reconcile_annotation
      reconcile_annotation=$(echo "$secrets_json" | jq -r '.items['"${i}"'].metadata.annotations["reconcile.external-secrets.io/data-hash"] // empty' 2>/dev/null)
      [[ -n "$reconcile_annotation" ]] && eso_managed=true

      # Check for CSI driver annotations
      local csi_managed=false
      local csi_annotation
      csi_annotation=$(echo "$secrets_json" | jq -r '.items['"${i}"'].metadata.annotations["secrets-store.csi.k8s.io/managed"] // empty' 2>/dev/null)
      [[ "$csi_annotation" == "true" ]] && csi_managed=true

      # Check for sealed-secrets
      local sealed_managed=false
      local sealed_annotation
      sealed_annotation=$(echo "$secrets_json" | jq -r '.items['"${i}"'].metadata.annotations["sealedsecrets.bitnami.com/managed"] // empty' 2>/dev/null)
      [[ -n "$sealed_annotation" ]] && sealed_managed=true

      if [[ "$eso_managed" == "false" && "$csi_managed" == "false" && "$sealed_managed" == "false" ]]; then
        unmanaged_in_ns=$((unmanaged_in_ns + 1))
        info "Unmanaged secret: ${ns}/${secret_name} (type: ${secret_type})"
      fi
    done

    unmanaged_secrets=$((unmanaged_secrets + unmanaged_in_ns))
  done

  if [[ $total_secrets -eq 0 ]]; then
    info "No secrets found in non-system namespaces"
  elif [[ $unmanaged_secrets -eq 0 ]]; then
    pass "All ${total_secrets} secrets are managed by ESO, CSI, or SealedSecrets"
  elif [[ $unmanaged_secrets -le 3 ]]; then
    warn "${unmanaged_secrets}/${total_secrets} secret(s) not managed by an external secrets operator"
  else
    fail "${unmanaged_secrets}/${total_secrets} secret(s) not managed by an external secrets operator"
  fi

  # ── Default service account usage ─────────────────────────────────────

  local default_sa_pods=0
  for ns in $namespaces; do
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    local pods_json
    pods_json=$(kubectl get pods -n "$ns" -o json 2>/dev/null || echo '{"items":[]}')
    local pod_count
    pod_count=$(echo "$pods_json" | jq '.items | length' 2>/dev/null || echo "0")

    for ((i = 0; i < pod_count; i++)); do
      local sa_name
      sa_name=$(echo "$pods_json" | jq -r ".items[${i}].spec.serviceAccountName // \"default\"" 2>/dev/null)
      if [[ "$sa_name" == "default" ]]; then
        local pod_name
        pod_name=$(echo "$pods_json" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
        default_sa_pods=$((default_sa_pods + 1))
        info "Pod using default SA: ${ns}/${pod_name}"
      fi
    done
  done

  if [[ $default_sa_pods -eq 0 ]]; then
    pass "No pods using the default service account"
  elif [[ $default_sa_pods -le 2 ]]; then
    warn "${default_sa_pods} pod(s) using the default service account — consider dedicated SAs"
  else
    fail "${default_sa_pods} pod(s) using the default service account — create dedicated SAs"
  fi

  # ── automountServiceAccountToken ──────────────────────────────────────

  local automount_issues=0
  for ns in $namespaces; do
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    # Check default SA in each namespace
    local default_sa_json
    default_sa_json=$(kubectl get sa default -n "$ns" -o json 2>/dev/null || echo '{}')
    local automount
    automount=$(echo "$default_sa_json" | jq -r '.automountServiceAccountToken // true' 2>/dev/null)
    if [[ "$automount" == "true" ]]; then
      automount_issues=$((automount_issues + 1))
      info "Default SA in ${ns} has automountServiceAccountToken enabled"
    fi
  done

  if [[ $automount_issues -eq 0 ]]; then
    pass "Default service accounts have automountServiceAccountToken disabled"
  else
    warn "${automount_issues} namespace(s) have default SA with automountServiceAccountToken enabled"
  fi

  # ── Namespace network policies ────────────────────────────────────────

  local ns_without_netpol=0
  for ns in $namespaces; do
    case "$ns" in
      kube-system|kube-public|kube-node-lease) continue ;;
    esac

    local netpol_count
    netpol_count=$(kubectl get networkpolicies -n "$ns" -o json 2>/dev/null | jq '.items | length' 2>/dev/null || echo "0")
    if [[ "$netpol_count" -eq 0 ]]; then
      ns_without_netpol=$((ns_without_netpol + 1))
      info "No NetworkPolicies in namespace: ${ns}"
    fi
  done

  if [[ $ns_without_netpol -eq 0 ]]; then
    pass "All non-system namespaces have NetworkPolicies"
  else
    warn "${ns_without_netpol} namespace(s) without NetworkPolicies — secrets traffic is unrestricted"
  fi

  # ── RBAC: check for broad secret access ──────────────────────────────

  local risky_bindings=0
  local cluster_roles
  cluster_roles=$(kubectl get clusterroles -o json 2>/dev/null || echo '{"items":[]}')
  local cr_count
  cr_count=$(echo "$cluster_roles" | jq '.items | length' 2>/dev/null || echo "0")

  for ((i = 0; i < cr_count; i++)); do
    local role_name
    role_name=$(echo "$cluster_roles" | jq -r ".items[${i}].metadata.name" 2>/dev/null)

    # Skip system roles
    [[ "$role_name" == system:* ]] && continue

    local rules
    rules=$(echo "$cluster_roles" | jq -c ".items[${i}].rules[]?" 2>/dev/null || echo "")

    while IFS= read -r rule; do
      [[ -z "$rule" ]] && continue
      local resources verbs
      resources=$(echo "$rule" | jq -r '.resources[]? // empty' 2>/dev/null)
      verbs=$(echo "$rule" | jq -r '.verbs[]? // empty' 2>/dev/null)

      if echo "$resources" | grep -qE '(secrets|\*)' && echo "$verbs" | grep -qE '(\*|list|get)'; then
        if [[ "$role_name" != "admin" && "$role_name" != "cluster-admin" && "$role_name" != "edit" ]]; then
          risky_bindings=$((risky_bindings + 1))
          info "ClusterRole '${role_name}' has broad secret access"
        fi
      fi
    done <<< "$rules"
  done

  if [[ $risky_bindings -eq 0 ]]; then
    pass "No custom ClusterRoles with broad secret access"
  else
    warn "${risky_bindings} custom ClusterRole(s) with broad secret access — review for least-privilege"
  fi

  # ── External Secrets Operator health ──────────────────────────────────

  if kubectl get crd externalsecrets.external-secrets.io &>/dev/null 2>&1; then
    pass "External Secrets Operator CRDs installed"

    # Check ESO pod health
    local eso_pods
    eso_pods=$(kubectl get pods -A -l app.kubernetes.io/name=external-secrets -o json 2>/dev/null || echo '{"items":[]}')
    local eso_pod_count
    eso_pod_count=$(echo "$eso_pods" | jq '.items | length' 2>/dev/null || echo "0")

    if [[ "$eso_pod_count" -gt 0 ]]; then
      local eso_ready=0
      for ((i = 0; i < eso_pod_count; i++)); do
        local phase
        phase=$(echo "$eso_pods" | jq -r ".items[${i}].status.phase" 2>/dev/null)
        [[ "$phase" == "Running" ]] && eso_ready=$((eso_ready + 1))
      done

      if [[ $eso_ready -eq $eso_pod_count ]]; then
        pass "ESO: ${eso_ready}/${eso_pod_count} pod(s) running"
      else
        fail "ESO: only ${eso_ready}/${eso_pod_count} pod(s) running"
      fi
    else
      warn "ESO CRDs installed but no ESO pods found"
    fi

    # Check for failed ExternalSecrets
    local failed_es=0
    local es_list
    es_list=$(kubectl get externalsecrets -A -o json 2>/dev/null || echo '{"items":[]}')
    local es_count
    es_count=$(echo "$es_list" | jq '.items | length' 2>/dev/null || echo "0")

    for ((i = 0; i < es_count; i++)); do
      local status
      status=$(echo "$es_list" | jq -r ".items[${i}].status.conditions[]? | select(.type==\"Ready\") | .status" 2>/dev/null)
      if [[ "$status" != "True" ]]; then
        local es_name es_ns
        es_name=$(echo "$es_list" | jq -r ".items[${i}].metadata.name" 2>/dev/null)
        es_ns=$(echo "$es_list" | jq -r ".items[${i}].metadata.namespace" 2>/dev/null)
        failed_es=$((failed_es + 1))
        info "ExternalSecret not ready: ${es_ns}/${es_name}"
      fi
    done

    if [[ $failed_es -eq 0 && $es_count -gt 0 ]]; then
      pass "All ${es_count} ExternalSecret(s) are ready"
    elif [[ $failed_es -gt 0 ]]; then
      fail "${failed_es}/${es_count} ExternalSecret(s) are not ready"
    fi
  else
    info "External Secrets Operator not installed"
  fi
}
