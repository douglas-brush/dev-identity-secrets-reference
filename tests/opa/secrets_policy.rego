# OPA Policy — Kubernetes Secret Management Controls
# Validates Kubernetes manifests against secret management best practices.
#
# Rules:
#   1. No Kubernetes Secret resources with hardcoded data (must use ExternalSecret)
#   2. No pods with default service account
#   3. No containers with secret env vars from ConfigMaps
#   4. Certificate resources must have renewBefore set
#   5. ExternalSecret must have refreshInterval <= 1h for production namespaces

package kubernetes.secrets

import rego.v1

# --- Rule 1: Block Kubernetes Secrets with hardcoded data ---

deny_hardcoded_secret contains msg if {
	input.kind == "Secret"
	not _is_system_managed(input)
	count(object.get(input, "data", {})) > 0
	msg := sprintf(
		"DENY: Secret '%s/%s' contains hardcoded data. Use ExternalSecret or CSI driver instead.",
		[object.get(input.metadata, "namespace", "default"), input.metadata.name],
	)
}

deny_hardcoded_secret contains msg if {
	input.kind == "Secret"
	not _is_system_managed(input)
	count(object.get(input, "stringData", {})) > 0
	msg := sprintf(
		"DENY: Secret '%s/%s' contains hardcoded stringData. Use ExternalSecret or CSI driver instead.",
		[object.get(input.metadata, "namespace", "default"), input.metadata.name],
	)
}

# System-managed secrets are exempt (cert-manager, ESO, Helm, SA tokens)
_is_system_managed(resource) if {
	resource.metadata.annotations["cert-manager.io/certificate-name"]
}

_is_system_managed(resource) if {
	resource.metadata.annotations["reconcile.external-secrets.io/managed"] == "true"
}

_is_system_managed(resource) if {
	resource.metadata.labels["app.kubernetes.io/managed-by"] == "Helm"
}

_is_system_managed(resource) if {
	resource.metadata.annotations["kubernetes.io/service-account.name"]
}

# --- Rule 2: Block pods using default service account ---

deny_default_sa contains msg if {
	_is_workload(input)
	sa := object.get(input.spec.template.spec, "serviceAccountName", "default")
	sa == "default"
	msg := sprintf(
		"DENY: %s '%s/%s' uses the default service account. Assign a dedicated SA with least-privilege RBAC.",
		[input.kind, object.get(input.metadata, "namespace", "default"), input.metadata.name],
	)
}

deny_default_sa contains msg if {
	input.kind == "Pod"
	sa := object.get(input.spec, "serviceAccountName", "default")
	sa == "default"
	msg := sprintf(
		"DENY: Pod '%s/%s' uses the default service account. Assign a dedicated SA with least-privilege RBAC.",
		[object.get(input.metadata, "namespace", "default"), input.metadata.name],
	)
}

_is_workload(resource) if {
	resource.kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}
}

# --- Rule 3: Block secret values sourced from ConfigMaps ---

deny_secret_from_configmap contains msg if {
	_is_workload(input)
	container := input.spec.template.spec.containers[i]
	env := container.env[j]
	env.valueFrom.configMapKeyRef
	contains(lower(env.name), "secret")
	msg := sprintf(
		"DENY: Container '%s' in %s '%s' has env var '%s' sourcing a secret-like value from a ConfigMap. Use a Secret or ExternalSecret instead.",
		[container.name, input.kind, input.metadata.name, env.name],
	)
}

deny_secret_from_configmap contains msg if {
	_is_workload(input)
	container := input.spec.template.spec.containers[i]
	env := container.env[j]
	env.valueFrom.configMapKeyRef
	contains(lower(env.name), "password")
	msg := sprintf(
		"DENY: Container '%s' in %s '%s' has env var '%s' sourcing a password from a ConfigMap. Use a Secret or ExternalSecret instead.",
		[container.name, input.kind, input.metadata.name, env.name],
	)
}

deny_secret_from_configmap contains msg if {
	_is_workload(input)
	container := input.spec.template.spec.containers[i]
	env := container.env[j]
	env.valueFrom.configMapKeyRef
	contains(lower(env.name), "api_key")
	msg := sprintf(
		"DENY: Container '%s' in %s '%s' has env var '%s' sourcing an API key from a ConfigMap. Use a Secret or ExternalSecret instead.",
		[container.name, input.kind, input.metadata.name, env.name],
	)
}

# --- Rule 4: Certificate resources must have renewBefore ---

deny_cert_no_renewal contains msg if {
	input.kind == "Certificate"
	input.apiVersion == "cert-manager.io/v1"
	not input.spec.renewBefore
	msg := sprintf(
		"DENY: Certificate '%s/%s' does not have spec.renewBefore set. Automated renewal before expiry is required.",
		[object.get(input.metadata, "namespace", "default"), input.metadata.name],
	)
}

# --- Rule 5: ExternalSecret refreshInterval must be <= 1h for production ---

deny_slow_refresh contains msg if {
	input.kind == "ExternalSecret"
	ns := object.get(input.metadata, "namespace", "default")
	_is_production_namespace(ns)
	interval := object.get(input.spec, "refreshInterval", "1h")
	_interval_exceeds_1h(interval)
	msg := sprintf(
		"DENY: ExternalSecret '%s/%s' has refreshInterval '%s' which exceeds 1h. Production secrets must refresh within 1 hour.",
		[ns, input.metadata.name, interval],
	)
}

_is_production_namespace(ns) if {
	startswith(ns, "prod")
}

_is_production_namespace(ns) if {
	ns == "production"
}

_is_production_namespace(ns) if {
	contains(ns, "-prod")
}

# Parse common interval formats that exceed 1h
_interval_exceeds_1h(interval) if {
	endswith(interval, "h")
	hours := to_number(trim_suffix(interval, "h"))
	hours > 1
}

_interval_exceeds_1h(interval) if {
	endswith(interval, "d")
}

# --- Aggregate all violations ---

violations contains msg if {
	some msg in deny_hardcoded_secret
}

violations contains msg if {
	some msg in deny_default_sa
}

violations contains msg if {
	some msg in deny_secret_from_configmap
}

violations contains msg if {
	some msg in deny_cert_no_renewal
}

violations contains msg if {
	some msg in deny_slow_refresh
}
