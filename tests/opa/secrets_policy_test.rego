# OPA Tests — Kubernetes Secret Management Policies
# Tests all rules in secrets_policy.rego with both allow and deny scenarios.

package kubernetes.secrets_test

import rego.v1

import data.kubernetes.secrets

# =============================================================================
# Rule 1: deny_hardcoded_secret
# =============================================================================

# DENY: Secret with hardcoded data
test_deny_secret_with_data if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "my-secret",
			"namespace": "default",
		},
		"data": {"password": "cGFzc3dvcmQ="},
	}
	count(result) > 0
}

# DENY: Secret with hardcoded stringData
test_deny_secret_with_string_data if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "my-secret",
			"namespace": "default",
		},
		"stringData": {"password": "plaintext-password"},
	}
	count(result) > 0
}

# ALLOW: cert-manager managed secret
test_allow_cert_manager_secret if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "my-tls",
			"namespace": "default",
			"annotations": {"cert-manager.io/certificate-name": "my-cert"},
		},
		"data": {"tls.crt": "Y2VydA=="},
	}
	count(result) == 0
}

# ALLOW: ESO managed secret
test_allow_eso_managed_secret if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "app-secrets",
			"namespace": "default",
			"annotations": {"reconcile.external-secrets.io/managed": "true"},
		},
		"data": {"key": "dmFsdWU="},
	}
	count(result) == 0
}

# ALLOW: Helm managed secret
test_allow_helm_secret if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "helm-release",
			"namespace": "default",
			"labels": {"app.kubernetes.io/managed-by": "Helm"},
			"annotations": {},
		},
		"data": {"release": "dmFsdWU="},
	}
	count(result) == 0
}

# ALLOW: SA token secret
test_allow_sa_token_secret if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "my-sa-token",
			"namespace": "default",
			"annotations": {"kubernetes.io/service-account.name": "my-sa"},
		},
		"data": {"token": "dG9rZW4="},
	}
	count(result) == 0
}

# ALLOW: Secret with no data
test_allow_empty_secret if {
	result := secrets.deny_hardcoded_secret with input as {
		"kind": "Secret",
		"apiVersion": "v1",
		"metadata": {
			"name": "empty-secret",
			"namespace": "default",
		},
	}
	count(result) == 0
}

# =============================================================================
# Rule 2: deny_default_sa
# =============================================================================

# DENY: Deployment with default SA
test_deny_deployment_default_sa if {
	result := secrets.deny_default_sa with input as {
		"kind": "Deployment",
		"metadata": {
			"name": "my-app",
			"namespace": "default",
		},
		"spec": {"template": {"spec": {"serviceAccountName": "default"}}},
	}
	count(result) > 0
}

# DENY: Deployment with no SA specified (defaults to "default")
test_deny_deployment_no_sa if {
	result := secrets.deny_default_sa with input as {
		"kind": "Deployment",
		"metadata": {
			"name": "my-app",
			"namespace": "default",
		},
		"spec": {"template": {"spec": {}}},
	}
	count(result) > 0
}

# DENY: Pod with default SA
test_deny_pod_default_sa if {
	result := secrets.deny_default_sa with input as {
		"kind": "Pod",
		"metadata": {
			"name": "my-pod",
			"namespace": "default",
		},
		"spec": {"serviceAccountName": "default"},
	}
	count(result) > 0
}

# ALLOW: Deployment with dedicated SA
test_allow_deployment_dedicated_sa if {
	result := secrets.deny_default_sa with input as {
		"kind": "Deployment",
		"metadata": {
			"name": "my-app",
			"namespace": "default",
		},
		"spec": {"template": {"spec": {"serviceAccountName": "my-app"}}},
	}
	count(result) == 0
}

# ALLOW: StatefulSet with dedicated SA
test_allow_statefulset_dedicated_sa if {
	result := secrets.deny_default_sa with input as {
		"kind": "StatefulSet",
		"metadata": {
			"name": "my-db",
			"namespace": "default",
		},
		"spec": {"template": {"spec": {"serviceAccountName": "my-db"}}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 3: deny_secret_from_configmap
# =============================================================================

# DENY: Env var named SECRET sourced from ConfigMap
test_deny_secret_env_from_configmap if {
	result := secrets.deny_secret_from_configmap with input as {
		"kind": "Deployment",
		"metadata": {"name": "my-app"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{
				"name": "DB_SECRET",
				"valueFrom": {"configMapKeyRef": {
					"name": "my-config",
					"key": "secret",
				}},
			}],
		}]}}},
	}
	count(result) > 0
}

# DENY: Env var named PASSWORD sourced from ConfigMap
test_deny_password_env_from_configmap if {
	result := secrets.deny_secret_from_configmap with input as {
		"kind": "Deployment",
		"metadata": {"name": "my-app"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{
				"name": "DATABASE_PASSWORD",
				"valueFrom": {"configMapKeyRef": {
					"name": "my-config",
					"key": "db-pass",
				}},
			}],
		}]}}},
	}
	count(result) > 0
}

# DENY: Env var named API_KEY sourced from ConfigMap
test_deny_api_key_env_from_configmap if {
	result := secrets.deny_secret_from_configmap with input as {
		"kind": "Deployment",
		"metadata": {"name": "my-app"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{
				"name": "MY_API_KEY",
				"valueFrom": {"configMapKeyRef": {
					"name": "my-config",
					"key": "api-key",
				}},
			}],
		}]}}},
	}
	count(result) > 0
}

# ALLOW: Non-secret env var from ConfigMap
test_allow_non_secret_env_from_configmap if {
	result := secrets.deny_secret_from_configmap with input as {
		"kind": "Deployment",
		"metadata": {"name": "my-app"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{
				"name": "LOG_LEVEL",
				"valueFrom": {"configMapKeyRef": {
					"name": "my-config",
					"key": "log-level",
				}},
			}],
		}]}}},
	}
	count(result) == 0
}

# ALLOW: Secret env var from a Secret (not ConfigMap)
test_allow_secret_env_from_secret if {
	result := secrets.deny_secret_from_configmap with input as {
		"kind": "Deployment",
		"metadata": {"name": "my-app"},
		"spec": {"template": {"spec": {"containers": [{
			"name": "app",
			"env": [{
				"name": "DB_SECRET",
				"valueFrom": {"secretKeyRef": {
					"name": "my-secret",
					"key": "secret",
				}},
			}],
		}]}}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 4: deny_cert_no_renewal
# =============================================================================

# DENY: Certificate without renewBefore
test_deny_cert_without_renew_before if {
	result := secrets.deny_cert_no_renewal with input as {
		"kind": "Certificate",
		"apiVersion": "cert-manager.io/v1",
		"metadata": {
			"name": "my-cert",
			"namespace": "default",
		},
		"spec": {
			"duration": "2160h",
			"secretName": "my-cert-tls",
			"issuerRef": {"name": "vault-pki"},
		},
	}
	count(result) > 0
}

# ALLOW: Certificate with renewBefore
test_allow_cert_with_renew_before if {
	result := secrets.deny_cert_no_renewal with input as {
		"kind": "Certificate",
		"apiVersion": "cert-manager.io/v1",
		"metadata": {
			"name": "my-cert",
			"namespace": "default",
		},
		"spec": {
			"duration": "2160h",
			"renewBefore": "360h",
			"secretName": "my-cert-tls",
			"issuerRef": {"name": "vault-pki"},
		},
	}
	count(result) == 0
}

# ALLOW: Non-Certificate resource (should not trigger)
test_allow_non_certificate if {
	result := secrets.deny_cert_no_renewal with input as {
		"kind": "Deployment",
		"apiVersion": "apps/v1",
		"metadata": {"name": "my-app"},
	}
	count(result) == 0
}

# =============================================================================
# Rule 5: deny_slow_refresh
# =============================================================================

# DENY: ExternalSecret in prod namespace with 24h refresh
test_deny_slow_refresh_prod if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "production",
		},
		"spec": {
			"refreshInterval": "24h",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) > 0
}

# DENY: ExternalSecret in prod-* namespace with 2h refresh
test_deny_slow_refresh_prod_prefixed if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "prod-us-east",
		},
		"spec": {
			"refreshInterval": "2h",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) > 0
}

# DENY: ExternalSecret in *-prod namespace with 4h refresh
test_deny_slow_refresh_suffix_prod if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "my-app-prod",
		},
		"spec": {
			"refreshInterval": "4h",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) > 0
}

# DENY: ExternalSecret in prod namespace with daily refresh
test_deny_daily_refresh_prod if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "production",
		},
		"spec": {
			"refreshInterval": "1d",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) > 0
}

# ALLOW: ExternalSecret in prod with 30m refresh
test_allow_fast_refresh_prod if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "production",
		},
		"spec": {
			"refreshInterval": "30m",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) == 0
}

# ALLOW: ExternalSecret in prod with 1h refresh
test_allow_1h_refresh_prod if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "production",
		},
		"spec": {
			"refreshInterval": "1h",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) == 0
}

# ALLOW: ExternalSecret in staging with 24h refresh (non-prod)
test_allow_slow_refresh_staging if {
	result := secrets.deny_slow_refresh with input as {
		"kind": "ExternalSecret",
		"metadata": {
			"name": "app-secrets",
			"namespace": "staging",
		},
		"spec": {
			"refreshInterval": "24h",
			"secretStoreRef": {"name": "vault"},
		},
	}
	count(result) == 0
}
