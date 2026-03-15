# OPA Tests — CI/CD Pipeline Security Policies
# Tests all rules in ci_policy.rego with both allow and deny scenarios.

package ci.security_test

import rego.v1

import data.ci.security

# =============================================================================
# Rule 1: deny_missing_oidc_permission
# =============================================================================

# DENY: Workflow without id-token permission
test_deny_no_oidc_permission if {
	result := security.deny_missing_oidc_permission with input as {
		"on": {"push": {"branches": ["main"]}},
		"permissions": {"contents": "read"},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "echo hello"}],
		}},
	}
	count(result) > 0
}

# DENY: Workflow with no permissions at all
test_deny_no_permissions if {
	result := security.deny_missing_oidc_permission with input as {
		"on": {"push": {"branches": ["main"]}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "echo hello"}],
		}},
	}
	count(result) > 0
}

# ALLOW: Workflow with workflow-level id-token: write
test_allow_workflow_level_oidc if {
	result := security.deny_missing_oidc_permission with input as {
		"on": {"push": {"branches": ["main"]}},
		"permissions": {
			"contents": "read",
			"id-token": "write",
		},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "echo deploy"}],
		}},
	}
	count(result) == 0
}

# ALLOW: Workflow with job-level id-token: write
test_allow_job_level_oidc if {
	result := security.deny_missing_oidc_permission with input as {
		"on": {"push": {"branches": ["main"]}},
		"permissions": {"contents": "read"},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"permissions": {"id-token": "write"},
			"steps": [{"run": "echo deploy"}],
		}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 2: deny_hardcoded_secrets
# =============================================================================

# DENY: Step with hardcoded secret env var
test_deny_hardcoded_secret_in_step if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {"MY_SECRET": "hardcoded-value"},
			}],
		}},
	}
	count(result) > 0
}

# DENY: Step with hardcoded password
test_deny_hardcoded_password if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {"DB_PASSWORD": "p@ssw0rd"},
			}],
		}},
	}
	count(result) > 0
}

# DENY: Step with hardcoded AWS access key
test_deny_hardcoded_aws_key if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "aws s3 ls",
				"env": {"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			}],
		}},
	}
	count(result) > 0
}

# DENY: Job-level hardcoded token
test_deny_hardcoded_token_job_level if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"env": {"API_TOKEN": "tok_1234567890"},
			"steps": [{"run": "curl -H 'Authorization: Bearer $API_TOKEN'"}],
		}},
	}
	count(result) > 0
}

# DENY: Workflow-level hardcoded secret
test_deny_hardcoded_secret_workflow_level if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"env": {"APP_SECRET": "my-secret-value"},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "echo test"}],
		}},
	}
	count(result) > 0
}

# ALLOW: Secret from ${{ secrets.* }}
test_allow_secret_from_github_secrets if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {"MY_SECRET": "${{ secrets.MY_SECRET }}"},
			}],
		}},
	}
	count(result) == 0
}

# ALLOW: Non-secret env var with hardcoded value
test_allow_non_secret_hardcoded if {
	result := security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {
					"NODE_ENV": "production",
					"LOG_LEVEL": "info",
				},
			}],
		}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 3: deny_static_cloud_creds
# =============================================================================

# DENY: Static AWS credentials
test_deny_static_aws_creds if {
	result := security.deny_static_cloud_creds with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "aws s3 ls",
				"env": {
					"AWS_ACCESS_KEY_ID": "${{ secrets.AWS_KEY }}",
					"AWS_SECRET_ACCESS_KEY": "${{ secrets.AWS_SECRET }}",
				},
			}],
		}},
	}
	count(result) > 0
}

# DENY: Static Azure credentials
test_deny_static_azure_creds if {
	result := security.deny_static_cloud_creds with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "az login",
				"env": {
					"AZURE_CLIENT_ID": "${{ secrets.AZURE_CLIENT_ID }}",
					"AZURE_CLIENT_SECRET": "${{ secrets.AZURE_CLIENT_SECRET }}",
					"AZURE_TENANT_ID": "${{ secrets.AZURE_TENANT_ID }}",
				},
			}],
		}},
	}
	count(result) > 0
}

# DENY: Static GCP credentials (service account key file)
test_deny_static_gcp_creds if {
	result := security.deny_static_cloud_creds with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "gcloud auth activate-service-account",
				"env": {"GOOGLE_APPLICATION_CREDENTIALS": "/tmp/sa-key.json"},
			}],
		}},
	}
	count(result) > 0
}

# ALLOW: AWS OIDC auth (no static creds)
test_allow_aws_oidc if {
	result := security.deny_static_cloud_creds with input as {
		"on": {"push": {}},
		"permissions": {"id-token": "write"},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"uses": "aws-actions/configure-aws-credentials@v4",
				"with": {
					"role-to-assume": "arn:aws:iam::123456789:role/deploy",
					"aws-region": "us-east-1",
				},
			}],
		}},
	}
	count(result) == 0
}

# ALLOW: GCP workload identity
test_allow_gcp_workload_identity if {
	result := security.deny_static_cloud_creds with input as {
		"on": {"push": {}},
		"permissions": {"id-token": "write"},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"uses": "google-github-actions/auth@v2",
				"with": {"workload_identity_provider": "projects/123/locations/global/workloadIdentityPools/pool/providers/provider"},
			}],
		}},
	}
	count(result) == 0
}

# ALLOW: Step without cloud credentials
test_allow_no_cloud_creds if {
	result := security.deny_static_cloud_creds with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "npm test",
				"env": {"NODE_ENV": "test"},
			}],
		}},
	}
	count(result) == 0
}
