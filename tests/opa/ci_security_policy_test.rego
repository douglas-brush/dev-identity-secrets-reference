# OPA Tests — CI Workflow Security Policies (Extended)
# Tests all rules in ci_security_policy.rego with both allow and deny scenarios.

package ci.advanced_security_test

import rego.v1

import data.ci.advanced_security

# =============================================================================
# Rule 1: deny_hardcoded_secrets
# =============================================================================

# DENY: Step with hardcoded secret
test_deny_hardcoded_secret_step if {
	result := advanced_security.deny_hardcoded_secrets with input as {
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

# DENY: Step with hardcoded private key
test_deny_hardcoded_private_key if {
	result := advanced_security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {"SSH_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----"},
			}],
		}},
	}
	count(result) > 0
}

# DENY: Job-level hardcoded credential
test_deny_hardcoded_credential_job if {
	result := advanced_security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"env": {"DB_CREDENTIAL": "admin:password123"},
			"steps": [{"run": "deploy.sh"}],
		}},
	}
	count(result) > 0
}

# DENY: Workflow-level hardcoded password
test_deny_hardcoded_password_workflow if {
	result := advanced_security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"env": {"ADMIN_PASSWORD": "supersecret"},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "echo test"}],
		}},
	}
	count(result) > 0
}

# ALLOW: Secret from GitHub secrets
test_allow_secret_from_gh_secrets if {
	result := advanced_security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {"MY_TOKEN": "${{ secrets.MY_TOKEN }}"},
			}],
		}},
	}
	count(result) == 0
}

# ALLOW: Non-secret env var
test_allow_nonsecret_env if {
	result := advanced_security.deny_hardcoded_secrets with input as {
		"on": {"push": {}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "echo test",
				"env": {"NODE_ENV": "production", "CI": "true"},
			}],
		}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 2: deny_static_tokens
# =============================================================================

# DENY: Static AWS credentials
test_deny_static_aws if {
	result := advanced_security.deny_static_tokens with input as {
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

# DENY: Static VAULT_TOKEN
test_deny_static_vault_token if {
	result := advanced_security.deny_static_tokens with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "vault kv get secret/app",
				"env": {"VAULT_TOKEN": "${{ secrets.VAULT_TOKEN }}"},
			}],
		}},
	}
	count(result) > 0
}

# ALLOW: VAULT_TOKEN from dynamic step output
test_allow_dynamic_vault_token if {
	result := advanced_security.deny_static_tokens with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "vault kv get secret/app",
				"env": {"VAULT_TOKEN": "${{ steps.vault-auth.outputs.token }}"},
			}],
		}},
	}
	count(result) == 0
}

# ALLOW: No cloud credentials
test_allow_no_cloud_creds if {
	result := advanced_security.deny_static_tokens with input as {
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

# =============================================================================
# Rule 3: deny_excessive_permissions
# =============================================================================

# DENY: Workflow-level contents: write without release
test_deny_contents_write_no_release if {
	result := advanced_security.deny_excessive_permissions with input as {
		"on": {"push": {}},
		"permissions": {"contents": "write"},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "npm test"}],
		}},
	}
	count(result) > 0
}

# DENY: Job-level contents: write without release
test_deny_job_contents_write if {
	result := advanced_security.deny_excessive_permissions with input as {
		"on": {"push": {}},
		"jobs": {"lint": {
			"runs-on": "ubuntu-latest",
			"permissions": {"contents": "write"},
			"steps": [{"run": "npm run lint"}],
		}},
	}
	count(result) > 0
}

# ALLOW: Contents write with release action
test_allow_contents_write_with_release if {
	result := advanced_security.deny_excessive_permissions with input as {
		"on": {"push": {"tags": ["v*"]}},
		"permissions": {"contents": "write"},
		"jobs": {"release": {
			"runs-on": "ubuntu-latest",
			"steps": [{"uses": "softprops/action-gh-release@v1"}],
		}},
	}
	count(result) == 0
}

# ALLOW: Contents write with git push
test_allow_contents_write_git_push if {
	result := advanced_security.deny_excessive_permissions with input as {
		"on": {"push": {}},
		"permissions": {"contents": "write"},
		"jobs": {"bump": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "git commit -am 'bump' && git push"}],
		}},
	}
	count(result) == 0
}

# ALLOW: Contents read only
test_allow_contents_read if {
	result := advanced_security.deny_excessive_permissions with input as {
		"on": {"push": {}},
		"permissions": {"contents": "read"},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "npm test"}],
		}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 4: deny_missing_cleanup
# =============================================================================

# DENY: Vault action without cleanup step
test_deny_vault_no_cleanup if {
	result := advanced_security.deny_missing_cleanup with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [
				{"uses": "hashicorp/vault-action@v2", "with": {"url": "https://vault.example.com"}},
				{"run": "deploy.sh"},
			],
		}},
	}
	count(result) > 0
}

# DENY: AWS creds without cleanup step
test_deny_aws_creds_no_cleanup if {
	result := advanced_security.deny_missing_cleanup with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"run": "aws s3 cp . s3://bucket/",
				"env": {
					"AWS_ACCESS_KEY_ID": "${{ secrets.AWS_KEY }}",
					"AWS_SECRET_ACCESS_KEY": "${{ secrets.AWS_SECRET }}",
				},
			}],
		}},
	}
	count(result) > 0
}

# ALLOW: Vault action with cleanup step
test_allow_vault_with_cleanup if {
	result := advanced_security.deny_missing_cleanup with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [
				{"uses": "hashicorp/vault-action@v2", "with": {"url": "https://vault.example.com"}},
				{"run": "deploy.sh"},
				{"name": "Cleanup credentials", "run": "rm -f /tmp/creds", "if": "always()"},
			],
		}},
	}
	count(result) == 0
}

# ALLOW: Vault with revoke step
test_allow_vault_with_revoke if {
	result := advanced_security.deny_missing_cleanup with input as {
		"on": {"push": {}},
		"jobs": {"deploy": {
			"runs-on": "ubuntu-latest",
			"steps": [
				{"uses": "hashicorp/vault-action@v2", "with": {"url": "https://vault.example.com"}},
				{"run": "deploy.sh"},
				{"name": "Revoke Vault token", "run": "vault token revoke -self"},
			],
		}},
	}
	count(result) == 0
}

# =============================================================================
# Rule 5: deny_pr_target_checkout
# =============================================================================

# DENY: pull_request_target with checkout of PR head SHA
test_deny_pr_target_checkout_sha if {
	result := advanced_security.deny_pr_target_checkout with input as {
		"on": {"pull_request_target": {"types": ["opened"]}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"uses": "actions/checkout@v4",
				"with": {"ref": "${{ github.event.pull_request.head.sha }}"},
			}],
		}},
	}
	count(result) > 0
}

# DENY: pull_request_target with checkout of PR head ref
test_deny_pr_target_checkout_ref if {
	result := advanced_security.deny_pr_target_checkout with input as {
		"on": {"pull_request_target": {"types": ["opened"]}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"uses": "actions/checkout@v4",
				"with": {"ref": "${{ github.event.pull_request.head.ref }}"},
			}],
		}},
	}
	count(result) > 0
}

# DENY: pull_request_target with bare checkout (no ref specified)
test_deny_pr_target_bare_checkout if {
	result := advanced_security.deny_pr_target_checkout with input as {
		"on": {"pull_request_target": {"types": ["opened"]}},
		"jobs": {"label": {
			"runs-on": "ubuntu-latest",
			"steps": [{"uses": "actions/checkout@v4"}],
		}},
	}
	count(result) > 0
}

# ALLOW: pull_request_target without checkout
test_allow_pr_target_no_checkout if {
	result := advanced_security.deny_pr_target_checkout with input as {
		"on": {"pull_request_target": {"types": ["labeled"]}},
		"jobs": {"label": {
			"runs-on": "ubuntu-latest",
			"steps": [{"run": "echo 'Label applied'"}],
		}},
	}
	count(result) == 0
}

# ALLOW: pull_request (not target) with checkout
test_allow_pr_with_checkout if {
	result := advanced_security.deny_pr_target_checkout with input as {
		"on": {"pull_request": {"branches": ["main"]}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{"uses": "actions/checkout@v4"}],
		}},
	}
	count(result) == 0
}

# ALLOW: pull_request_target with checkout of base ref (safe)
test_allow_pr_target_checkout_base if {
	result := advanced_security.deny_pr_target_checkout with input as {
		"on": {"pull_request_target": {"types": ["opened"]}},
		"jobs": {"build": {
			"runs-on": "ubuntu-latest",
			"steps": [{
				"uses": "actions/checkout@v4",
				"with": {"ref": "${{ github.event.pull_request.base.ref }}"},
			}],
		}},
	}
	count(result) == 0
}
