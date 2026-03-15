# OPA Policy — CI/CD Pipeline Security Controls
# Validates GitHub Actions workflow files against security best practices.
#
# Rules:
#   1. GitHub Actions must have id-token: write permission for OIDC
#   2. No hardcoded secrets in workflow files
#   3. Must use OIDC for cloud auth (no static credentials)

package ci.security

import rego.v1

# --- Rule 1: Require id-token: write permission ---

deny_missing_oidc_permission contains msg if {
	# Check for workflow-level permissions
	input.on  # This is a GitHub Actions workflow file
	not _has_id_token_write(input)
	not _any_job_has_id_token_write(input)
	msg := "DENY: GitHub Actions workflow must have 'permissions.id-token: write' at workflow or job level for OIDC authentication."
}

_has_id_token_write(workflow) if {
	workflow.permissions["id-token"] == "write"
}

_any_job_has_id_token_write(workflow) if {
	some job_name
	workflow.jobs[job_name].permissions["id-token"] == "write"
}

# --- Rule 2: No hardcoded secrets ---

deny_hardcoded_secrets contains msg if {
	input.on  # GitHub Actions workflow
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	env_val := step.env[env_name]
	_looks_like_secret(env_name)
	not startswith(env_val, "${{")
	msg := sprintf(
		"DENY: Job '%s', step %d has env var '%s' with a hardcoded value. Use '${{ secrets.* }}' or OIDC instead.",
		[job_name, step_idx + 1, env_name],
	)
}

deny_hardcoded_secrets contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	env_val := job.env[env_name]
	_looks_like_secret(env_name)
	not startswith(env_val, "${{")
	msg := sprintf(
		"DENY: Job '%s' has job-level env var '%s' with a hardcoded value. Use '${{ secrets.* }}' or OIDC instead.",
		[job_name, env_name],
	)
}

deny_hardcoded_secrets contains msg if {
	input.on
	env_val := input.env[env_name]
	_looks_like_secret(env_name)
	not startswith(env_val, "${{")
	msg := sprintf(
		"DENY: Workflow-level env var '%s' has a hardcoded value. Use '${{ secrets.* }}' or OIDC instead.",
		[env_name],
	)
}

_looks_like_secret(name) if {
	lower_name := lower(name)
	contains(lower_name, "secret")
}

_looks_like_secret(name) if {
	lower_name := lower(name)
	contains(lower_name, "password")
}

_looks_like_secret(name) if {
	lower_name := lower(name)
	contains(lower_name, "token")
}

_looks_like_secret(name) if {
	lower_name := lower(name)
	contains(lower_name, "api_key")
}

_looks_like_secret(name) if {
	lower_name := lower(name)
	contains(lower_name, "apikey")
}

_looks_like_secret(name) if {
	name == "AWS_SECRET_ACCESS_KEY"
}

_looks_like_secret(name) if {
	name == "AWS_ACCESS_KEY_ID"
}

_looks_like_secret(name) if {
	lower_name := lower(name)
	contains(lower_name, "credential")
}

# --- Rule 3: Must use OIDC for cloud auth ---

deny_static_cloud_creds contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	# Check for AWS static credential usage
	step.env.AWS_ACCESS_KEY_ID
	step.env.AWS_SECRET_ACCESS_KEY
	msg := sprintf(
		"DENY: Job '%s', step %d uses static AWS credentials (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY). Use OIDC with 'aws-actions/configure-aws-credentials' and role-to-assume instead.",
		[job_name, step_idx + 1],
	)
}

deny_static_cloud_creds contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	# Check for Azure static credential usage
	step.env.AZURE_CLIENT_SECRET
	msg := sprintf(
		"DENY: Job '%s', step %d uses static Azure credentials (AZURE_CLIENT_SECRET). Use OIDC with 'azure/login' and federated credentials instead.",
		[job_name, step_idx + 1],
	)
}

deny_static_cloud_creds contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	# Check for GCP static credential usage (service account key)
	step.env.GOOGLE_APPLICATION_CREDENTIALS
	not _is_workload_identity_file(step.env.GOOGLE_APPLICATION_CREDENTIALS)
	msg := sprintf(
		"DENY: Job '%s', step %d uses GOOGLE_APPLICATION_CREDENTIALS pointing to a static key file. Use OIDC with 'google-github-actions/auth' and workload_identity_provider instead.",
		[job_name, step_idx + 1],
	)
}

_is_workload_identity_file(path) if {
	contains(path, "workload_identity")
}

# --- Aggregate all violations ---

violations contains msg if {
	some msg in deny_missing_oidc_permission
}

violations contains msg if {
	some msg in deny_hardcoded_secrets
}

violations contains msg if {
	some msg in deny_static_cloud_creds
}
