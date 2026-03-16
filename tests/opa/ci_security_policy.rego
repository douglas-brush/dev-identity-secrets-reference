# OPA Policy — CI Workflow Security Controls (Extended)
# Validates GitHub Actions workflow files against advanced security best practices.
#
# Rules:
#   1. No hardcoded secrets in env blocks
#   2. OIDC auth preferred over static tokens
#   3. Permissions must be least-privilege (no contents: write unless justified)
#   4. Must have cleanup/revoke step
#   5. No pull_request_target with checkout of PR code

package ci.advanced_security

import rego.v1

# --- Rule 1: No hardcoded secrets in env blocks ---

deny_hardcoded_secrets contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	env_val := step.env[env_name]
	_looks_like_secret_name(env_name)
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
	_looks_like_secret_name(env_name)
	not startswith(env_val, "${{")
	msg := sprintf(
		"DENY: Job '%s' has job-level env var '%s' with a hardcoded value. Use '${{ secrets.* }}' or OIDC instead.",
		[job_name, env_name],
	)
}

deny_hardcoded_secrets contains msg if {
	input.on
	env_val := input.env[env_name]
	_looks_like_secret_name(env_name)
	not startswith(env_val, "${{")
	msg := sprintf(
		"DENY: Workflow-level env var '%s' has a hardcoded value. Use '${{ secrets.* }}' or OIDC instead.",
		[env_name],
	)
}

_looks_like_secret_name(name) if {
	lower_name := lower(name)
	_secret_patterns[pattern]
	contains(lower_name, pattern)
}

_looks_like_secret_name(name) if {
	name == "AWS_ACCESS_KEY_ID"
}

_looks_like_secret_name(name) if {
	name == "AWS_SECRET_ACCESS_KEY"
}

_secret_patterns contains "secret"

_secret_patterns contains "password"

_secret_patterns contains "token"

_secret_patterns contains "api_key"

_secret_patterns contains "apikey"

_secret_patterns contains "credential"

_secret_patterns contains "private_key"

# --- Rule 2: OIDC auth preferred over static tokens ---

deny_static_tokens contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	step.env.AWS_ACCESS_KEY_ID
	step.env.AWS_SECRET_ACCESS_KEY
	msg := sprintf(
		"DENY: Job '%s', step %d uses static AWS credentials. Use OIDC with 'aws-actions/configure-aws-credentials' and role-to-assume instead.",
		[job_name, step_idx + 1],
	)
}

deny_static_tokens contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	step.env.AZURE_CLIENT_SECRET
	msg := sprintf(
		"DENY: Job '%s', step %d uses static Azure credentials. Use OIDC with federated credentials instead.",
		[job_name, step_idx + 1],
	)
}

deny_static_tokens contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	step.env.VAULT_TOKEN
	env_val := step.env.VAULT_TOKEN
	not startswith(env_val, "${{ steps.")
	msg := sprintf(
		"DENY: Job '%s', step %d uses a static VAULT_TOKEN. Use Vault's JWT/OIDC auth method or retrieve tokens dynamically.",
		[job_name, step_idx + 1],
	)
}

# --- Rule 3: Permissions must be least-privilege ---

deny_excessive_permissions contains msg if {
	input.on
	input.permissions.contents == "write"
	not _workflow_needs_write(input)
	msg := "DENY: Workflow-level 'contents: write' is overly permissive. Use 'contents: read' unless the workflow creates releases or pushes commits."
}

deny_excessive_permissions contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	job.permissions.contents == "write"
	not _job_needs_write(job)
	msg := sprintf(
		"DENY: Job '%s' has 'contents: write' permission. Use 'contents: read' unless the job creates releases or pushes commits.",
		[job_name],
	)
}

# A workflow needs write if any job uses release actions or git push
_workflow_needs_write(workflow) if {
	some job_name
	_job_needs_write(workflow.jobs[job_name])
}

_job_needs_write(job) if {
	some step_idx
	step := job.steps[step_idx]
	_is_release_action(step)
}

_job_needs_write(job) if {
	some step_idx
	step := job.steps[step_idx]
	step.run
	contains(step.run, "git push")
}

_is_release_action(step) if {
	startswith(step.uses, "softprops/action-gh-release")
}

_is_release_action(step) if {
	startswith(step.uses, "actions/create-release")
}

_is_release_action(step) if {
	startswith(step.uses, "ncipollo/release-action")
}

# --- Rule 4: Must have cleanup/revoke step ---

deny_missing_cleanup contains msg if {
	input.on
	some job_name
	job := input.jobs[job_name]
	_job_uses_credentials(job)
	not _job_has_cleanup(job)
	msg := sprintf(
		"DENY: Job '%s' uses credentials but has no cleanup/revoke step. Add a step to revoke tokens or clean up credentials.",
		[job_name],
	)
}

_job_uses_credentials(job) if {
	some step_idx
	step := job.steps[step_idx]
	step.env.AWS_ACCESS_KEY_ID
}

_job_uses_credentials(job) if {
	some step_idx
	step := job.steps[step_idx]
	step.env.VAULT_TOKEN
}

_job_uses_credentials(job) if {
	some step_idx
	step := job.steps[step_idx]
	step.env.AZURE_CLIENT_SECRET
}

_job_uses_credentials(job) if {
	some step_idx
	step := job.steps[step_idx]
	_is_vault_action(step)
}

_is_vault_action(step) if {
	startswith(step.uses, "hashicorp/vault-action")
}

_job_has_cleanup(job) if {
	some step_idx
	step := job.steps[step_idx]
	contains(lower(object.get(step, "name", "")), "cleanup")
}

_job_has_cleanup(job) if {
	some step_idx
	step := job.steps[step_idx]
	contains(lower(object.get(step, "name", "")), "revoke")
}

_job_has_cleanup(job) if {
	some step_idx
	step := job.steps[step_idx]
	step.run
	contains(step.run, "vault token revoke")
}

_job_has_cleanup(job) if {
	some step_idx
	step := job.steps[step_idx]
	step.if == "always()"
	_step_has_credential_cleanup(step)
}

_step_has_credential_cleanup(step) if {
	step.run
	contains(lower(step.run), "clean")
}

_step_has_credential_cleanup(step) if {
	step.run
	contains(lower(step.run), "revoke")
}

# --- Rule 5: No pull_request_target with checkout of PR code ---

deny_pr_target_checkout contains msg if {
	input.on.pull_request_target
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	_is_checkout_action(step)
	_checks_out_pr_head(step)
	msg := sprintf(
		"DENY: Job '%s', step %d checks out PR code in a pull_request_target workflow. This allows arbitrary code execution with write permissions. Use pull_request trigger instead.",
		[job_name, step_idx + 1],
	)
}

deny_pr_target_checkout contains msg if {
	input.on.pull_request_target
	some job_name
	job := input.jobs[job_name]
	some step_idx
	step := job.steps[step_idx]
	_is_checkout_action(step)
	not step["with"]
	msg := sprintf(
		"DENY: Job '%s', step %d uses checkout in a pull_request_target workflow without explicit ref. This may check out PR code with write permissions.",
		[job_name, step_idx + 1],
	)
}

_is_checkout_action(step) if {
	startswith(step.uses, "actions/checkout")
}

_checks_out_pr_head(step) if {
	step["with"].ref == "${{ github.event.pull_request.head.sha }}"
}

_checks_out_pr_head(step) if {
	step["with"].ref == "${{ github.event.pull_request.head.ref }}"
}

_checks_out_pr_head(step) if {
	contains(object.get(object.get(step, "with", {}), "ref", ""), "pull_request.head")
}

# --- Aggregate all violations ---

violations contains msg if {
	some msg in deny_hardcoded_secrets
}

violations contains msg if {
	some msg in deny_static_tokens
}

violations contains msg if {
	some msg in deny_excessive_permissions
}

violations contains msg if {
	some msg in deny_missing_cleanup
}

violations contains msg if {
	some msg in deny_pr_target_checkout
}
