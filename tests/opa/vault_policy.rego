# OPA Policy — Vault HCL Policy Validation Controls
# Validates Vault policy documents (parsed as JSON) against security best practices.
#
# Rules:
#   1. No wildcard capabilities on sensitive paths (sys/*, auth/*)
#   2. Break-glass policies must have explicit deny on seal/unseal
#   3. All policies must have a header comment
#   4. No sudo capability except break-glass policies
#   5. Transit policies cannot have delete on keys

package vault.policy

import rego.v1

# --- Rule 1: No wildcard capabilities on sensitive paths ---

deny_wildcard_sensitive contains msg if {
	some i
	rule := input.rules[i]
	_is_sensitive_path(rule.path)
	some cap in rule.capabilities
	cap == "*"
	msg := sprintf(
		"DENY: Wildcard capability '*' on sensitive path '%s'. Use explicit capabilities instead.",
		[rule.path],
	)
}

deny_wildcard_sensitive contains msg if {
	some i
	rule := input.rules[i]
	_is_sensitive_path(rule.path)
	some cap in rule.capabilities
	cap == "sudo"
	not _is_break_glass(input)
	msg := sprintf(
		"DENY: Sudo capability on sensitive path '%s' outside of break-glass policy.",
		[rule.path],
	)
}

_is_sensitive_path(path) if {
	startswith(path, "sys/")
}

_is_sensitive_path(path) if {
	path == "sys"
}

_is_sensitive_path(path) if {
	startswith(path, "auth/")
}

_is_sensitive_path(path) if {
	path == "auth"
}

# --- Rule 2: Break-glass policies must explicitly deny seal/unseal ---

deny_break_glass_missing_seal_deny contains msg if {
	_is_break_glass(input)
	not _has_deny_on_path(input.rules, "sys/seal")
	msg := "DENY: Break-glass policy must have explicit deny on 'sys/seal'."
}

deny_break_glass_missing_seal_deny contains msg if {
	_is_break_glass(input)
	not _has_deny_on_path(input.rules, "sys/unseal")
	msg := "DENY: Break-glass policy must have explicit deny on 'sys/unseal'."
}

_has_deny_on_path(rules, target_path) if {
	some i
	rules[i].path == target_path
	some cap in rules[i].capabilities
	cap == "deny"
}

_is_break_glass(policy) if {
	contains(lower(policy.name), "break-glass")
}

_is_break_glass(policy) if {
	contains(lower(policy.name), "breakglass")
}

_is_break_glass(policy) if {
	contains(lower(policy.name), "break_glass")
}

# --- Rule 3: All policies must have a header comment ---

deny_missing_header contains msg if {
	not input.header_comment
	msg := sprintf(
		"DENY: Policy '%s' is missing a header comment. All Vault policies must document their purpose.",
		[object.get(input, "name", "unknown")],
	)
}

deny_missing_header contains msg if {
	input.header_comment == ""
	msg := sprintf(
		"DENY: Policy '%s' has an empty header comment. All Vault policies must document their purpose.",
		[object.get(input, "name", "unknown")],
	)
}

# --- Rule 4: No sudo capability except break-glass ---

deny_sudo_non_breakglass contains msg if {
	not _is_break_glass(input)
	some i
	rule := input.rules[i]
	some cap in rule.capabilities
	cap == "sudo"
	msg := sprintf(
		"DENY: Sudo capability on path '%s' is only allowed in break-glass policies. Policy '%s' is not a break-glass policy.",
		[rule.path, object.get(input, "name", "unknown")],
	)
}

# --- Rule 5: Transit policies cannot have delete on keys ---

deny_transit_delete contains msg if {
	some i
	rule := input.rules[i]
	_is_transit_key_path(rule.path)
	some cap in rule.capabilities
	cap == "delete"
	msg := sprintf(
		"DENY: Transit key path '%s' has 'delete' capability. Deleting transit keys destroys all data encrypted with them.",
		[rule.path],
	)
}

_is_transit_key_path(path) if {
	startswith(path, "transit/keys/")
}

_is_transit_key_path(path) if {
	path == "transit/keys"
}

_is_transit_key_path(path) if {
	startswith(path, "transit/keys/*")
}

# --- Aggregate all violations ---

violations contains msg if {
	some msg in deny_wildcard_sensitive
}

violations contains msg if {
	some msg in deny_break_glass_missing_seal_deny
}

violations contains msg if {
	some msg in deny_missing_header
}

violations contains msg if {
	some msg in deny_sudo_non_breakglass
}

violations contains msg if {
	some msg in deny_transit_delete
}
