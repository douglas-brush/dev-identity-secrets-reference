# OPA Tests — SOPS Configuration Policy Validation
# Tests all rules in sops_config_policy.rego with both allow and deny scenarios.

package sops.config_test

import rego.v1

import data.sops.config

# =============================================================================
# Rule 1: deny_missing_creation_rules
# =============================================================================

# DENY: No creation_rules field
test_deny_no_creation_rules if {
	result := config.deny_missing_creation_rules with input as {"stores": {}}
	count(result) > 0
}

# DENY: Empty creation_rules
test_deny_empty_creation_rules if {
	result := config.deny_missing_creation_rules with input as {"creation_rules": []}
	count(result) > 0
}

# ALLOW: Valid creation_rules present
test_allow_creation_rules_present if {
	result := config.deny_missing_creation_rules with input as {"creation_rules": [{
		"path_regex": ".*\\.enc\\.yaml$",
		"age": "age1abc123",
	}]}
	count(result) == 0
}

# =============================================================================
# Rule 2: deny_pgp_usage
# =============================================================================

# DENY: PGP key in creation rule
test_deny_pgp_in_creation_rule if {
	result := config.deny_pgp_usage with input as {"creation_rules": [{
		"path_regex": ".*",
		"pgp": "ABCDEF1234567890",
	}]}
	count(result) > 0
}

# DENY: PGP in key_groups
test_deny_pgp_in_key_groups if {
	result := config.deny_pgp_usage with input as {"creation_rules": [{
		"path_regex": ".*",
		"key_groups": [{"pgp": ["ABCDEF1234567890"]}],
	}]}
	count(result) > 0
}

# ALLOW: Age key (no PGP)
test_allow_age_key if {
	result := config.deny_pgp_usage with input as {"creation_rules": [{
		"path_regex": ".*\\.enc\\.yaml$",
		"age": "age1xyz789def456",
	}]}
	count(result) == 0
}

# ALLOW: AWS KMS (no PGP)
test_allow_aws_kms if {
	result := config.deny_pgp_usage with input as {"creation_rules": [{
		"path_regex": ".*\\.enc\\.yaml$",
		"kms": "arn:aws:kms:us-east-1:123456789:key/abc-123",
	}]}
	count(result) == 0
}

# =============================================================================
# Rule 3: deny_missing_path_regex
# =============================================================================

# DENY: Multiple rules without path_regex
test_deny_multi_rules_no_path_regex if {
	result := config.deny_missing_path_regex with input as {"creation_rules": [
		{"age": "age1abc"},
		{"age": "age1def"},
	]}
	count(result) > 0
}

# DENY: Single rule without path_regex
test_deny_single_rule_no_path_regex if {
	result := config.deny_missing_path_regex with input as {"creation_rules": [{"age": "age1abc"}]}
	count(result) > 0
}

# ALLOW: All rules have path_regex
test_allow_all_rules_with_path_regex if {
	result := config.deny_missing_path_regex with input as {"creation_rules": [
		{"path_regex": "prod/.*\\.enc\\.yaml$", "age": "age1prod"},
		{"path_regex": "staging/.*\\.enc\\.yaml$", "age": "age1staging"},
	]}
	count(result) == 0
}

# ALLOW: Single rule with path_regex
test_allow_single_rule_with_path_regex if {
	result := config.deny_missing_path_regex with input as {"creation_rules": [{
		"path_regex": ".*\\.enc\\.yaml$",
		"age": "age1abc",
	}]}
	count(result) == 0
}

# =============================================================================
# Rule 4: deny_unencrypted_suffix
# =============================================================================

# DENY: unencrypted_suffix without allowlist
test_deny_unencrypted_suffix_no_allowlist if {
	result := config.deny_unencrypted_suffix with input as {"creation_rules": [{
		"path_regex": ".*",
		"age": "age1abc",
		"unencrypted_suffix": "_unencrypted",
	}]}
	count(result) > 0
}

# DENY: unencrypted_suffix with empty allowlist
test_deny_unencrypted_suffix_empty_allowlist if {
	result := config.deny_unencrypted_suffix with input as {"creation_rules": [{
		"path_regex": ".*",
		"age": "age1abc",
		"unencrypted_suffix": "_unencrypted",
		"allowed_unencrypted_keys": [],
	}]}
	count(result) > 0
}

# ALLOW: unencrypted_suffix with populated allowlist
test_allow_unencrypted_suffix_with_allowlist if {
	result := config.deny_unencrypted_suffix with input as {"creation_rules": [{
		"path_regex": ".*",
		"age": "age1abc",
		"unencrypted_suffix": "_unencrypted",
		"allowed_unencrypted_keys": ["metadata", "description"],
	}]}
	count(result) == 0
}

# ALLOW: No unencrypted_suffix at all
test_allow_no_unencrypted_suffix if {
	result := config.deny_unencrypted_suffix with input as {"creation_rules": [{
		"path_regex": ".*",
		"age": "age1abc",
	}]}
	count(result) == 0
}

# =============================================================================
# Comprehensive: Full valid config
# =============================================================================

# ALLOW: Fully compliant SOPS config
test_allow_full_compliant_config if {
	result := config.violations with input as {"creation_rules": [
		{
			"path_regex": "environments/prod/.*\\.enc\\.yaml$",
			"age": "age1prodkey123",
		},
		{
			"path_regex": "environments/staging/.*\\.enc\\.yaml$",
			"age": "age1stagingkey456",
		},
	]}
	count(result) == 0
}
