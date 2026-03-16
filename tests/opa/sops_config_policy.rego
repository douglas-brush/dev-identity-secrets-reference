# OPA Policy — SOPS Configuration Validation Controls
# Validates .sops.yaml configuration files against security best practices.
#
# Rules:
#   1. Must have creation_rules defined
#   2. Must use age or cloud KMS (not PGP)
#   3. Must have path_regex for environment separation
#   4. Must not have unencrypted_suffix without explicit allowlist

package sops.config

import rego.v1

# --- Rule 1: Must have creation_rules ---

deny_missing_creation_rules contains msg if {
	not input.creation_rules
	msg := "DENY: .sops.yaml must have 'creation_rules' defined."
}

deny_missing_creation_rules contains msg if {
	count(input.creation_rules) == 0
	msg := "DENY: .sops.yaml 'creation_rules' must not be empty."
}

# --- Rule 2: Must use age or cloud KMS (not PGP) ---

deny_pgp_usage contains msg if {
	some i
	rule := input.creation_rules[i]
	rule.pgp
	msg := sprintf(
		"DENY: creation_rules[%d] uses PGP. Use age keys or cloud KMS (AWS KMS, GCP KMS, Azure Key Vault) instead.",
		[i],
	)
}

deny_pgp_usage contains msg if {
	some i
	rule := input.creation_rules[i]
	some j
	key_group := rule.key_groups[j]
	key_group.pgp
	count(key_group.pgp) > 0
	msg := sprintf(
		"DENY: creation_rules[%d].key_groups[%d] uses PGP. Use age keys or cloud KMS instead.",
		[i, j],
	)
}

# Warn if no encryption key method is specified at all
deny_no_key_method contains msg if {
	some i
	rule := input.creation_rules[i]
	not rule.age
	not rule.kms
	not rule.gcp_kms
	not rule.azure_keyvault
	not rule.hc_vault_transit_uri
	not rule.key_groups
	msg := sprintf(
		"DENY: creation_rules[%d] has no encryption key method specified. Use age, kms, gcp_kms, azure_keyvault, or hc_vault_transit_uri.",
		[i],
	)
}

# --- Rule 3: Must have path_regex for environment separation ---

deny_missing_path_regex contains msg if {
	count(input.creation_rules) > 1
	some i
	rule := input.creation_rules[i]
	not rule.path_regex
	msg := sprintf(
		"DENY: creation_rules[%d] is missing 'path_regex'. Environment separation requires path-based rules.",
		[i],
	)
}

# Single rule without path_regex is also a problem if there are env-specific paths expected
deny_missing_path_regex contains msg if {
	count(input.creation_rules) == 1
	not input.creation_rules[0].path_regex
	msg := "DENY: Single creation rule without 'path_regex'. Use path-based rules for environment separation."
}

# --- Rule 4: No unencrypted_suffix without explicit allowlist ---

deny_unencrypted_suffix contains msg if {
	some i
	rule := input.creation_rules[i]
	rule.unencrypted_suffix
	not rule.allowed_unencrypted_keys
	msg := sprintf(
		"DENY: creation_rules[%d] has 'unencrypted_suffix' ('%s') without 'allowed_unencrypted_keys'. Explicitly allowlist which keys may remain unencrypted.",
		[i, rule.unencrypted_suffix],
	)
}

deny_unencrypted_suffix contains msg if {
	some i
	rule := input.creation_rules[i]
	rule.unencrypted_suffix
	rule.allowed_unencrypted_keys
	count(rule.allowed_unencrypted_keys) == 0
	msg := sprintf(
		"DENY: creation_rules[%d] has 'unencrypted_suffix' with empty 'allowed_unencrypted_keys'. Provide an explicit allowlist or remove unencrypted_suffix.",
		[i],
	)
}

# --- Aggregate all violations ---

violations contains msg if {
	some msg in deny_missing_creation_rules
}

violations contains msg if {
	some msg in deny_pgp_usage
}

violations contains msg if {
	some msg in deny_no_key_method
}

violations contains msg if {
	some msg in deny_missing_path_regex
}

violations contains msg if {
	some msg in deny_unencrypted_suffix
}
