# OPA Tests — Vault HCL Policy Validation
# Tests all rules in vault_policy.rego with both allow and deny scenarios.

package vault.policy_test

import rego.v1

import data.vault.policy

# =============================================================================
# Rule 1: deny_wildcard_sensitive — No wildcard on sensitive paths
# =============================================================================

# DENY: Wildcard capability on sys/ path
test_deny_wildcard_on_sys if {
	result := policy.deny_wildcard_sensitive with input as {
		"name": "admin-policy",
		"header_comment": "Admin policy",
		"rules": [{"path": "sys/mounts", "capabilities": ["*"]}],
	}
	count(result) > 0
}

# DENY: Wildcard capability on auth/ path
test_deny_wildcard_on_auth if {
	result := policy.deny_wildcard_sensitive with input as {
		"name": "admin-policy",
		"header_comment": "Admin policy",
		"rules": [{"path": "auth/token/create", "capabilities": ["*"]}],
	}
	count(result) > 0
}

# DENY: Sudo on sensitive path (non-break-glass)
test_deny_sudo_on_sensitive_non_breakglass if {
	result := policy.deny_wildcard_sensitive with input as {
		"name": "admin-policy",
		"header_comment": "Admin policy",
		"rules": [{"path": "sys/policy", "capabilities": ["sudo", "read"]}],
	}
	count(result) > 0
}

# ALLOW: Wildcard on non-sensitive path
test_allow_wildcard_on_nonsensitive if {
	result := policy.deny_wildcard_sensitive with input as {
		"name": "app-policy",
		"header_comment": "App policy",
		"rules": [{"path": "secret/data/myapp/*", "capabilities": ["*"]}],
	}
	count(result) == 0
}

# ALLOW: Read-only on sensitive path
test_allow_read_on_sensitive if {
	result := policy.deny_wildcard_sensitive with input as {
		"name": "readonly-policy",
		"header_comment": "Read-only policy",
		"rules": [{"path": "sys/health", "capabilities": ["read"]}],
	}
	count(result) == 0
}

# =============================================================================
# Rule 2: deny_break_glass_missing_seal_deny
# =============================================================================

# DENY: Break-glass missing deny on sys/seal
test_deny_breakglass_no_seal_deny if {
	result := policy.deny_break_glass_missing_seal_deny with input as {
		"name": "break-glass-emergency",
		"header_comment": "Emergency break-glass",
		"rules": [
			{"path": "sys/*", "capabilities": ["sudo", "read", "list"]},
			{"path": "sys/unseal", "capabilities": ["deny"]},
		],
	}
	count(result) > 0
}

# DENY: Break-glass missing deny on sys/unseal
test_deny_breakglass_no_unseal_deny if {
	result := policy.deny_break_glass_missing_seal_deny with input as {
		"name": "break-glass-emergency",
		"header_comment": "Emergency break-glass",
		"rules": [
			{"path": "sys/*", "capabilities": ["sudo", "read", "list"]},
			{"path": "sys/seal", "capabilities": ["deny"]},
		],
	}
	count(result) > 0
}

# ALLOW: Break-glass with both seal and unseal denied
test_allow_breakglass_with_seal_deny if {
	result := policy.deny_break_glass_missing_seal_deny with input as {
		"name": "break-glass-emergency",
		"header_comment": "Emergency break-glass",
		"rules": [
			{"path": "sys/*", "capabilities": ["sudo", "read", "list"]},
			{"path": "sys/seal", "capabilities": ["deny"]},
			{"path": "sys/unseal", "capabilities": ["deny"]},
		],
	}
	count(result) == 0
}

# ALLOW: Non-break-glass policy (rule should not fire)
test_allow_non_breakglass_no_seal_deny if {
	result := policy.deny_break_glass_missing_seal_deny with input as {
		"name": "app-policy",
		"header_comment": "Application policy",
		"rules": [{"path": "secret/data/app/*", "capabilities": ["read"]}],
	}
	count(result) == 0
}

# =============================================================================
# Rule 3: deny_missing_header
# =============================================================================

# DENY: Policy with no header comment field
test_deny_no_header_comment if {
	result := policy.deny_missing_header with input as {
		"name": "bad-policy",
		"rules": [{"path": "secret/*", "capabilities": ["read"]}],
	}
	count(result) > 0
}

# DENY: Policy with empty header comment
test_deny_empty_header_comment if {
	result := policy.deny_missing_header with input as {
		"name": "bad-policy",
		"header_comment": "",
		"rules": [{"path": "secret/*", "capabilities": ["read"]}],
	}
	count(result) > 0
}

# ALLOW: Policy with header comment
test_allow_policy_with_header if {
	result := policy.deny_missing_header with input as {
		"name": "good-policy",
		"header_comment": "This policy grants read access to application secrets.",
		"rules": [{"path": "secret/data/myapp/*", "capabilities": ["read"]}],
	}
	count(result) == 0
}

# =============================================================================
# Rule 4: deny_sudo_non_breakglass
# =============================================================================

# DENY: Sudo on regular policy
test_deny_sudo_regular_policy if {
	result := policy.deny_sudo_non_breakglass with input as {
		"name": "admin-policy",
		"header_comment": "Admin policy",
		"rules": [{"path": "secret/data/*", "capabilities": ["sudo", "read", "create", "update"]}],
	}
	count(result) > 0
}

# DENY: Sudo on non-sensitive path in regular policy
test_deny_sudo_nonsensitive_path if {
	result := policy.deny_sudo_non_breakglass with input as {
		"name": "dev-policy",
		"header_comment": "Dev policy",
		"rules": [{"path": "kv/data/dev/*", "capabilities": ["sudo", "read"]}],
	}
	count(result) > 0
}

# ALLOW: Sudo in break-glass policy
test_allow_sudo_breakglass if {
	result := policy.deny_sudo_non_breakglass with input as {
		"name": "break-glass-emergency",
		"header_comment": "Emergency break-glass",
		"rules": [
			{"path": "sys/*", "capabilities": ["sudo", "read", "list"]},
			{"path": "sys/seal", "capabilities": ["deny"]},
			{"path": "sys/unseal", "capabilities": ["deny"]},
		],
	}
	count(result) == 0
}

# ALLOW: No sudo in regular policy
test_allow_no_sudo_regular if {
	result := policy.deny_sudo_non_breakglass with input as {
		"name": "app-policy",
		"header_comment": "App policy",
		"rules": [{"path": "secret/data/app/*", "capabilities": ["read", "create", "update"]}],
	}
	count(result) == 0
}

# ALLOW: Sudo in breakglass (underscore variant)
test_allow_sudo_break_glass_underscore if {
	result := policy.deny_sudo_non_breakglass with input as {
		"name": "break_glass_ops",
		"header_comment": "Break glass operations",
		"rules": [{"path": "sys/health", "capabilities": ["sudo", "read"]}],
	}
	count(result) == 0
}

# =============================================================================
# Rule 5: deny_transit_delete
# =============================================================================

# DENY: Delete on transit key path
test_deny_transit_key_delete if {
	result := policy.deny_transit_delete with input as {
		"name": "transit-policy",
		"header_comment": "Transit policy",
		"rules": [{"path": "transit/keys/my-key", "capabilities": ["read", "create", "delete"]}],
	}
	count(result) > 0
}

# DENY: Delete on transit keys wildcard
test_deny_transit_keys_wildcard_delete if {
	result := policy.deny_transit_delete with input as {
		"name": "transit-admin",
		"header_comment": "Transit admin",
		"rules": [{"path": "transit/keys/*", "capabilities": ["read", "create", "update", "delete"]}],
	}
	count(result) > 0
}

# DENY: Delete on transit/keys root
test_deny_transit_keys_root_delete if {
	result := policy.deny_transit_delete with input as {
		"name": "transit-admin",
		"header_comment": "Transit admin",
		"rules": [{"path": "transit/keys", "capabilities": ["delete", "list"]}],
	}
	count(result) > 0
}

# ALLOW: Transit encrypt/decrypt without delete
test_allow_transit_no_delete if {
	result := policy.deny_transit_delete with input as {
		"name": "transit-user",
		"header_comment": "Transit user",
		"rules": [
			{"path": "transit/encrypt/my-key", "capabilities": ["update"]},
			{"path": "transit/decrypt/my-key", "capabilities": ["update"]},
			{"path": "transit/keys/my-key", "capabilities": ["read"]},
		],
	}
	count(result) == 0
}

# ALLOW: Delete on non-transit path
test_allow_delete_nontransit if {
	result := policy.deny_transit_delete with input as {
		"name": "kv-admin",
		"header_comment": "KV admin",
		"rules": [{"path": "secret/data/temp/*", "capabilities": ["read", "create", "delete"]}],
	}
	count(result) == 0
}
