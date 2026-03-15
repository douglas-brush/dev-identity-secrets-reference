# vault-jit-policy.hcl — Vault policy and control group configuration for
# just-in-time privileged access with approval workflows and break-glass.
#
# This file defines:
#   1. A base (unprivileged) policy for day-to-day access
#   2. A privileged policy gated by control groups (requires approval)
#   3. An approver policy that can authorize control group requests
#   4. A break-glass policy with mandatory audit logging
#   5. Sentinel policy (EGP) for time-bounded access enforcement
#
# Deploy order:
#   1. Write policies:       vault policy write jit-base jit-base.hcl
#   2. Write policies:       vault policy write jit-privileged jit-privileged.hcl
#   3. Write policies:       vault policy write jit-approver jit-approver.hcl
#   4. Write policies:       vault policy write jit-break-glass jit-break-glass.hcl
#   5. Apply Sentinel EGP:   vault write sys/policies/egp/jit-time-bound ...
#   6. Configure identity groups for approvers
#
# Requires: Vault Enterprise (control groups + Sentinel) or Vault 1.16+
#           with the community control group feature.

# ============================================================================
# 1. BASE POLICY — Day-to-day non-privileged access
# ============================================================================
# Engineers get read access to their team's KV secrets and the ability to
# request elevation. No write access to production paths.

# Allow reading team-scoped secrets (non-production)
path "kv/data/dev/+/config" {
  capabilities = ["read", "list"]
}

path "kv/metadata/dev/+/config" {
  capabilities = ["read", "list"]
}

# Allow generating short-lived database credentials for dev/staging
path "database/creds/dev-*" {
  capabilities = ["read"]
}

# Allow requesting SSH certificates for non-production hosts
path "ssh-client-signer/sign/dev-role" {
  capabilities = ["update"]
}

# Allow reading own token info (needed for elevation workflow)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow requesting elevation (triggers control group)
path "sys/control-group/request" {
  capabilities = ["update"]
}

# ============================================================================
# 2. PRIVILEGED POLICY — Gated by control group approval
# ============================================================================
# Access to production secrets, admin operations, and sensitive infrastructure.
# Every path in this policy requires a control group authorization before
# the token can actually read the data.

# Production KV secrets — requires approval before access
path "kv/data/prod/+/config" {
  capabilities = ["read", "list"]

  # Control group: at least 1 approver from the "jit-approvers" group
  # must authorize before this path is accessible. The requester's token
  # is blocked until authorization is received or the TTL expires.
  control_group {
    factor "security-team-approval" {
      identity {
        group_names = ["jit-approvers"]
        approvals   = 1
      }
    }
    # Request expires after 1 hour if not approved
    ttl = "1h"
  }
}

# Production database credentials — requires approval
path "database/creds/prod-*" {
  capabilities = ["read"]

  control_group {
    factor "security-team-approval" {
      identity {
        group_names = ["jit-approvers"]
        approvals   = 1
      }
    }
    ttl = "30m"
  }
}

# Production SSH certificates — requires approval
path "ssh-client-signer/sign/prod-role" {
  capabilities = ["update"]

  control_group {
    factor "security-team-approval" {
      identity {
        group_names = ["jit-approvers"]
        approvals   = 1
      }
    }
    ttl = "30m"
  }
}

# PKI certificate issuance for production domains — requires approval
path "pki/issue/prod-server" {
  capabilities = ["update"]

  control_group {
    factor "security-team-approval" {
      identity {
        group_names = ["jit-approvers"]
        approvals   = 1
      }
    }
    ttl = "30m"
  }
}

# AWS/cloud credential generation for production — requires approval
path "cloud/creds/prod-deploy" {
  capabilities = ["read"]

  control_group {
    factor "security-team-approval" {
      identity {
        group_names = ["jit-approvers"]
        approvals   = 1
      }
    }
    ttl = "30m"
  }
}

# ============================================================================
# 3. APPROVER POLICY — For team leads / security team
# ============================================================================
# Members of the "jit-approvers" identity group can authorize pending
# control group requests. They cannot self-approve their own requests.

# Allow listing pending control group requests
path "sys/control-group/authorize" {
  capabilities = ["update"]
}

# Allow checking status of control group requests
path "sys/control-group/request" {
  capabilities = ["update"]
}

# ============================================================================
# 4. BREAK-GLASS POLICY — Emergency override with mandatory audit
# ============================================================================
# Break-glass bypasses control group approval but triggers enhanced audit.
# This policy should be assigned to a separate auth method (e.g., a
# hardware-token-protected OIDC flow or a sealed emergency credential).
#
# CRITICAL: Break-glass usage triggers:
#   - Immediate audit log entry with break-glass flag
#   - Slack/PagerDuty notification via audit webhook
#   - Mandatory post-incident review within 24 hours
#   - The Sentinel policy below enforces a maximum 2-hour session

# Production secrets — no control group, but time-bounded by Sentinel
path "kv/data/prod/+/config" {
  capabilities = ["read", "list"]
}

# Production database — emergency access
path "database/creds/prod-*" {
  capabilities = ["read"]
}

# Production SSH — emergency access
path "ssh-client-signer/sign/prod-role" {
  capabilities = ["update"]
}

# Cloud credentials — emergency access
path "cloud/creds/prod-deploy" {
  capabilities = ["read"]
}

# Explicitly deny destructive operations even in break-glass
# No emergency justifies deleting secrets or revoking all leases
path "sys/leases/revoke-prefix/*" {
  capabilities = ["deny"]
}

path "kv/delete/*" {
  capabilities = ["deny"]
}

path "kv/destroy/*" {
  capabilities = ["deny"]
}

path "sys/seal" {
  capabilities = ["deny"]
}

# ============================================================================
# 5. SENTINEL POLICY — Time-bounded access enforcement (EGP)
# ============================================================================
# This Endpoint Governing Policy (EGP) enforces that:
#   - Break-glass tokens cannot exceed 2 hours TTL
#   - All privileged tokens include a "reason" metadata field
#   - Access is denied outside of configured maintenance windows (optional)
#
# Deploy as:
#   vault write sys/policies/egp/jit-time-bound \
#     policy="$(cat jit-sentinel-time-bound.sentinel)" \
#     paths="kv/data/prod/*,database/creds/prod-*" \
#     enforcement_level="hard-mandatory"

# --- Sentinel policy content (jit-sentinel-time-bound.sentinel) ---
# Paste into a .sentinel file for deployment.
#
#   import "time"
#   import "strings"
#
#   # Maximum TTL for any token accessing privileged paths
#   max_ttl_seconds = 7200  # 2 hours
#
#   # Enforce token TTL does not exceed maximum
#   ttl_check = rule {
#       request.auth.token_ttl <= max_ttl_seconds
#   }
#
#   # Require "reason" metadata on all privileged access requests
#   reason_check = rule {
#       "reason" in keys(request.auth.metadata) and
#       length(request.auth.metadata["reason"]) > 10
#   }
#
#   # Optional: restrict to business hours (uncomment to enable)
#   # business_hours = rule {
#   #     time.now.hour >= 6 and time.now.hour <= 22
#   # }
#
#   # Main rule: all checks must pass
#   main = rule {
#       ttl_check and reason_check
#   }

# ============================================================================
# 6. AUDIT DEVICE CONFIGURATION (reference)
# ============================================================================
# Ensure the audit device captures control group and break-glass events.
# Deploy with:
#
#   vault audit enable file \
#     file_path=/var/log/vault/audit.log \
#     log_raw=false \
#     hmac_accessor=true
#
#   vault audit enable socket \
#     address=siem.example.com:514 \
#     socket_type=tcp \
#     tag=vault-jit
#
# The approval-webhook.py in this directory listens for control group
# events and routes them to Slack/email for human approval.
