# 17. Just-in-Time Access Patterns

## Overview

Just-in-time (JIT) access eliminates standing privileged access by granting
credentials only when needed, only for the duration needed, with mandatory
audit and automatic revocation. This document covers architecture patterns
for implementing JIT without expensive commercial PAM products.

## The Problem with Standing Privilege

Every standing privileged account is a pre-positioned attack path. The risk
compounds along three dimensions:

1. **Time exposure.** A standing admin account is exploitable 24/7. JIT reduces
   the window to minutes or hours per use.
2. **Scope creep.** Admin accounts accumulate permissions over time. JIT forces
   explicit scope declaration on every request.
3. **Audit noise.** When an account is always active, all its activity looks
   "normal." JIT makes every privileged action a distinct, auditable event.

Traditional PAM products (CyberArk, BeyondTrust, Delinea) solve this but at
$50-150+/user/month with 6-12 month implementation timelines. The patterns
below achieve equivalent security outcomes using Vault and cloud-native tools.

## Architecture: Vault as Universal Access Broker

```
┌──────────────────────────────────────────────────────────────┐
│                        REQUESTER                             │
│   (human via CLI/UI, CI/CD pipeline, service account)        │
└──────────────┬───────────────────────────────────────────────┘
               │
               │  1. Authenticate (OIDC / AppRole / K8s)
               │  2. Request elevated access (scope + reason + duration)
               ▼
┌──────────────────────────────────────────────────────────────┐
│                     VAULT (Access Broker)                     │
│                                                              │
│  ┌─────────────┐  ┌───────────────┐  ┌───────────────────┐  │
│  │ Auth Methods │  │ Control Groups│  │ Sentinel Policies │  │
│  │ (OIDC,      │  │ (approval     │  │ (time bounds,     │  │
│  │  AppRole,   │  │  workflow)    │  │  reason required, │  │
│  │  K8s auth)  │  │              │  │  scope limits)    │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────────┘  │
│         │                │                   │               │
│         ▼                ▼                   ▼               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Dynamic Secrets Engines                    │  │
│  │  ┌────────┐ ┌────────┐ ┌───────┐ ┌──────┐ ┌────────┐ │  │
│  │  │Database│ │  AWS   │ │ Azure │ │ GCP  │ │SSH/PKI │ │  │
│  │  │Creds   │ │STS     │ │Creds  │ │Creds │ │Certs   │ │  │
│  │  └────────┘ └────────┘ └───────┘ └──────┘ └────────┘ │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Audit Log (every operation)                │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
               │
               │  3. Time-bounded credentials issued
               │  4. Auto-revoke on expiry
               ▼
┌──────────────────────────────────────────────────────────────┐
│                    TARGET SYSTEMS                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │PostgreSQL│ │ AWS IAM  │ │ Azure AD │ │ GCP IAM       │  │
│  │ MySQL    │ │ Console  │ │ Entra ID │ │ Cloud Console │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Approval Workflows

### Standard Flow (Control Groups)

```
Requester                  Vault                    Approver
    │                        │                         │
    │── Request access ──────►│                         │
    │                        │── Block token ──────────►│
    │                        │   (send notification)    │
    │   (waiting...)         │                         │
    │                        │◄─── Authorize ──────────│
    │◄── Unwrap token ───────│                         │
    │                        │                         │
    │── Use credentials ─────►│                         │
    │                        │── Generate dynamic ──►  │
    │◄── Time-bounded creds ─│   secret                │
    │                        │                         │
    │   ... duration expires ...                       │
    │                        │── Auto-revoke ──►       │
```

### Break-Glass Flow

```
Requester                  Vault                    SIEM / Ops
    │                        │                         │
    │── Break-glass req ─────►│                         │
    │   (special auth)       │── ALERT: break-glass ──►│
    │                        │   (immediate audit)     │
    │◄── Immediate creds ────│                         │
    │   (max 2h TTL)         │                         │
    │                        │                         │
    │   ... within 24h ...   │                         │
    │◄── Post-incident ──────│──────────────────────────│
    │    review required     │                         │
```

## Cloud-Native JIT Patterns

### AWS: STS AssumeRole

AWS STS is the most mature cloud-native JIT mechanism. Key properties:

- **Credential lifetime:** 15 minutes to 12 hours (configurable per role)
- **Session tags:** Attach audit metadata (reason, ticket) to the session
- **Condition keys:** Restrict what the assumed role can do via IAM policy conditions
- **External ID:** Prevent confused deputy attacks in cross-account scenarios
- **MFA enforcement:** Require MFA token for sensitive role assumptions

Best practices:
- Set `MaxSessionDuration` on IAM roles to the minimum needed (default 1h)
- Use session tags to pass reason and requester identity into CloudTrail
- Combine with AWS Organizations SCPs to prevent permanent IAM user creation
- Use `aws:TokenIssueTime` condition to enforce freshness

See: `examples/jit-access/cloud-jit/aws-sts-elevation.sh`

### Azure: Privileged Identity Management (PIM)

Azure PIM converts permanent role assignments to "eligible" assignments that
must be activated on demand. Available in Azure AD P2 (included in E5).

- **Activation duration:** Configurable per role (30 min to 24 hours)
- **Approval workflow:** Built-in approval chain with email/Teams notifications
- **Justification required:** Free-text reason stored in audit log
- **Ticket integration:** Link to ServiceNow/JIRA ticket numbers
- **MFA on activation:** Enforce re-authentication at activation time

Best practices:
- Convert all permanent Owner/Contributor assignments to eligible
- Set maximum activation duration to 4 hours for most roles
- Require approval for Global Admin and Privileged Role Administrator
- Enable access reviews on a quarterly cadence
- Use Conditional Access to restrict PIM activation to compliant devices

See: `examples/jit-access/cloud-jit/azure-pim-activation.sh`

### GCP: IAM Conditions

GCP IAM Conditions allow time-bounded and attribute-based access control on
IAM policy bindings. The condition is evaluated server-side on every API call.

- **Time condition:** `request.time < timestamp("2024-01-01T00:00:00Z")`
- **Resource condition:** Restrict to specific resources within a project
- **IP condition:** Combine time bounds with source IP restrictions
- **Server-side enforcement:** Access denied after expiry even if binding persists

Best practices:
- Always use IAM Conditions for JIT rather than adding/removing bindings
- Include a descriptive `title` on conditions for audit trail
- Implement periodic cleanup of expired condition bindings
- Combine with VPC Service Controls for defense in depth
- Use Asset Inventory to detect bindings without conditions

See: `examples/jit-access/cloud-jit/gcp-iam-binding.sh`

## Comparison: PAM Approaches

| Approach                    | Cost               | Setup Time | Credential Types      | Approval Workflow | Audit Quality | Break-Glass |
|-----------------------------|--------------------|-----------|-----------------------|-------------------|---------------|-------------|
| Commercial PAM (CyberArk)  | $50-150/user/mo    | 6-12 months| All                   | Built-in          | Excellent     | Built-in    |
| Vault + Control Groups      | Vault license      | 2-4 weeks | All (via engines)     | Control groups    | Excellent     | Policy-based|
| AWS STS only               | Free (AWS costs)   | Days      | AWS IAM only          | Manual/custom     | CloudTrail    | N/A         |
| Azure PIM only             | E5/P2 license      | Days      | Azure RBAC only       | Built-in          | Azure AD logs | Built-in    |
| GCP IAM Conditions only    | Free (GCP costs)   | Days      | GCP IAM only          | Manual/custom     | Cloud Audit   | N/A         |
| Vault + Cloud-native combo | Vault + cloud costs| 2-4 weeks | All clouds + infra    | Flexible          | Unified       | Flexible    |

**Recommended approach:** Vault as the universal broker with cloud-native JIT
as the backend. This gives unified audit, consistent approval workflows, and
coverage across all credential types from a single control plane.

## Integration with Ticketing Systems

JIT requests should tie back to change management or incident records:

```
┌─────────────┐     ┌────────────┐     ┌──────────────┐
│ JIRA / SNOW │────►│ Webhook    │────►│ Vault        │
│ Ticket      │     │ (approve)  │     │ Control Group│
│ approved    │     │            │     │ authorize    │
└─────────────┘     └────────────┘     └──────────────┘
```

Implementation options:

1. **Manual reference:** Requester includes ticket number in `--reason` flag.
   Audit log captures the reference for post-hoc correlation.

2. **Webhook integration:** Approval webhook queries the ticketing API to
   verify the ticket exists, is in the correct state, and is assigned to
   the requester before authorizing the control group.

3. **Bidirectional sync:** On approval, the webhook updates the ticket with
   the granted access scope, duration, and Vault accessor for full traceability.

## Audit Trail Requirements

Every JIT access event must capture:

| Field            | Source                      | Retention |
|------------------|-----------------------------|-----------|
| Requester ID     | Vault auth identity         | 1 year+   |
| Timestamp        | Vault audit log             | 1 year+   |
| Reason/ticket    | Request metadata            | 1 year+   |
| Scope granted    | Vault policy path           | 1 year+   |
| Duration         | Token/lease TTL             | 1 year+   |
| Approver ID      | Control group authorization | 1 year+   |
| Credential type  | Secrets engine              | 1 year+   |
| Source IP        | Vault audit log             | 1 year+   |
| Break-glass flag | Token metadata              | 1 year+   |
| Revocation time  | Lease expiry / manual revoke| 1 year+   |

Forward audit events to SIEM via:
- Vault audit device (file, syslog, socket)
- Cloud-native audit logs (CloudTrail, Azure AD, Cloud Audit)
- The approval webhook audit log (`/var/log/jit-approvals.json`)

## Compliance Mapping

| Control                       | JIT Implementation                              |
|-------------------------------|-------------------------------------------------|
| SOC 2 CC6.1 (Logical access) | Vault policies + control groups                 |
| SOC 2 CC6.3 (Role-based)     | Scope-limited dynamic credentials               |
| NIST AC-2 (Account mgmt)     | Auto-provisioned/deprovisioned credentials      |
| NIST AC-6 (Least privilege)  | Time-bounded, scope-limited access              |
| PCI-DSS 7.2 (Access control) | Approval workflow + audit trail                 |
| PCI-DSS 10.2 (Audit trails)  | Vault audit log + SIEM forwarding               |
| ISO 27001 A.9.2.3            | Privileged access management via JIT            |
| ISO 27001 A.9.4.1            | Access limited to what is needed, when needed   |
| CIS Controls 6.8             | Centralized access logging                      |

## Implementation Files

| File                                              | Purpose                                    |
|---------------------------------------------------|--------------------------------------------|
| `examples/jit-access/README.md`                   | Overview and decision tree                 |
| `examples/jit-access/vault-jit-policy.hcl`        | Vault policies with control groups         |
| `examples/jit-access/request-elevation.sh`         | CLI for requesting elevated access         |
| `examples/jit-access/approval-webhook.py`          | Webhook for control group approvals        |
| `examples/jit-access/cloud-jit/aws-sts-elevation.sh`   | AWS STS temporary credentials         |
| `examples/jit-access/cloud-jit/azure-pim-activation.sh` | Azure PIM role activation             |
| `examples/jit-access/cloud-jit/gcp-iam-binding.sh`      | GCP time-bounded IAM binding          |
