# Incident Playbook: Break-Glass Emergency Access

## Purpose

This playbook documents the procedure for emergency administrative access when normal authentication paths are unavailable. It is designed for scenarios where the IdP, Vault, or cloud authentication services are down and critical infrastructure requires immediate access.

## When to Invoke

- IdP is completely unavailable and critical system access is needed
- Vault is sealed and cannot be unsealed through normal procedures
- Cloud IAM is experiencing an outage blocking all operational access
- A security incident requires immediate access to revoke compromised credentials
- Certificate authority is unreachable and emergency cert issuance is needed

## Prerequisites

Before this procedure can be invoked:
- [ ] Two authorized personnel must be present (dual-control)
- [ ] Both personnel must verify their identity to each other
- [ ] The decision to invoke break-glass must be documented
- [ ] The incident ticket or emergency declaration must be referenced

## Break-Glass Materials

### Storage Locations

| Material | Primary Location | Secondary Location | Access Method |
|----------|-----------------|-------------------|---------------|
| Vault unseal keys (Shamir) | Physical safe A | Physical safe B | 3-of-5 key holders |
| Cloud root account credentials | Secured vault | Offline backup | Dual-control access |
| SOPS age break-glass key | Hardware security key | Paper backup in safe | Physical access |
| SSH emergency key | Secured vault | Offline USB | Physical access |
| KMS break-glass access | IAM emergency role | Out-of-band access | Dual approval |

### Key Holders

| Role | Primary | Backup |
|------|---------|--------|
| Holder 1 | [Name — CTO/CISO] | [Backup name] |
| Holder 2 | [Name — Platform Lead] | [Backup name] |
| Holder 3 | [Name — Security Lead] | [Backup name] |
| Holder 4 | [Name — Senior Engineer] | [Backup name] |
| Holder 5 | [Name — Ops Lead] | [Backup name] |

## Procedure

### Step 1: Declare Emergency (5 minutes)

```
BREAK-GLASS DECLARATION
════════════════════════
Declared by:    [Name]
Witnessed by:   [Name]
Timestamp:      [ISO UTC]
Reason:         [Brief description of emergency]
Systems needed: [List of systems requiring access]
Incident ref:   [Ticket/incident ID]
Expected duration: [Estimated time needed]
```

### Step 2: Retrieve Materials (15 minutes)

1. Both authorized personnel physically retrieve break-glass materials
2. Each person brings their portion (no single person has complete access)
3. Materials are verified (hash check on digital materials, seal check on physical)

### Step 3: Establish Access (10 minutes)

#### Scenario A: Vault Unsealing

```bash
# Each key holder enters their unseal key (3 of 5 required)
vault operator unseal  # Key holder 1 enters key
vault operator unseal  # Key holder 2 enters key
vault operator unseal  # Key holder 3 enters key

# Verify seal status
vault status

# Log access
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] BREAK-GLASS: Vault unsealed by [names]" >> /var/log/break-glass.log
```

#### Scenario B: Cloud Root Access

```bash
# Use break-glass IAM credentials (from secured storage)
# These credentials should ONLY be used for emergency access

# AWS
aws configure --profile emergency
aws sts get-caller-identity --profile emergency

# Azure
az login  # Use break-glass service principal

# GCP
gcloud auth activate-service-account --key-file=/path/to/break-glass-key.json
```

#### Scenario C: SOPS Emergency Decryption

```bash
# Use age break-glass key (from physical storage)
export SOPS_AGE_KEY_FILE=/tmp/break-glass.age
sops decrypt secrets/prod/critical.enc.yaml > /tmp/critical.dec.yaml
chmod 0600 /tmp/critical.dec.yaml

# Use the decrypted values for emergency operations
# ...

# Clean up immediately after use
shred -u /tmp/critical.dec.yaml /tmp/break-glass.age
```

#### Scenario D: SSH Emergency Access

```bash
# Use emergency SSH key (from physical storage)
chmod 0600 /tmp/emergency-ssh-key
ssh -i /tmp/emergency-ssh-key admin@critical-server

# After operations complete
shred -u /tmp/emergency-ssh-key
```

### Step 4: Perform Emergency Operations (as needed)

- Execute only the minimum operations necessary
- Document every action taken
- Two-person verification for destructive operations
- Screenshot or log all changes

### Step 5: Secure and Rotate (immediately after)

```
POST-BREAK-GLASS CHECKLIST
═══════════════════════════
[ ] All break-glass credentials rotated
[ ] All temporary files securely deleted (shred)
[ ] All emergency sessions terminated
[ ] Break-glass materials returned to secure storage
[ ] New break-glass materials generated if consumed
[ ] Root/emergency tokens revoked
[ ] Audit logs preserved
```

#### Rotation Procedures

```bash
# Generate new Vault root token (to revoke later)
vault operator generate-root -init
# ... complete generation ceremony
vault token revoke <root-token>

# Rotate age break-glass key
age-keygen -o new-break-glass.age
# Re-encrypt all SOPS files with new recipient
./tools/rotate/rotate_sops_keys.sh --new-recipient $(grep "public key" new-break-glass.age | awk '{print $NF}')

# Rotate cloud root credentials
# [Follow cloud-specific rotation procedure]

# Generate new SSH emergency key
ssh-keygen -t ed25519 -f new-emergency-key -N ""
# Deploy to emergency authorized_keys
```

### Step 6: Document and Review (within 24 hours)

```
BREAK-GLASS INCIDENT REPORT
════════════════════════════
Incident ID:        [INC-YYYY-NNN]
Date/Time:          [Start] to [End]
Duration:           [HH:MM]
Declared by:        [Name]
Witnessed by:       [Name]
Reason:             [Why normal access was unavailable]

ACTIONS TAKEN
─────────────
[Timestamp] [Action] [By whom] [Result]
[Timestamp] [Action] [By whom] [Result]

MATERIALS USED
──────────────
[Material type] [Used/Not used] [Rotated: Yes/No]

ROOT CAUSE OF OUTAGE
────────────────────
[Why normal access failed]

PREVENTIVE MEASURES
───────────────────
[Steps to prevent recurrence]

ROTATION CONFIRMATION
─────────────────────
[All materials rotated: Yes/No]
[Rotation verified by: Name]
[Rotation timestamp: ISO UTC]
```

## Quarterly Drill Procedure

Break-glass procedures MUST be tested quarterly.

### Drill Checklist

- [ ] Schedule drill with all key holders (minimum 3 of 5)
- [ ] Use non-production environment
- [ ] Execute full procedure from declaration through rotation
- [ ] Time each phase
- [ ] Document any issues encountered
- [ ] Update procedure based on findings
- [ ] Rotate drill materials after test
- [ ] File drill report

### Drill Report Template

```
BREAK-GLASS DRILL REPORT
═════════════════════════
Date:           [ISO date]
Participants:   [Names]
Environment:    [Non-production environment used]
Result:         [PASS / FAIL]

TIMING
──────
Declaration:    [MM:SS]
Retrieval:      [MM:SS]
Access:         [MM:SS]
Operations:     [MM:SS]
Rotation:       [MM:SS]
Total:          [MM:SS]

ISSUES
──────
[Any issues encountered and resolutions]

IMPROVEMENTS
────────────
[Procedure updates needed]

NEXT DRILL
──────────
Scheduled: [Date]
```

## Audit Requirements

- All break-glass events (real and drills) must be logged
- Logs must be immutable (write-once storage)
- Logs must be retained for minimum 1 year
- Logs must include: who, what, when, why, result
- External auditors must have access to break-glass logs on request
