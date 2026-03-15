# Just-in-Time (JIT) Access Patterns

## Why Static Privileged Access Is the #1 Identity Risk

Standing privileged access -- admin accounts, long-lived service credentials, persistent
role memberships -- is the single largest attack surface in most organizations. The pattern
creates compounding risk:

- **Lateral movement enabler.** Compromised standing admin creds give attackers immediate
  access to high-value targets without needing to escalate.
- **Blast radius amplifier.** A single compromised privileged account can reach every system
  the role covers, 24/7, not just during the window it was needed.
- **Audit blind spot.** When access is always-on, distinguishing legitimate admin activity
  from attacker activity requires behavioral analytics rather than simple access logs.
- **Credential sprawl.** Teams create "just in case" service accounts and admin aliases that
  outlive projects, people, and even entire teams.
- **Compliance friction.** SOC 2 CC6.1/CC6.3, NIST 800-53 AC-2/AC-6, PCI-DSS 7.2, and
  ISO 27001 A.9.2.3 all require least-privilege enforcement -- standing admin violates all.

JIT access eliminates the standing privilege window entirely: access is granted only when
needed, only for the duration needed, and is automatically revoked when the task is complete.

## JIT vs. Standing Access

| Dimension             | Standing Access                  | JIT Access                              |
|-----------------------|----------------------------------|-----------------------------------------|
| Default state         | Always-on                        | No access until requested               |
| Credential lifetime   | Long-lived (months/years)        | Minutes to hours                        |
| Blast radius          | Full scope, 24/7                 | Scoped to task, time-bounded            |
| Audit signal          | High noise, low signal           | Every access event is a signal          |
| Attacker utility      | Immediate lateral movement       | Must wait for or trigger elevation      |
| Compliance posture    | Requires compensating controls   | Native least-privilege                  |
| Operational cost      | Low (set and forget)             | Moderate (requires workflow investment) |
| Recovery after breach | Rotate everything                | Credentials already expired             |

## Decision Tree: Which JIT Pattern to Use

```
Is the access for a human or a machine identity?
|
+-- HUMAN
|   |
|   +-- Is the target a cloud management plane (AWS/Azure/GCP console/API)?
|   |   |
|   |   +-- YES --> Use cloud-native JIT:
|   |   |           AWS: STS AssumeRole with session tags
|   |   |           Azure: PIM role activation
|   |   |           GCP: IAM Conditions with time-bound bindings
|   |   |
|   |   +-- NO --> Is the target a Vault-managed resource (DB, PKI, SSH)?
|   |       |
|   |       +-- YES --> Use Vault control groups + request-elevation workflow
|   |       |
|   |       +-- NO --> Use Vault as broker: wrap the target system's
|   |                   native credential API behind Vault dynamic secrets
|   |
+-- MACHINE (CI/CD, service, cron)
    |
    +-- Is the workload in CI/CD?
    |   |
    |   +-- YES --> OIDC federation (GitHub Actions, GitLab CI, etc.)
    |   |           to cloud provider or Vault -- no stored credentials
    |   |
    |   +-- NO --> Is the workload on Kubernetes?
    |       |
    |       +-- YES --> Vault Agent / CSI driver with short-lived leases
    |       |
    |       +-- NO --> Vault AppRole with wrapped SecretID (single-use)
    |                   + automatic lease renewal
```

## Integration Points

### Vault as Universal Access Broker

Vault sits at the center of the JIT model. Every elevation request flows through it:

1. **Authentication** -- Human via OIDC, machine via AppRole/Kubernetes auth
2. **Authorization** -- Policies + Sentinel rules enforce scope, time, and approval
3. **Credential generation** -- Dynamic secrets (DB, cloud, SSH, PKI)
4. **Audit** -- Every operation logged with identity, timestamp, and lease metadata

### Cloud IAM Integration

| Cloud    | JIT Mechanism         | Vault Integration                    | Script                          |
|----------|-----------------------|--------------------------------------|---------------------------------|
| AWS      | STS AssumeRole        | AWS secrets engine                   | `cloud-jit/aws-sts-elevation.sh`    |
| Azure    | PIM role activation   | Azure secrets engine                 | `cloud-jit/azure-pim-activation.sh` |
| GCP      | IAM Conditions        | GCP secrets engine                   | `cloud-jit/gcp-iam-binding.sh`      |

### CI/CD Integration

JIT in CI/CD pipelines eliminates stored cloud credentials entirely:

```yaml
# GitHub Actions example -- OIDC federation to Vault
- uses: hashicorp/vault-action@v3
  with:
    url: ${{ secrets.VAULT_ADDR }}
    method: jwt
    role: ci-deploy
    jwtGithubAudience: vault.example.com
    secrets: |
      cloud/creds/deploy-role access_key | AWS_ACCESS_KEY_ID ;
      cloud/creds/deploy-role secret_key | AWS_SECRET_ACCESS_KEY ;
      cloud/creds/deploy-role security_token | AWS_SESSION_TOKEN
```

Credentials are generated per-run, scoped to the deployment role, and expire with the
Vault lease (typically 15-60 minutes).

## Files in This Directory

| File                              | Purpose                                           |
|-----------------------------------|---------------------------------------------------|
| `vault-jit-policy.hcl`           | Vault policy with control groups and break-glass   |
| `request-elevation.sh`           | CLI tool to request temporary elevated access      |
| `approval-webhook.py`            | Webhook endpoint for control group approvals       |
| `cloud-jit/aws-sts-elevation.sh` | AWS STS temporary role assumption                  |
| `cloud-jit/azure-pim-activation.sh` | Azure PIM role activation via az CLI            |
| `cloud-jit/gcp-iam-binding.sh`   | GCP time-bounded IAM binding                      |
