# User Stories

## Identity and access

- As a developer, I can sign in to my tooling using organizational SSO and do not need a personal long-lived cloud key.
- As a security lead, I can revoke a developer's access centrally without tracking down copied credentials.
- As a platform engineer, I can require managed-device posture for access to high-value environments.
- As an administrator, I can obtain short-lived SSH access without relying on a shared private key.

## Repository and configuration

- As an engineer, I can keep structured config in Git while ensuring secrets stay encrypted with SOPS.
- As a reviewer, I can block merges that contain plaintext secrets.
- As a platform owner, I can rotate repository master keys without breaking all teams.

## CI/CD

- As a build system, I can authenticate to cloud and Vault using OIDC federation instead of stored secrets.
- As a security lead, I can restrict CI access by repository, branch, environment, and workflow.
- As a release engineer, I can run deployments without maintaining static tokens.

## Runtime workloads

- As an application, I can receive secrets from a central secret store without hardcoding credentials.
- As an application, I can receive a certificate and private key under lifecycle control.
- As a platform operator, I can choose secret delivery by use case: external sync, volume mount, or sidecar/agent.
- As a platform owner, I can enforce one service account per app and one role per trust boundary.

## VMs and administrative operations

- As an operator, I can bootstrap a VM without embedding secrets in the image.
- As an operator, I can use short-lived credentials to reach databases and services during maintenance.
- As a business, we can recover administrative access during an outage through a tested break-glass path.

## Governance and resilience

- As a security lead, I can see who requested what credential, when, and from where.
- As a risk owner, I can separate dev, stage, and prod trust domains.
- As a business, we can rotate or revoke central credentials without a major outage.
