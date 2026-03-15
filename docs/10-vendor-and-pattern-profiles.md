# Vendor and Pattern Profiles

## Pattern A — Microsoft-heavy hybrid

Use when:
- Entra ID and Intune are already primary
- developer devices are mostly Windows/macOS under Intune
- internal VPN and endpoint certificate distribution are Microsoft-centric

Recommended stack:
- Entra ID
- Intune
- Microsoft Cloud PKI for Intune-managed devices, preferably in BYOCA mode if you want a unified private trust hierarchy
- Vault for dynamic credentials, SSH CA, Transit, and runtime brokering
- SOPS + Azure Key Vault / Managed HSM
- GitHub OIDC to Azure and/or Vault
- Kubernetes secret delivery via External Secrets / CSI as needed

## Pattern B — Multi-cloud platform team

Use when:
- workloads span AWS/Azure/GCP
- Kubernetes and VMs both matter
- the secret and credential model must stay portable

Recommended stack:
- Entra or Okta
- Vault
- SOPS + cloud-specific KMS by environment
- GitHub OIDC to target cloud and Vault
- cert-manager + Vault or enterprise CA
- Secrets Store CSI and External Secrets
- optional SPIFFE/SPIRE later for workload identity maturity

## Pattern C — Leaner implementation

Use when:
- the team is smaller
- dynamic secrets and SSH CA are not phase-one requirements
- the main need is encrypted Git, federated CI, and runtime secret retrieval

Recommended stack:
- IdP + MDM
- cloud secret manager
- cloud KMS / Key Vault / Cloud KMS
- SOPS
- GitHub OIDC
- External Secrets or CSI
- private CA provider for certificates

Note:
This is simpler operationally but weaker when you need dynamic database credentials, SSH CA, or crypto-as-a-service patterns.
