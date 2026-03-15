# Bootstrap Scripts

Developer workstation and environment bootstrap automation.

## Scripts

| Script | Purpose |
|--------|---------|
| `bootstrap_dev.sh` | Complete developer workstation setup: tool validation, Vault auth, secret retrieval |
| `check_no_plaintext_secrets.sh` | Enhanced secret scanner with 15+ pattern types |
| `vault_login_oidc.sh` | Vault OIDC authentication with token validation and renewal |
| `fetch_dev_env.sh` | Retrieve development secrets from Vault to temporary files |
| `onboard_app.sh` | Automate application onboarding: Vault policy, K8s SA, secret delivery |

## Quick Start

```bash
# First time setup
./bootstrap/scripts/bootstrap_dev.sh

# Authenticate to Vault
export VAULT_ADDR=https://vault.example.internal
./bootstrap/scripts/vault_login_oidc.sh

# Fetch secrets for current project
./bootstrap/scripts/fetch_dev_env.sh my-app dev

# Onboard a new application
./bootstrap/scripts/onboard_app.sh my-api dev --delivery eso --cert --db-role
```

## Security Notes

- All temporary secrets are written with `0600` permissions
- Cleanup trap ensures secrets are deleted on shell exit
- No secrets are ever written to the repository directory
- The secret scanner supports `.secretsignore` for false positives
