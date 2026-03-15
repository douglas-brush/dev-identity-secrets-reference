# Local Development Environment

Patterns for injecting secrets into your local development workflow without writing sensitive material to disk.

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| `vault` | Secret management CLI | [Install](https://developer.hashicorp.com/vault/install) |
| `sops` | Encrypted config files | [Install](https://github.com/getsops/sops/releases) |
| `age` | Encryption key management | [Install](https://github.com/FiloSottile/age/releases) |
| `jq` | JSON processing | [Install](https://stedolan.github.io/jq/download/) |
| `direnv` | Automatic env loading | [Install](https://direnv.net/docs/installation.html) |
| `yq` | YAML processing (optional) | [Install](https://github.com/mikefarah/yq/releases) |

## Quick Start

```bash
# 1. Generate an age key (one-time)
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt

# 2. Copy direnv template
cp platform/local-dev/envrc.example .envrc
direnv allow

# 3. Login to Vault (direnv will auto-detect on subsequent cd)
vault login -method=oidc
```

## Components

### direnv Setup (`envrc.example`)

The `.envrc` template provides automatic Vault-backed environment setup. When you `cd` into the project directory, direnv:

1. Checks for a valid Vault token; renews if expiring, OIDC-logins if missing
2. Fetches KV secrets from Vault and exports with `APP_` prefix
3. Acquires dynamic database credentials
4. Decrypts SOPS files into env vars via process substitution
5. Loads `.env` overrides if present

```bash
# Install
cp platform/local-dev/envrc.example .envrc
# Edit VAULT_ADDR and other defaults for your environment
vim .envrc
direnv allow
```

No secrets touch disk. The Vault token stays in `VAULT_TOKEN` (not `~/.vault-token`) and SOPS decryption pipes through `eval`.

### Environment Template (`env.template`)

Documents every variable the reference architecture uses, grouped by section. All sensitive values use `REPLACE_*` placeholders.

```bash
cp platform/local-dev/env.template .env
# Fill in non-secret values; leave Vault-managed fields commented out
```

### SOPS Environment Fetch (`sops-env-fetch.sh`)

Decrypts SOPS-encrypted YAML/JSON files to environment variables without writing decrypted content to disk.

```bash
# Load into current shell
eval "$(./platform/local-dev/sops-env-fetch.sh --file secrets.enc.yaml)"

# Load with prefix
eval "$(./platform/local-dev/sops-env-fetch.sh --file secrets.enc.yaml --prefix DB_)"

# Print for docker --env-file (no export keyword)
docker run --env-file <(./platform/local-dev/sops-env-fetch.sh --file secrets.enc.yaml --export) myimage
```

### Vault Dev Proxy (`vault-dev-proxy.sh`)

Runs a Vault agent that auto-renews tokens and templates secrets to a memory-backed filesystem (tmpfs on Linux, ramdisk on macOS).

```bash
# Start with defaults
./platform/local-dev/vault-dev-proxy.sh

# Custom Vault address and templates
./platform/local-dev/vault-dev-proxy.sh \
  --vault-addr https://vault.internal:8200 \
  --template-dir ./my-templates/

# Templated secrets appear in the ramdisk directory
source /tmp/vault-proxy-XXXXXX/secrets.env
```

Press `Ctrl+C` to stop. The ramdisk is unmounted and all secrets are wiped.

## SOPS Workflow for Local Encrypted Config

```bash
# Create a .sops.yaml in your project root
cat > .sops.yaml <<EOF
creation_rules:
  - path_regex: \.enc\.(yaml|json)$
    age: >-
      age1your_public_key_here
EOF

# Encrypt a config file
sops -e config.yaml > config.enc.yaml

# Edit encrypted file in-place (decrypts to $EDITOR, re-encrypts on save)
sops config.enc.yaml

# Decrypt to stdout (never to a file)
sops -d config.enc.yaml

# Rotate to a new key
sops updatekeys config.enc.yaml
```

## IDE Integration

### VS Code

Add to `.vscode/settings.json`:

```json
{
  "terminal.integrated.env.osx": {
    "VAULT_ADDR": "http://127.0.0.1:8200"
  },
  "terminal.integrated.env.linux": {
    "VAULT_ADDR": "http://127.0.0.1:8200"
  },
  "dotenv.enableAutocloaking": true,
  "files.exclude": {
    "**/.env": false,
    "**/*.enc.*": false
  }
}
```

Install the **direnv** extension (`mkhl.direnv`) to auto-load `.envrc` in the integrated terminal.

For SOPS files, install the **SOPS Edit** extension to transparently edit encrypted files.

### JetBrains (IntelliJ, GoLand, PyCharm, etc.)

1. **direnv plugin**: Install from Marketplace. It hooks into run configurations to source `.envrc`.

2. **EnvFile plugin**: Reference `.env` files in Run/Debug configurations:
   - Run > Edit Configurations > EnvFile tab
   - Add `.env` path
   - Check "Enable EnvFile"

3. **Terminal env**: Settings > Tools > Terminal > Environment Variables:
   - Add `VAULT_ADDR=http://127.0.0.1:8200`

4. For SOPS, use an External Tool:
   - Settings > Tools > External Tools
   - Program: `sops`
   - Arguments: `$FilePath$`

## Security Rules for Local Development

1. **No secrets on disk** — Use process substitution (`<()`) and `eval` to keep decrypted values in memory only.
2. **Auto-expiring tokens** — Vault tokens should have a short TTL (1h). The direnv template and Vault proxy handle renewal automatically.
3. **Dynamic credentials** — Use Vault database/AWS/cloud engines for short-lived, unique-per-developer credentials.
4. **git-ignored files** — `.env`, `.envrc`, `*.dec.*` must be in `.gitignore`. Only encrypted (`*.enc.*`) files are committed.
5. **No shared secrets** — Each developer authenticates independently via OIDC. No shared service accounts for local dev.
6. **Ramdisk for templates** — When using Vault agent templates, `vault-dev-proxy.sh` writes to a memory-backed filesystem that is wiped on exit.
7. **Audit trail** — Vault logs every secret access with the developer's identity. Dynamic credentials are traceable per-developer.
