# VM Onboarding Guide

How to deliver secrets to virtual machines using Vault Agent.

## Architecture

Vault Agent runs as a systemd service on the VM, authenticating via AppRole and rendering secrets to local files. Applications read secrets from `/run/app/` (tmpfs, never written to disk).

```
VM
├── /etc/vault-agent/
│   ├── vault-agent.hcl      # Agent configuration
│   ├── vault-env             # VAULT_ADDR and environment
│   ├── role-id               # AppRole role ID (provisioned)
│   ├── secret-id             # AppRole secret ID (one-time use)
│   └── templates/
│       ├── app-secrets.ctmpl # Application config template
│       └── db-creds.ctmpl    # Database credentials template
├── /run/vault/
│   └── .vault-token          # Auto-auth token (tmpfs)
└── /run/app/
    ├── secrets.env           # Rendered application secrets
    └── db.env                # Rendered database credentials
```

## Deployment Options

### Option 1: Cloud-Init (Recommended for new VMs)

Use `cloud-init-vault-agent.yaml` as your cloud-init user data. It installs Vault, creates the vault user, writes configuration files, and sets up the systemd service.

```bash
# AWS
aws ec2 run-instances \
  --user-data file://cloud-init-vault-agent.yaml \
  ...

# GCP
gcloud compute instances create my-vm \
  --metadata-from-file user-data=cloud-init-vault-agent.yaml \
  ...
```

### Option 2: Manual Installation

1. Install Vault CLI on the VM
2. Copy the systemd service file to `/etc/systemd/system/`
3. Create the Vault Agent configuration at `/etc/vault-agent/vault-agent.hcl`
4. Provision AppRole credentials (see below)
5. Enable and start the service

```bash
systemctl daemon-reload
systemctl enable vault-agent
systemctl start vault-agent
```

## AppRole Credential Provisioning

The VM needs a `role-id` and `secret-id` to authenticate. The secret-id is consumed on first use and never stored.

### Secure Provisioning Approaches

1. **Terraform provisioner**: Deliver role-id in AMI, secret-id via remote-exec
2. **Cloud metadata**: Store role-id in instance tags, secret-id in metadata
3. **Configuration management**: Ansible/Chef/Puppet delivers credentials at boot
4. **Instance identity**: Use AWS IAM, GCP GCE, or Azure MSI auth instead of AppRole

```bash
# Generate AppRole credentials (run from admin workstation)
ROLE_ID=$(vault read -field=role_id auth/approle/role/my-app/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/my-app/secret-id)

# Deliver to VM securely (example with SSH)
ssh admin@vm "echo '$ROLE_ID' | sudo tee /etc/vault-agent/role-id && sudo chmod 0400 /etc/vault-agent/role-id"
ssh admin@vm "echo '$SECRET_ID' | sudo tee /etc/vault-agent/secret-id && sudo chmod 0400 /etc/vault-agent/secret-id"
```

## Monitoring

```bash
# Check service status
systemctl status vault-agent

# View logs
journalctl -u vault-agent -f

# Verify rendered secrets exist
ls -la /run/app/

# Check token validity
VAULT_TOKEN=$(cat /run/vault/.vault-token) vault token lookup
```

## Security Notes

- Secret-id is removed after first read (`remove_secret_id_file_after_reading = true`)
- Rendered secrets use `0600` permissions, owned by the vault user
- Secrets are written to `/run/` (tmpfs) and never touch persistent disk
- The systemd service uses extensive hardening (NoNewPrivileges, ProtectSystem, etc.)
- Vault Agent auto-renews tokens and re-renders templates on secret rotation
