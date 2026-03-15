# Example PKI role.
# Use with:
# vault write pki_int/roles/dev-services @platform/vault/examples/pki-role.hcl

allowed_domains="dev.internal.example"
allow_subdomains=true
max_ttl="72h"
key_type="rsa"
key_bits=2048
server_flag=true
client_flag=true
