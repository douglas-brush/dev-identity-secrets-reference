# Example SSH signing role.
# Use with:
# vault write ssh/roles/dev-admin @platform/vault/examples/ssh-role.hcl

key_type="ca"
allow_user_certificates=true
allowed_users="ubuntu,ec2-user,admin"
default_extensions='{"permit-pty": ""}'
ttl="30m"
max_ttl="4h"
