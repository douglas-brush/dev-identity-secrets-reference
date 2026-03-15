# Example payload for dynamic database role creation.
# Use with:
# vault write database/roles/dev-demo-app @platform/vault/examples/database-role.hcl

db_name="postgres-dev"
creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE demo TO \"{{name}}\";"
default_ttl="1h"
max_ttl="24h"
