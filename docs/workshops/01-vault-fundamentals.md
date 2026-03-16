# Workshop 01: Vault Fundamentals

**Duration:** 2 hours
**Level:** Introductory
**Audience:** All developers, DevOps engineers, security engineers

---

## Objectives

By the end of this workshop, participants will be able to:

1. Explain why static secrets are an organizational liability
2. Authenticate to Vault using three different methods (token, AppRole, OIDC)
3. Perform CRUD operations on KV v2 secrets with versioning
4. Generate dynamic database credentials that expire automatically
5. Use Vault Transit for encryption-as-a-service without managing keys

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Docker 24.0+ | `docker --version` |
| Docker Compose 2.20+ | `docker compose version` |
| curl | `curl --version` |
| jq 1.6+ | `jq --version` |
| Vault CLI (optional but recommended) | `vault version` |

If you do not have the Vault CLI installed, all labs provide equivalent `curl` commands.

---

## Environment Setup (15 minutes)

### Step 1: Clone and start the dev environment

```bash
git clone https://github.com/BrushCyber/dev-identity-secrets-reference.git
cd dev-identity-secrets-reference

# Start the stack
make dev-up

# Bootstrap Vault with engines, policies, AppRole, PKI, demo data
make dev-setup
```

### Step 2: Set environment variables

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
```

### Step 3: Verify connectivity

Using the Vault CLI:
```bash
vault status
```

Expected output (key fields):
```
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.15.x
Storage Type    inmem
```

Using curl:
```bash
curl -s $VAULT_ADDR/v1/sys/health | jq .
```

Expected output:
```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1234567890,
  "version": "1.15.x",
  "cluster_name": "vault-cluster-...",
  "cluster_id": "..."
}
```

### Step 4: Open the Vault UI (optional)

Open http://localhost:8200/ui in a browser. Sign in with token `dev-root-token`.

---

## Lab 1: Authentication Methods (25 minutes)

### Concept

Vault separates **authentication** (who are you?) from **authorization** (what can you do?). Authentication methods verify identity and return a token. That token carries policies that define access.

### 1.1 Token Authentication

The root token is pre-configured in dev mode. This is the simplest auth method -- and the most dangerous in production.

**Read a secret using the root token:**

```bash
# The root token is already set in VAULT_TOKEN
vault token lookup
```

Expected output includes:
```
Key                 Value
---                 -----
accessor            ...
creation_time       ...
display_name        token
entity_id           n/a
policies            [root]
```

**Create a limited token:**

```bash
vault token create \
  -policy=default \
  -ttl=1h \
  -display-name="workshop-token"
```

Expected output:
```
Key                  Value
---                  -----
token                hvs.CAESI...
token_accessor       ...
token_duration       1h
token_renewable      true
token_policies       ["default"]
```

**Use the limited token:**

```bash
# Save the token (copy the token value from above)
export WORKSHOP_TOKEN=hvs.CAESI...

# Try to list secrets with the limited token
VAULT_TOKEN=$WORKSHOP_TOKEN vault secrets list
```

Expected: Permission denied (the `default` policy cannot list secrets engines).

```bash
# Switch back to root
export VAULT_TOKEN=dev-root-token
```

**Verification:**
- [ ] `vault token lookup` shows `policies: [root]` for the root token
- [ ] The created token has `token_duration: 1h`
- [ ] The limited token gets "permission denied" on `vault secrets list`

### 1.2 AppRole Authentication

AppRole is machine-to-machine authentication. Applications authenticate using a `role_id` (identity) and `secret_id` (credential).

**Check that AppRole is enabled:**

```bash
vault auth list | grep approle
```

Expected:
```
approle/    approle    auth_approle_...    n/a
```

**Read the role configuration (set up by `make dev-setup`):**

```bash
vault read auth/approle/role/demo-app
```

**Get the role ID:**

```bash
vault read auth/approle/role/demo-app/role-id
```

Expected output:
```
Key        Value
---        -----
role_id    <uuid>
```

Save it:
```bash
ROLE_ID=$(vault read -field=role_id auth/approle/role/demo-app/role-id)
echo "Role ID: $ROLE_ID"
```

**Generate a secret ID:**

```bash
vault write -f auth/approle/role/demo-app/secret-id
```

Expected output:
```
Key                   Value
---                   -----
secret_id             <uuid>
secret_id_accessor    <uuid>
secret_id_num_uses    0
secret_id_ttl         0s
```

Save it:
```bash
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/demo-app/secret-id)
echo "Secret ID: $SECRET_ID"
```

**Authenticate with AppRole:**

```bash
vault write auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID"
```

Expected output:
```
Key                     Value
---                     -----
token                   hvs....
token_accessor          ...
token_duration          768h
token_renewable         true
token_policies          ["default", "demo-app"]
```

Using curl:
```bash
curl -s -X POST \
  $VAULT_ADDR/v1/auth/approle/login \
  -d "{\"role_id\": \"$ROLE_ID\", \"secret_id\": \"$SECRET_ID\"}" \
  | jq .
```

**Verification:**
- [ ] AppRole login returns a token with `demo-app` policy attached
- [ ] The token has a finite TTL (not root-level access)
- [ ] The curl and CLI commands return equivalent results

### 1.3 OIDC Authentication (Conceptual)

In production, developers authenticate via their identity provider (Entra ID, Okta, Google Workspace) using OIDC. The dev environment does not include a full IdP, so this section is conceptual with reference to production patterns.

**How OIDC works with Vault:**

1. Developer runs `vault login -method=oidc`
2. Vault redirects to the IdP login page in the browser
3. Developer authenticates with MFA
4. IdP returns a JWT to Vault's callback URL
5. Vault validates the JWT, maps claims to policies, returns a Vault token

**Production configuration reference:**

```bash
# These commands show how OIDC is configured (do NOT run in the dev environment)
# See: platform/vault/examples/setup-oidc-auth.sh

vault auth enable oidc

vault write auth/oidc/config \
  oidc_discovery_url="https://login.microsoftonline.com/<tenant>/v2.0" \
  oidc_client_id="<app-registration-client-id>" \
  oidc_client_secret="<app-registration-secret>" \
  default_role="developer"

vault write auth/oidc/role/developer \
  bound_audiences="<client-id>" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  user_claim="email" \
  groups_claim="groups" \
  policies="developer"
```

**Progression of trust:**

| Method | Trust Basis | Use Case | Risk Level |
|--------|------------|----------|------------|
| Token | Pre-shared secret | Dev/testing | High (static) |
| AppRole | Role + secret binding | Machine-to-machine | Medium (rotatable) |
| OIDC | Identity provider + MFA | Human developers | Low (federated) |

**Verification:**
- [ ] Participant can explain why OIDC is preferred over static tokens for human access
- [ ] Participant understands the claim-to-policy mapping concept

---

## Lab 2: KV v2 Secrets CRUD with Versioning (25 minutes)

### Concept

KV v2 (Key-Value version 2) is Vault's versioned secret engine. Every write creates a new version. Old versions are retained (configurable) and can be retrieved, soft-deleted, or permanently destroyed.

### 2.1 Write a Secret

```bash
vault kv put secret/workshop/myapp \
  api_key="sk-workshop-12345" \
  api_url="https://api.example.com" \
  environment="development"
```

Expected output:
```
====== Secret Path ======
secret/data/workshop/myapp

======= Metadata =======
Key                Value
---                -----
created_time       2024-...
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1
```

Using curl:
```bash
curl -s -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/secret/data/workshop/myapp \
  -d '{"data": {"api_key": "sk-workshop-12345", "api_url": "https://api.example.com", "environment": "development"}}' \
  | jq .
```

### 2.2 Read a Secret

```bash
vault kv get secret/workshop/myapp
```

Expected output:
```
====== Secret Path ======
secret/data/workshop/myapp

======= Metadata =======
Key                Value
---                -----
created_time       ...
version            1

====== Data ======
Key            Value
---            -----
api_key        sk-workshop-12345
api_url        https://api.example.com
environment    development
```

**Read as JSON (programmatic access):**

```bash
vault kv get -format=json secret/workshop/myapp | jq '.data.data'
```

Expected:
```json
{
  "api_key": "sk-workshop-12345",
  "api_url": "https://api.example.com",
  "environment": "development"
}
```

**Read a single field:**

```bash
vault kv get -field=api_key secret/workshop/myapp
```

Expected: `sk-workshop-12345`

### 2.3 Update a Secret (Create Version 2)

```bash
vault kv put secret/workshop/myapp \
  api_key="sk-workshop-67890-rotated" \
  api_url="https://api.example.com" \
  environment="development"
```

Note: `version` in the output is now `2`.

### 2.4 Read a Previous Version

```bash
vault kv get -version=1 secret/workshop/myapp
```

Expected: Returns version 1 with the original `api_key` value.

```bash
vault kv get -version=2 secret/workshop/myapp
```

Expected: Returns version 2 with the rotated `api_key` value.

### 2.5 Patch a Secret (Partial Update)

```bash
vault kv patch secret/workshop/myapp \
  environment="staging"
```

Expected: Creates version 3 with only `environment` changed. `api_key` and `api_url` retain their version 2 values.

**Verify:**

```bash
vault kv get -format=json secret/workshop/myapp | jq '.data.data'
```

Expected:
```json
{
  "api_key": "sk-workshop-67890-rotated",
  "api_url": "https://api.example.com",
  "environment": "staging"
}
```

### 2.6 View Secret Metadata

```bash
vault kv metadata get secret/workshop/myapp
```

Expected: Shows all versions with timestamps, max_versions setting, and delete_version_after.

### 2.7 Soft-Delete and Undelete

```bash
# Soft-delete version 1
vault kv delete -versions=1 secret/workshop/myapp

# Try to read version 1
vault kv get -version=1 secret/workshop/myapp
```

Expected: Version 1 shows `deletion_time` set and data is nil.

```bash
# Undelete version 1
vault kv undelete -versions=1 secret/workshop/myapp

# Read it again
vault kv get -version=1 secret/workshop/myapp
```

Expected: Version 1 data is restored.

### 2.8 Permanent Destroy

```bash
# Permanently destroy version 1 (IRREVERSIBLE)
vault kv destroy -versions=1 secret/workshop/myapp
```

Expected: Version 1 is permanently gone -- cannot be undeleted.

### 2.9 List Secrets

```bash
vault kv list secret/workshop/
```

Expected:
```
Keys
----
myapp
```

**Verification:**
- [ ] Created a secret with 3 fields
- [ ] Updated the secret and confirmed version number incremented
- [ ] Read a previous version by number
- [ ] Patched a single field without overwriting others
- [ ] Soft-deleted and undeleted a version
- [ ] Permanently destroyed a version

---

## Lab 3: Dynamic Database Credentials (25 minutes)

### Concept

Dynamic secrets are generated on-demand with a built-in TTL. When the TTL expires, Vault revokes the credential. No more shared database passwords. No more credentials that outlive the application.

### 3.1 Verify the Database Engine

The `make dev-setup` command configured a database secrets engine connected to the PostgreSQL container.

```bash
vault secrets list | grep database
```

Expected:
```
database/    database    ...    n/a
```

**Check the connection configuration:**

```bash
vault read database/config/demo-postgres
```

Expected output includes:
```
Key                                   Value
---                                   -----
connection_details                    map[connection_url:... username:postgres]
plugin_name                           postgresql-database-plugin
allowed_roles                         [demo-readonly, demo-readwrite]
```

### 3.2 Read the Role Configuration

```bash
vault read database/roles/demo-readonly
```

Expected output includes:
```
Key                      Value
---                      -----
creation_statements      [CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";]
default_ttl              1h
max_ttl                  24h
```

### 3.3 Generate Dynamic Credentials

```bash
vault read database/creds/demo-readonly
```

Expected output:
```
Key                Value
---                -----
lease_id           database/creds/demo-readonly/...
lease_duration     1h
lease_renewable    true
password           <generated-password>
username           v-token-demo-rea-...
```

**Save the credentials:**

```bash
DB_CREDS=$(vault read -format=json database/creds/demo-readonly)
DB_USER=$(echo $DB_CREDS | jq -r '.data.username')
DB_PASS=$(echo $DB_CREDS | jq -r '.data.password')
LEASE_ID=$(echo $DB_CREDS | jq -r '.lease_id')

echo "Username: $DB_USER"
echo "Password: $DB_PASS"
echo "Lease ID: $LEASE_ID"
```

### 3.4 Use the Credentials

```bash
# Connect to PostgreSQL with the dynamic credentials
docker exec dev-postgres psql -U "$DB_USER" -d demo -c "SELECT current_user, now();"
```

Expected: Shows the dynamic username and current timestamp.

```bash
# Verify it is read-only
docker exec dev-postgres psql -U "$DB_USER" -d demo \
  -c "CREATE TABLE test_fail (id int);" 2>&1
```

Expected: Permission denied (the role only has SELECT privileges).

Using curl:
```bash
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/database/creds/demo-readonly | jq .
```

### 3.5 List Active Leases

```bash
vault list sys/leases/lookup/database/creds/demo-readonly
```

Expected: Shows one or more lease IDs.

### 3.6 Revoke a Lease (Credential Rotation)

```bash
vault lease revoke "$LEASE_ID"
```

Expected: `All revocation operations queued successfully!`

**Verify revocation:**

```bash
# The credential should no longer work
docker exec dev-postgres psql -U "$DB_USER" -d demo \
  -c "SELECT 1;" 2>&1
```

Expected: Authentication failure (the user has been dropped from PostgreSQL).

### 3.7 Generate Read-Write Credentials

```bash
vault read database/creds/demo-readwrite
```

Expected: A credential with broader privileges (INSERT, UPDATE, DELETE in addition to SELECT).

**Verification:**
- [ ] Generated dynamic database credentials from Vault
- [ ] Connected to PostgreSQL with the dynamic credentials
- [ ] Confirmed the readonly role cannot create tables
- [ ] Revoked a lease and confirmed the credential stopped working
- [ ] Generated read-write credentials and observed the difference

---

## Lab 4: Transit Encryption as a Service (20 minutes)

### Concept

Vault Transit provides encryption-as-a-service. Applications send plaintext to Vault, receive ciphertext back. The encryption key never leaves Vault. This eliminates the need for applications to manage encryption keys.

### 4.1 Verify Transit is Enabled

```bash
vault secrets list | grep transit
```

Expected:
```
transit/    transit    ...    n/a
```

### 4.2 Create an Encryption Key

```bash
vault write -f transit/keys/workshop-key
```

Expected: `Success! Data written to: transit/keys/workshop-key`

**Read the key metadata:**

```bash
vault read transit/keys/workshop-key
```

Expected output includes:
```
Key                       Value
---                       -----
keys                      map[1:...]
latest_version            1
min_decryption_version    1
min_encryption_version    0
name                      workshop-key
type                      aes256-gcm96
```

Note: You see key metadata, but never the raw key material.

### 4.3 Encrypt Data

```bash
vault write transit/encrypt/workshop-key \
  plaintext=$(echo -n "my-secret-api-key-12345" | base64)
```

Expected output:
```
Key           Value
---           -----
ciphertext    vault:v1:...
key_version   1
```

**Save the ciphertext:**

```bash
CIPHERTEXT=$(vault write -field=ciphertext transit/encrypt/workshop-key \
  plaintext=$(echo -n "my-secret-api-key-12345" | base64))
echo "Ciphertext: $CIPHERTEXT"
```

Using curl:
```bash
curl -s -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/transit/encrypt/workshop-key \
  -d "{\"plaintext\": \"$(echo -n 'my-secret-api-key-12345' | base64)\"}" \
  | jq .
```

### 4.4 Decrypt Data

```bash
vault write transit/decrypt/workshop-key \
  ciphertext="$CIPHERTEXT"
```

Expected output:
```
Key          Value
---          -----
plaintext    bXktc2VjcmV0LWFwaS1rZXktMTIzNDU=
```

**Decode the plaintext:**

```bash
vault write -field=plaintext transit/decrypt/workshop-key \
  ciphertext="$CIPHERTEXT" | base64 -d
```

Expected: `my-secret-api-key-12345`

### 4.5 Key Rotation

```bash
# Rotate the encryption key
vault write -f transit/keys/workshop-key/rotate
```

**Verify the new key version:**

```bash
vault read transit/keys/workshop-key | grep latest_version
```

Expected: `latest_version    2`

**Encrypt with the new key version:**

```bash
NEW_CIPHERTEXT=$(vault write -field=ciphertext transit/encrypt/workshop-key \
  plaintext=$(echo -n "my-secret-api-key-12345" | base64))
echo "New ciphertext: $NEW_CIPHERTEXT"
```

Note: The ciphertext prefix is now `vault:v2:...` indicating key version 2.

**Old ciphertext still decrypts:**

```bash
vault write -field=plaintext transit/decrypt/workshop-key \
  ciphertext="$CIPHERTEXT" | base64 -d
```

Expected: `my-secret-api-key-12345` -- old data is still readable after key rotation.

### 4.6 Rewrap (Re-encrypt with Latest Key)

```bash
vault write transit/rewrap/workshop-key \
  ciphertext="$CIPHERTEXT"
```

Expected: Returns new ciphertext with `vault:v2:...` prefix. The old v1 ciphertext is replaced without ever exposing the plaintext to the client.

### 4.7 Batch Encryption

```bash
vault write transit/encrypt/workshop-key \
  batch_input='[
    {"plaintext": "'$(echo -n "record-1" | base64)'"},
    {"plaintext": "'$(echo -n "record-2" | base64)'"},
    {"plaintext": "'$(echo -n "record-3" | base64)'"}
  ]'
```

Expected: Returns a `batch_results` array with three ciphertext values.

**Verification:**
- [ ] Created a Transit encryption key
- [ ] Encrypted plaintext and received ciphertext (never saw the raw key)
- [ ] Decrypted ciphertext back to original plaintext
- [ ] Rotated the key and confirmed old ciphertext still decrypts
- [ ] Used rewrap to re-encrypt data with the latest key version
- [ ] Performed batch encryption

---

## Cleanup (5 minutes)

```bash
# Remove workshop secrets
vault kv metadata delete secret/workshop/myapp
vault delete transit/keys/workshop-key

# Or reset the entire environment
make dev-reset
```

---

## Review Questions

### Knowledge Check

1. **Why is the root token dangerous in production?**
   It has unlimited access with no TTL. If leaked, an attacker has full control of all secrets. In production, root tokens should be revoked after initial setup and generated only when needed via `vault operator generate-root`.

2. **What happens to a dynamic database credential when its lease expires?**
   Vault automatically revokes it -- the database user is dropped. The application must request new credentials before the TTL expires or use token/lease renewal.

3. **Why does Transit never expose the encryption key to the application?**
   This is the fundamental principle: the application never holds key material. If the application is compromised, the attacker gets ciphertext but not the key. Key management (rotation, access control, audit) stays centralized in Vault.

4. **What is the difference between soft-delete and destroy in KV v2?**
   Soft-delete marks a version as deleted but retains the data -- it can be undeleted. Destroy permanently removes the data for that version -- it cannot be recovered.

5. **In what order should an organization adopt these auth methods?**
   Start with tokens for initial setup and testing. Move to AppRole for machine-to-machine authentication. Implement OIDC for all human access as soon as the IdP integration is ready. Never use root tokens in production workflows.

### Discussion Topics

- How would you handle secret access for a microservice that scales to 50 replicas?
- What monitoring would you set up around dynamic database credential generation?
- How does Transit encryption compare to application-level encryption (e.g., using libsodium directly)?

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `vault: command not found` | Install Vault CLI or use the curl equivalents provided in each lab |
| `Error checking seal status: ... connection refused` | Vault container is not running. Run `make dev-up` |
| `permission denied` on secret operations | Ensure `VAULT_TOKEN=dev-root-token` is set |
| Dynamic DB creds fail to connect | Check `docker exec dev-postgres pg_isready` -- PostgreSQL may still be starting |
| Transit encrypt returns error | Verify the key exists: `vault read transit/keys/workshop-key` |
| `no handler for route` on database/* | The database engine may not be configured. Run `make dev-setup` |

---

## Next Steps

- **Workshop 02:** [Secrets in CI/CD](02-secrets-in-cicd.md) -- Apply these concepts to automated pipelines
- **Workshop 04:** [SDK Development](04-sdk-development.md) -- Use the Python/Go/TS SDKs to interact with Vault programmatically
- **Reference:** [Reference Architecture](../02-reference-architecture.md) for the full production design
