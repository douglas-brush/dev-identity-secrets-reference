// Jenkins Shared Library: Vault integration utilities
//
// Place this file in your shared library repo at:
//   vars/vault.groovy
//
// Then reference in Jenkinsfile:
//   @Library('vault-shared-library') _
//
//   pipeline {
//     stages {
//       stage('Deploy') {
//         steps {
//           script {
//             def token = vault.auth()
//             def dbCreds = vault.dynamicCreds('test-readonly')
//             vault.withSecrets(['kv/data/myapp/config', 'kv/data/myapp/api']) { secrets ->
//               sh "echo DB_HOST=${secrets['DB_HOST']}"
//             }
//           }
//         }
//       }
//     }
//   }
//
// All methods respect VAULT_ADDR and VAULT_NAMESPACE environment variables.
// Tokens are short-lived and revoked after use.

// ---------------------------------------------------------------------------
// vaultAuth() — Authenticate to Vault and return a token string.
//
// Tries OIDC first (zero static secrets), falls back to AppRole.
//
// Parameters:
//   role     — Vault auth role name (default: from VAULT_ROLE env)
//   authPath — JWT auth mount path (default: 'jwt/jenkins')
//
// Returns: String — the Vault client token
// ---------------------------------------------------------------------------
def auth(Map opts = [:]) {
    def role = opts.get('role', env.VAULT_ROLE ?: 'REPLACE_VAULT_ROLE')
    def authPath = opts.get('authPath', env.VAULT_AUTH_PATH ?: 'jwt/jenkins')
    def vaultAddr = env.VAULT_ADDR ?: error("VAULT_ADDR environment variable is required")

    def token = null

    // ── OIDC authentication (preferred) ────────────────────────────────────
    // Jenkins OIDC Provider plugin generates a JWT signed by Jenkins' own key.
    // Vault validates the JWT against Jenkins' JWKS endpoint:
    //   vault write auth/jwt/jenkins/config \
    //     jwks_url="https://jenkins.example.com/oidc/jwks" \
    //     bound_issuer="https://jenkins.example.com"
    try {
        echo "[vault] Attempting OIDC authentication (role: ${role})..."
        def jwt = getOidcToken()
        if (jwt) {
            def response = sh(
                script: """
                    set -euo pipefail
                    vault write -format=json \
                        "auth/${authPath}/login" \
                        role="${role}" \
                        jwt="\$(cat /tmp/.vault-jwt)"
                """,
                returnStdout: true
            ).trim()
            // Write JWT to temp file to avoid shell escaping issues with long tokens
            writeFile file: '/tmp/.vault-jwt', text: jwt

            response = sh(
                script: """
                    set -euo pipefail
                    vault write -format=json \
                        "auth/${authPath}/login" \
                        role="${role}" \
                        jwt="\$(cat /tmp/.vault-jwt)"
                """,
                returnStdout: true
            ).trim()

            token = extractToken(response)
            sh 'rm -f /tmp/.vault-jwt'
            echo "[vault] OIDC authentication successful."
        }
    } catch (Exception e) {
        echo "[vault] OIDC not available: ${e.message}. Falling back to AppRole."
    }

    // ── AppRole authentication (fallback) ──────────────────────────────────
    // AppRole uses a role_id (non-secret) + secret_id (short-lived, rotated).
    // The secret_id should be a Jenkins credential that is rotated regularly
    // (e.g., via a cron job that calls vault write -f auth/approle/role/ROLE/secret-id).
    if (!token) {
        echo "[vault] Attempting AppRole authentication..."
        withCredentials([
            string(credentialsId: 'vault-approle-role-id', variable: 'ROLE_ID'),
            string(credentialsId: 'vault-approle-secret-id', variable: 'SECRET_ID')
        ]) {
            def response = sh(
                script: '''
                    set -euo pipefail
                    vault write -format=json \
                        auth/approle/login \
                        role_id="${ROLE_ID}" \
                        secret_id="${SECRET_ID}"
                ''',
                returnStdout: true
            ).trim()
            token = extractToken(response)
            echo "[vault] AppRole authentication successful."
        }
    }

    if (!token || token == 'null') {
        error("[vault] Authentication failed — neither OIDC nor AppRole succeeded.")
    }

    // Validate and log token metadata (never log the token itself)
    withEnv(["VAULT_TOKEN=${token}"]) {
        sh '''
            set -euo pipefail
            TOKEN_INFO=$(vault token lookup -format=json)
            TTL=$(echo "${TOKEN_INFO}" | jq -r '.data.ttl')
            POLICIES=$(echo "${TOKEN_INFO}" | jq -r '.data.policies | join(", ")')
            echo "[vault] Token acquired — TTL: ${TTL}s, policies: ${POLICIES}"
        '''
    }

    return token
}

// ---------------------------------------------------------------------------
// vaultRead(path) — Read a secret from Vault KV v2.
//
// Parameters:
//   path  — Full KV path (e.g. 'kv/data/myapp/config')
//   token — Vault token (optional, uses VAULT_TOKEN env if not provided)
//   field — Specific field to return (optional, returns all if omitted)
//
// Returns: Map<String, String> of key-value pairs, or String if field specified
// ---------------------------------------------------------------------------
def read(String path, Map opts = [:]) {
    def token = opts.get('token', env.VAULT_TOKEN)
    def field = opts.get('field', null)

    if (!token) {
        error("[vault] No Vault token available. Call vault.auth() first.")
    }

    def result
    withEnv(["VAULT_TOKEN=${token}"]) {
        if (field) {
            // Return a single field value
            result = sh(
                script: """
                    set -euo pipefail
                    vault kv get -field="${field}" "${path}"
                """,
                returnStdout: true
            ).trim()
        } else {
            // Return all fields as JSON, then parse
            def json = sh(
                script: """
                    set -euo pipefail
                    vault kv get -format=json "${path}" | jq -r '.data.data'
                """,
                returnStdout: true
            ).trim()
            result = readJSON(text: json)
        }
    }

    return result
}

// ---------------------------------------------------------------------------
// vaultDynamicCreds(role) — Request dynamic database credentials.
//
// Vault generates a unique username/password with an automatic TTL.
// Credentials are revoked when the lease expires or when explicitly revoked.
//
// Parameters:
//   role     — Database role name (e.g. 'test-readonly')
//   token    — Vault token (optional)
//   backend  — Database secrets engine mount (default: 'database')
//
// Returns: Map with keys: username, password, lease_id, lease_duration
// ---------------------------------------------------------------------------
def dynamicCreds(String role, Map opts = [:]) {
    def token = opts.get('token', env.VAULT_TOKEN)
    def backend = opts.get('backend', 'database')

    if (!token) {
        error("[vault] No Vault token available. Call vault.auth() first.")
    }

    def creds = [:]
    withEnv(["VAULT_TOKEN=${token}"]) {
        def json = sh(
            script: """
                set -euo pipefail
                vault read -format=json "${backend}/creds/${role}"
            """,
            returnStdout: true
        ).trim()

        def parsed = readJSON(text: json)
        creds = [
            username:       parsed.data.username,
            password:       parsed.data.password,
            lease_id:       parsed.lease_id,
            lease_duration: parsed.lease_duration
        ]

        echo "[vault] Dynamic credentials provisioned for role '${role}' — user: ${creds.username}, lease: ${creds.lease_id}"
    }

    return creds
}

// ---------------------------------------------------------------------------
// withVaultSecrets(paths, closure) — Inject secrets into a block, revoke after.
//
// Reads one or more Vault KV paths, merges all key-value pairs into a flat
// map, and passes them to the closure. Token is revoked after the block
// completes (success or failure).
//
// Parameters:
//   paths   — List of Vault KV paths to read
//   opts    — Optional: token, revokeAfter (default: true)
//   body    — Closure receiving Map<String, String> of all secrets
//
// Usage:
//   vault.withSecrets(['kv/data/myapp/db', 'kv/data/myapp/api']) { secrets ->
//     sh "curl -H 'Authorization: Bearer ${secrets.API_TOKEN}' https://api.example.com"
//   }
// ---------------------------------------------------------------------------
def withSecrets(List<String> paths, Map opts = [:], Closure body) {
    def vaultToken = opts.get('token', null) ?: auth(opts)
    def revokeAfter = opts.get('revokeAfter', true)

    def allSecrets = [:]

    try {
        withEnv(["VAULT_TOKEN=${vaultToken}"]) {
            paths.each { path ->
                echo "[vault] Reading: ${path}"
                def secrets = read(path, [token: vaultToken])
                if (secrets instanceof Map) {
                    allSecrets.putAll(secrets)
                }
            }
        }

        // Build environment variables list for secret masking.
        // Jenkins will mask any variable set via withEnv from console output.
        def envVars = allSecrets.collect { k, v -> "${k}=${v}" }

        withEnv(envVars) {
            body(allSecrets)
        }

    } finally {
        if (revokeAfter) {
            try {
                withEnv(["VAULT_TOKEN=${vaultToken}"]) {
                    sh 'vault token revoke -self 2>/dev/null || true'
                }
                echo "[vault] Token revoked."
            } catch (Exception e) {
                echo "[vault] Token revocation failed (may have already expired): ${e.message}"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// revokeLease(leaseId) — Revoke a Vault lease (e.g. dynamic DB credentials).
// ---------------------------------------------------------------------------
def revokeLease(String leaseId, Map opts = [:]) {
    def token = opts.get('token', env.VAULT_TOKEN)
    if (!token) {
        echo "[vault] No token available for lease revocation."
        return
    }
    withEnv(["VAULT_TOKEN=${token}"]) {
        sh """
            set -euo pipefail
            vault lease revoke "${leaseId}" 2>/dev/null || true
            echo "[vault] Lease revoked: ${leaseId}"
        """
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

private def getOidcToken() {
    // Check for Jenkins OIDC Provider plugin token
    def tokenFile = env.OIDC_TOKEN_FILE
    if (tokenFile && fileExists(tokenFile)) {
        return readFile(tokenFile).trim()
    }
    // Check for environment variable (some OIDC plugins expose it this way)
    if (env.JENKINS_OIDC_TOKEN) {
        return env.JENKINS_OIDC_TOKEN
    }
    return null
}

private def extractToken(String vaultResponse) {
    def json = readJSON(text: vaultResponse)
    return json?.auth?.client_token
}

return this
