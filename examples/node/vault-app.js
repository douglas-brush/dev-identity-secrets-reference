#!/usr/bin/env node
/**
 * Vault-integrated Node.js application demonstrating OIDC/AppRole auth,
 * KV v2 secret reading, dynamic database credentials, and an Express
 * health endpoint exposing secret status.
 *
 * Environment variables:
 *   VAULT_ADDR          - Vault server URL (required)
 *   VAULT_AUTH_METHOD   - "oidc" or "approle" (default: approle)
 *   VAULT_ROLE          - Vault role name for authentication
 *   VAULT_ROLE_ID       - AppRole role ID (required if approle)
 *   VAULT_SECRET_ID     - AppRole secret ID (required if approle)
 *   VAULT_OIDC_TOKEN    - Pre-obtained OIDC JWT (required if oidc)
 *   VAULT_KV_PATH       - KV v2 secret path (default: kv/dev/apps/myapp/config)
 *   VAULT_DB_ROLE       - Database secret engine role (default: myapp-db)
 *   VAULT_NAMESPACE     - Vault namespace (optional, enterprise)
 *   PORT                - Health endpoint port (default: 8080)
 */

"use strict";

const vault = require("node-vault");
const express = require("express");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const state = {
  authenticated: false,
  kvSecrets: {},
  kvLoadedAt: null,
  dbCredentials: null,
  dbLeaseId: null,
  dbLeaseExpiry: null,
  renewalActive: false,
  errors: [],
};

let vaultClient = null;
let renewalTimer = null;

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Authenticate to Vault. AppRole uses role_id + secret_id delivered by
 * a trusted orchestrator. OIDC uses a pre-obtained JWT for headless envs.
 */
async function authenticate() {
  const method = process.env.VAULT_AUTH_METHOD || "approle";
  const role = process.env.VAULT_ROLE || "myapp";

  if (method === "approle") {
    const roleId = process.env.VAULT_ROLE_ID;
    const secretId = process.env.VAULT_SECRET_ID;
    if (!roleId || !secretId) {
      throw new Error("VAULT_ROLE_ID and VAULT_SECRET_ID required for AppRole");
    }
    const resp = await vaultClient.approleLogin({
      role_id: roleId,
      secret_id: secretId,
    });
    vaultClient.token = resp.auth.client_token;
    console.log(`[vault] Authenticated via AppRole, TTL ${resp.auth.lease_duration}s`);
    return resp.auth.lease_duration;

  } else if (method === "oidc") {
    const jwt = process.env.VAULT_OIDC_TOKEN;
    if (!jwt) throw new Error("VAULT_OIDC_TOKEN required for OIDC auth");
    // Use the JWT auth backend which accepts OIDC tokens
    const resp = await vaultClient.write("auth/oidc/login", {
      role,
      jwt,
    });
    vaultClient.token = resp.auth.client_token;
    console.log(`[vault] Authenticated via OIDC, TTL ${resp.auth.lease_duration}s`);
    return resp.auth.lease_duration;

  } else {
    throw new Error(`Unsupported auth method: ${method}`);
  }
}

// ---------------------------------------------------------------------------
// Secret operations
// ---------------------------------------------------------------------------

/**
 * Read a KV v2 secret. The path should NOT include the /data/ segment —
 * the KV v2 API adds it automatically when using the correct endpoint.
 */
async function readKvSecret(path) {
  // KV v2: GET /secret/data/:path
  const resp = await vaultClient.read(path);
  const version = resp.data.metadata.version;
  console.log(`[vault] Read KV secret at ${path} (version ${version})`);
  return resp.data.data;
}

/**
 * Request dynamic database credentials. These are short-lived and tied
 * to a Vault lease. The app must handle credential expiry gracefully —
 * typically by catching connection errors and re-acquiring credentials.
 */
async function getDatabaseCredentials(role) {
  const resp = await vaultClient.read(`database/creds/${role}`);
  const { username, password } = resp.data;
  const leaseId = resp.lease_id;
  const leaseDuration = resp.lease_duration;
  console.log(
    `[vault] DB creds acquired: user=${username} TTL=${leaseDuration}s lease=${leaseId.substring(0, 16)}...`
  );
  return { username, password, leaseId, leaseDuration };
}

// ---------------------------------------------------------------------------
// Lease / token renewal
// ---------------------------------------------------------------------------

/**
 * Start a renewal loop that renews the auth token and any tracked leases.
 * Runs at 2/3 of the TTL to allow margin for transient failures.
 * After 3 consecutive failures, triggers full re-authentication.
 */
function startRenewalLoop(tokenTtl) {
  let failures = 0;
  state.renewalActive = true;

  async function renew() {
    try {
      // Renew auth token
      const tokenResp = await vaultClient.tokenRenewSelf();
      const newTtl = tokenResp.auth.lease_duration;
      console.log(`[vault] Token renewed, new TTL ${newTtl}s`);

      // Renew DB lease if active
      if (state.dbLeaseId) {
        try {
          await vaultClient.write("sys/leases/renew", {
            lease_id: state.dbLeaseId,
          });
          console.log("[vault] DB lease renewed");
        } catch (err) {
          console.warn(`[vault] DB lease renewal failed: ${err.message}`);
          // Re-acquire credentials on next cycle
          state.dbLeaseId = null;
        }
      }

      failures = 0;
      const sleepMs = Math.max((newTtl * 2000) / 3, 5000);
      renewalTimer = setTimeout(renew, sleepMs);

    } catch (err) {
      failures += 1;
      console.error(`[vault] Renewal failed (attempt ${failures}): ${err.message}`);
      state.errors.push({ time: new Date().toISOString(), error: err.message });

      if (failures >= 3) {
        console.warn("[vault] 3 consecutive failures — re-authenticating");
        try {
          const ttl = await authenticate();
          failures = 0;
          renewalTimer = setTimeout(renew, Math.max((ttl * 2000) / 3, 5000));
        } catch (authErr) {
          console.error(`[vault] Re-auth failed: ${authErr.message}`);
          renewalTimer = setTimeout(renew, 10000);
        }
      } else {
        renewalTimer = setTimeout(renew, 5000);
      }
    }
  }

  const initialSleep = Math.max((tokenTtl * 2000) / 3, 5000);
  renewalTimer = setTimeout(renew, initialSleep);
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

function startHealthServer() {
  const app = express();
  const port = parseInt(process.env.PORT || "8080", 10);

  // Health check exposes secret metadata (not values) for observability.
  // This lets monitoring detect stale secrets or renewal failures.
  app.get("/health", (_req, res) => {
    const dbExpired = state.dbLeaseExpiry
      ? new Date() > new Date(state.dbLeaseExpiry)
      : false;

    const healthy = state.authenticated && !dbExpired && state.renewalActive;
    const status = {
      status: healthy ? "healthy" : "degraded",
      vault: {
        authenticated: state.authenticated,
        renewalActive: state.renewalActive,
      },
      kv: {
        loaded: !!state.kvLoadedAt,
        loadedAt: state.kvLoadedAt,
        keyCount: Object.keys(state.kvSecrets).length,
      },
      database: {
        credentialsActive: !!state.dbCredentials,
        username: state.dbCredentials?.username || null,
        leaseExpired: dbExpired,
        expiresAt: state.dbLeaseExpiry,
      },
      recentErrors: state.errors.slice(-5),
    };

    res.status(healthy ? 200 : 503).json(status);
  });

  app.listen(port, () => {
    console.log(`[health] Listening on :${port}/health`);
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const addr = process.env.VAULT_ADDR;
  if (!addr) {
    console.error("[vault] VAULT_ADDR is required");
    process.exit(1);
  }

  const kvPath = process.env.VAULT_KV_PATH || "kv/data/dev/apps/myapp/config";
  const dbRole = process.env.VAULT_DB_ROLE || "myapp-db";

  // Initialize client — TLS verification uses system CA bundle by default.
  // Set NODE_EXTRA_CA_CERTS for custom CA bundles.
  vaultClient = vault({
    apiVersion: "v1",
    endpoint: addr,
    namespace: process.env.VAULT_NAMESPACE || undefined,
  });

  // Step 1: Authenticate
  const tokenTtl = await authenticate();
  state.authenticated = true;

  // Step 2: Start renewal before reading secrets
  startRenewalLoop(tokenTtl);

  // Step 3: Read static KV secrets
  state.kvSecrets = await readKvSecret(kvPath);
  state.kvLoadedAt = new Date().toISOString();

  // Export to env for child processes or framework config
  for (const [key, value] of Object.entries(state.kvSecrets)) {
    process.env[`APP_${key.toUpperCase()}`] = String(value);
  }
  console.log(`[vault] Exported ${Object.keys(state.kvSecrets).length} KV secrets to env`);

  // Step 4: Acquire dynamic DB credentials
  const dbCreds = await getDatabaseCredentials(dbRole);
  state.dbCredentials = { username: dbCreds.username };
  state.dbLeaseId = dbCreds.leaseId;
  state.dbLeaseExpiry = new Date(
    Date.now() + dbCreds.leaseDuration * 1000
  ).toISOString();
  process.env.APP_DB_USERNAME = dbCreds.username;
  process.env.APP_DB_PASSWORD = dbCreds.password;

  console.log("[vault] Integration ready — secrets loaded, renewal active");

  // Step 5: Start health endpoint
  startHealthServer();
}

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[vault] SIGTERM received, shutting down");
  clearTimeout(renewalTimer);
  process.exit(0);
});
process.on("SIGINT", () => {
  console.log("[vault] SIGINT received, shutting down");
  clearTimeout(renewalTimer);
  process.exit(0);
});

main().catch((err) => {
  console.error(`[vault] Fatal: ${err.message}`);
  process.exit(1);
});
