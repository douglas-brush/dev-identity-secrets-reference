// Vault-integrated Go application demonstrating OIDC/AppRole auth,
// KV v2 secret reading, dynamic database credentials, and an HTTP
// health endpoint.
//
// Environment variables:
//
//	VAULT_ADDR          - Vault server URL (required)
//	VAULT_AUTH_METHOD   - "oidc" or "approle" (default: approle)
//	VAULT_ROLE          - Vault role name for authentication
//	VAULT_ROLE_ID       - AppRole role ID (required if approle)
//	VAULT_SECRET_ID     - AppRole secret ID (required if approle)
//	VAULT_OIDC_TOKEN    - Pre-obtained OIDC JWT (required if oidc)
//	VAULT_KV_PATH       - KV v2 secret path (default: kv/data/dev/apps/myapp/config)
//	VAULT_DB_ROLE       - Database secret engine role (default: myapp-db)
//	VAULT_NAMESPACE     - Vault namespace (optional, enterprise)
//	PORT                - Health endpoint port (default: 8080)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

type appState struct {
	mu             sync.RWMutex
	authenticated  bool
	kvSecrets      map[string]interface{}
	kvLoadedAt     time.Time
	dbUsername     string
	dbLeaseID     string
	dbLeaseExpiry time.Time
	renewalActive bool
	errors        []stateError
}

type stateError struct {
	Time    string `json:"time"`
	Message string `json:"error"`
}

var state = &appState{}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// authenticate logs into Vault using the configured auth method.
// AppRole: uses role_id + secret_id delivered by a trusted orchestrator.
// OIDC: uses a pre-obtained JWT for headless environments.
func authenticate(client *vault.Client, method, role string) (leaseDuration int, err error) {
	switch method {
	case "approle":
		roleID := os.Getenv("VAULT_ROLE_ID")
		secretID := os.Getenv("VAULT_SECRET_ID")
		if roleID == "" || secretID == "" {
			return 0, fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID required for AppRole")
		}
		secret, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
			"role_id":   roleID,
			"secret_id": secretID,
		})
		if err != nil {
			return 0, fmt.Errorf("AppRole login: %w", err)
		}
		client.SetToken(secret.Auth.ClientToken)
		log.Printf("[vault] Authenticated via AppRole, TTL %ds", secret.Auth.LeaseDuration)
		return secret.Auth.LeaseDuration, nil

	case "oidc":
		jwt := os.Getenv("VAULT_OIDC_TOKEN")
		if jwt == "" {
			return 0, fmt.Errorf("VAULT_OIDC_TOKEN required for OIDC auth")
		}
		secret, err := client.Logical().Write("auth/oidc/login", map[string]interface{}{
			"role": role,
			"jwt":  jwt,
		})
		if err != nil {
			return 0, fmt.Errorf("OIDC login: %w", err)
		}
		client.SetToken(secret.Auth.ClientToken)
		log.Printf("[vault] Authenticated via OIDC, TTL %ds", secret.Auth.LeaseDuration)
		return secret.Auth.LeaseDuration, nil

	default:
		return 0, fmt.Errorf("unsupported auth method: %s", method)
	}
}

// ---------------------------------------------------------------------------
// Secret operations
// ---------------------------------------------------------------------------

// readKVSecret reads a KV v2 secret and returns the data map.
// The path should include the /data/ segment for KV v2.
func readKVSecret(client *vault.Client, path string) (map[string]interface{}, error) {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("read KV %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret at %s", path)
	}

	// KV v2 wraps data in a nested "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected KV v2 response structure at %s", path)
	}

	metadata := secret.Data["metadata"].(map[string]interface{})
	log.Printf("[vault] Read KV secret at %s (version %v)", path, metadata["version"])
	return data, nil
}

// getDBCredentials requests dynamic database credentials from Vault.
// These are short-lived and tied to a lease. The application must handle
// credential rotation by catching connection errors and re-acquiring.
func getDBCredentials(client *vault.Client, role string) (username, password, leaseID string, leaseDuration int, err error) {
	path := fmt.Sprintf("database/creds/%s", role)
	secret, err := client.Logical().Read(path)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("get DB creds for %s: %w", role, err)
	}
	if secret == nil {
		return "", "", "", 0, fmt.Errorf("no credentials returned for role %s", role)
	}

	username = secret.Data["username"].(string)
	password = secret.Data["password"].(string)
	leaseID = secret.LeaseID
	leaseDuration = secret.LeaseDuration

	log.Printf("[vault] DB creds acquired: user=%s TTL=%ds lease=%s...",
		username, leaseDuration, leaseID[:min(16, len(leaseID))])
	return username, password, leaseID, leaseDuration, nil
}

// ---------------------------------------------------------------------------
// Token / lease renewal
// ---------------------------------------------------------------------------

// startRenewalLoop renews the Vault token and tracked leases in the background.
// It renews at 2/3 of the TTL to provide margin for transient failures.
// After 3 consecutive failures it triggers full re-authentication.
func startRenewalLoop(ctx context.Context, client *vault.Client, tokenTTL int, method, role string) {
	state.mu.Lock()
	state.renewalActive = true
	state.mu.Unlock()

	go func() {
		failures := 0
		sleepDur := time.Duration(max(tokenTTL*2/3, 5)) * time.Second

		for {
			select {
			case <-ctx.Done():
				log.Println("[vault] Renewal loop stopped")
				return
			case <-time.After(sleepDur):
			}

			// Renew auth token
			secret, err := client.Auth().Token().RenewSelf(0)
			if err != nil {
				failures++
				log.Printf("[vault] Token renewal failed (attempt %d): %v", failures, err)
				state.mu.Lock()
				state.errors = append(state.errors, stateError{
					Time:    time.Now().UTC().Format(time.RFC3339),
					Message: err.Error(),
				})
				state.mu.Unlock()

				if failures >= 3 {
					log.Println("[vault] 3 consecutive failures — re-authenticating")
					ttl, authErr := authenticate(client, method, role)
					if authErr != nil {
						log.Printf("[vault] Re-auth failed: %v", authErr)
						sleepDur = 10 * time.Second
					} else {
						failures = 0
						sleepDur = time.Duration(max(ttl*2/3, 5)) * time.Second
					}
				} else {
					sleepDur = 5 * time.Second
				}
				continue
			}

			newTTL := secret.Auth.LeaseDuration
			log.Printf("[vault] Token renewed, new TTL %ds", newTTL)

			// Renew DB lease if tracked
			state.mu.RLock()
			leaseID := state.dbLeaseID
			state.mu.RUnlock()

			if leaseID != "" {
				_, err := client.Sys().Renew(leaseID, 0)
				if err != nil {
					log.Printf("[vault] DB lease renewal failed: %v", err)
					state.mu.Lock()
					state.dbLeaseID = ""
					state.mu.Unlock()
				} else {
					log.Println("[vault] DB lease renewed")
				}
			}

			failures = 0
			sleepDur = time.Duration(max(newTTL*2/3, 5)) * time.Second
		}
	}()
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

func healthHandler(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	defer state.mu.RUnlock()

	dbExpired := !state.dbLeaseExpiry.IsZero() && time.Now().After(state.dbLeaseExpiry)
	healthy := state.authenticated && !dbExpired && state.renewalActive

	// Expose metadata only — never secret values
	resp := map[string]interface{}{
		"status": "healthy",
		"vault": map[string]interface{}{
			"authenticated": state.authenticated,
			"renewalActive": state.renewalActive,
		},
		"kv": map[string]interface{}{
			"loaded":   !state.kvLoadedAt.IsZero(),
			"loadedAt": state.kvLoadedAt.Format(time.RFC3339),
			"keyCount": len(state.kvSecrets),
		},
		"database": map[string]interface{}{
			"credentialsActive": state.dbUsername != "",
			"username":          state.dbUsername,
			"leaseExpired":      dbExpired,
			"expiresAt":         state.dbLeaseExpiry.Format(time.RFC3339),
		},
	}
	if !healthy {
		resp["status"] = "degraded"
	}

	// Include last 5 errors for debugging
	errSlice := state.errors
	if len(errSlice) > 5 {
		errSlice = errSlice[len(errSlice)-5:]
	}
	resp["recentErrors"] = errSlice

	w.Header().Set("Content-Type", "application/json")
	if healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		log.Fatal("[vault] VAULT_ADDR is required")
	}

	authMethod := envOrDefault("VAULT_AUTH_METHOD", "approle")
	role := envOrDefault("VAULT_ROLE", "myapp")
	kvPath := envOrDefault("VAULT_KV_PATH", "kv/data/dev/apps/myapp/config")
	dbRole := envOrDefault("VAULT_DB_ROLE", "myapp-db")
	port := envOrDefault("PORT", "8080")

	// Build Vault client — TLS verification uses system CA bundle.
	// Set VAULT_CACERT for custom CA bundles.
	config := vault.DefaultConfig()
	config.Address = vaultAddr
	if ns := os.Getenv("VAULT_NAMESPACE"); ns != "" {
		// Namespace is set via header after client creation
		_ = ns
	}

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("[vault] Client init failed: %v", err)
	}
	if ns := os.Getenv("VAULT_NAMESPACE"); ns != "" {
		client.SetNamespace(ns)
	}

	// Step 1: Authenticate
	tokenTTL, err := authenticate(client, authMethod, role)
	if err != nil {
		log.Fatalf("[vault] Authentication failed: %v", err)
	}
	state.mu.Lock()
	state.authenticated = true
	state.mu.Unlock()

	// Step 2: Start renewal loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startRenewalLoop(ctx, client, tokenTTL, authMethod, role)

	// Step 3: Read KV secrets
	kvData, err := readKVSecret(client, kvPath)
	if err != nil {
		log.Fatalf("[vault] Failed to read KV secret: %v", err)
	}
	state.mu.Lock()
	state.kvSecrets = kvData
	state.kvLoadedAt = time.Now().UTC()
	state.mu.Unlock()

	// Export to env for child processes
	for key, value := range kvData {
		envKey := fmt.Sprintf("APP_%s", strings.ToUpper(key))
		os.Setenv(envKey, fmt.Sprintf("%v", value))
	}
	log.Printf("[vault] Exported %d KV secrets to env", len(kvData))

	// Step 4: Acquire dynamic DB credentials
	username, _, leaseID, leaseDuration, err := getDBCredentials(client, dbRole)
	if err != nil {
		log.Fatalf("[vault] Failed to get DB credentials: %v", err)
	}
	state.mu.Lock()
	state.dbUsername = username
	state.dbLeaseID = leaseID
	state.dbLeaseExpiry = time.Now().Add(time.Duration(leaseDuration) * time.Second)
	state.mu.Unlock()

	log.Println("[vault] Integration ready — secrets loaded, renewal active")

	// Step 5: Start health server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	srv := &http.Server{Addr: ":" + port, Handler: mux}

	go func() {
		log.Printf("[health] Listening on :%s/health", port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("[health] Server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[vault] Shutting down")
	cancel()
	srv.Shutdown(context.Background())
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
