// Package vault provides a high-level client for HashiCorp Vault operations.
//
// It wraps the official Vault API client with typed operations for KV v2,
// dynamic credentials, PKI certificate issuance, SSH signing, Transit
// encrypt/decrypt, and token lifecycle management.
package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// HealthStatus represents the health state of a Vault component.
type HealthStatus string

const (
	// HealthStatusHealthy indicates the component is fully operational.
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusDegraded indicates partial functionality.
	HealthStatusDegraded HealthStatus = "degraded"
	// HealthStatusUnhealthy indicates the component is non-functional.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	// HealthStatusUnknown indicates the status could not be determined.
	HealthStatusUnknown HealthStatus = "unknown"
)

// HealthCheck is the result of a single health probe.
type HealthCheck struct {
	Name      string       `json:"name"`
	Status    HealthStatus `json:"status"`
	Detail    string       `json:"detail"`
	LatencyMs float64      `json:"latency_ms"`
}

// HealthReport aggregates multiple health checks.
type HealthReport struct {
	Checks    []HealthCheck `json:"checks"`
	Timestamp time.Time     `json:"timestamp"`
}

// OverallStatus derives the worst-case status across all checks.
func (r *HealthReport) OverallStatus() HealthStatus {
	if len(r.Checks) == 0 {
		return HealthStatusUnknown
	}
	hasUnhealthy := false
	hasDegraded := false
	for _, c := range r.Checks {
		switch c.Status {
		case HealthStatusUnhealthy:
			hasUnhealthy = true
		case HealthStatusDegraded:
			hasDegraded = true
		}
	}
	if hasUnhealthy {
		return HealthStatusUnhealthy
	}
	if hasDegraded {
		return HealthStatusDegraded
	}
	return HealthStatusHealthy
}

// Summary returns a one-line summary of the health report.
func (r *HealthReport) Summary() string {
	parts := make([]string, 0, len(r.Checks))
	for _, c := range r.Checks {
		parts = append(parts, fmt.Sprintf("%s: %s", c.Name, c.Status))
	}
	return fmt.Sprintf("[%s] %s", strings.ToUpper(string(r.OverallStatus())), strings.Join(parts, " | "))
}

// SecretMetadata holds metadata about a KV v2 secret version.
type SecretMetadata struct {
	Path           string            `json:"path"`
	Version        int               `json:"version"`
	CreatedTime    string            `json:"created_time,omitempty"`
	Destroyed      bool              `json:"destroyed"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// LeaseInfo holds dynamic credential lease details.
type LeaseInfo struct {
	LeaseID       string                 `json:"lease_id"`
	LeaseDuration int                    `json:"lease_duration"`
	Renewable     bool                   `json:"renewable"`
	RequestID     string                 `json:"request_id,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
}

// CertInfo holds a PKI-issued certificate and its metadata.
type CertInfo struct {
	Certificate    string   `json:"certificate"`
	IssuingCA      string   `json:"issuing_ca"`
	CAChain        []string `json:"ca_chain,omitempty"`
	PrivateKey     string   `json:"private_key,omitempty"`
	PrivateKeyType string   `json:"private_key_type,omitempty"`
	SerialNumber   string   `json:"serial_number,omitempty"`
	Expiration     int64    `json:"expiration,omitempty"`
}

// SSHCertInfo holds a signed SSH certificate.
type SSHCertInfo struct {
	SignedKey     string `json:"signed_key"`
	SerialNumber string `json:"serial_number,omitempty"`
}

// TransitResult holds the result of a Transit encrypt or decrypt operation.
type TransitResult struct {
	Ciphertext string `json:"ciphertext,omitempty"`
	Plaintext  string `json:"plaintext,omitempty"`
	KeyVersion int    `json:"key_version,omitempty"`
}

// PKIIssueOpts are optional parameters for PKI certificate issuance.
type PKIIssueOpts struct {
	AltNames []string
	TTL      string
}

// ClientOption configures a VaultClient.
type ClientOption func(*clientConfig)

type clientConfig struct {
	token      string
	namespace  string
	skipVerify bool
	kvMount    string
	httpClient *http.Client
}

// WithToken sets the initial Vault token.
func WithToken(token string) ClientOption {
	return func(c *clientConfig) { c.token = token }
}

// WithNamespace sets the Vault namespace (enterprise).
func WithNamespace(ns string) ClientOption {
	return func(c *clientConfig) { c.namespace = ns }
}

// WithSkipVerify disables TLS certificate verification.
func WithSkipVerify(skip bool) ClientOption {
	return func(c *clientConfig) { c.skipVerify = skip }
}

// WithKVMount sets the KV v2 secrets engine mount point.
func WithKVMount(mount string) ClientOption {
	return func(c *clientConfig) { c.kvMount = mount }
}

// WithHTTPClient sets a custom HTTP client for Vault API requests.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *clientConfig) { c.httpClient = hc }
}

// VaultClient is a high-level client for HashiCorp Vault.
//
// It provides typed methods for authentication, KV v2 operations, dynamic
// credentials, PKI, SSH signing, Transit encryption, and health checks.
type VaultClient struct {
	addr       string
	token      string
	namespace  string
	kvMount    string
	httpClient *http.Client

	mu          sync.Mutex
	renewCancel context.CancelFunc
}

// NewClient creates a new VaultClient for the given Vault address.
//
// The address defaults to VAULT_ADDR or http://127.0.0.1:8200 if empty.
// Options configure authentication, namespaces, and TLS behavior.
func NewClient(addr string, opts ...ClientOption) *VaultClient {
	if addr == "" {
		addr = os.Getenv("VAULT_ADDR")
	}
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	addr = strings.TrimRight(addr, "/")

	cfg := &clientConfig{
		kvMount: "kv",
	}
	for _, o := range opts {
		o(cfg)
	}

	hc := cfg.httpClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	token := cfg.token
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}

	ns := cfg.namespace
	if ns == "" {
		ns = os.Getenv("VAULT_NAMESPACE")
	}

	return &VaultClient{
		addr:       addr,
		token:      token,
		namespace:  ns,
		kvMount:    cfg.kvMount,
		httpClient: hc,
	}
}

// --------------------------------------------------------------------
// Authentication
// --------------------------------------------------------------------

// AuthToken authenticates the client using a Vault token.
// If token is empty, it falls back to the VAULT_TOKEN environment variable.
func (c *VaultClient) AuthToken(ctx context.Context, token string) error {
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return &AuthError{Method: "token", Detail: "no token provided and VAULT_TOKEN not set"}
	}
	c.token = token

	// Verify token by looking it up
	_, err := c.doRequest(ctx, "GET", "/v1/auth/token/lookup-self", nil)
	if err != nil {
		c.token = ""
		return &AuthError{Method: "token", Detail: err.Error()}
	}
	return nil
}

// AuthAppRole authenticates using AppRole credentials.
// Falls back to VAULT_ROLE_ID and VAULT_SECRET_ID environment variables.
func (c *VaultClient) AuthAppRole(ctx context.Context, roleID, secretID, mountPoint string) error {
	if roleID == "" {
		roleID = os.Getenv("VAULT_ROLE_ID")
	}
	if secretID == "" {
		secretID = os.Getenv("VAULT_SECRET_ID")
	}
	if mountPoint == "" {
		mountPoint = "approle"
	}
	if roleID == "" {
		return &AuthError{Method: "approle", Detail: "no role_id provided and VAULT_ROLE_ID not set"}
	}

	body := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/auth/%s/login", mountPoint), body)
	if err != nil {
		return &AuthError{Method: "approle", Detail: err.Error()}
	}
	auth, ok := resp["auth"].(map[string]interface{})
	if !ok {
		return &AuthError{Method: "approle", Detail: "missing auth in response"}
	}
	tok, _ := auth["client_token"].(string)
	if tok == "" {
		return &AuthError{Method: "approle", Detail: "empty client_token in response"}
	}
	c.token = tok
	return nil
}

// AuthOIDC authenticates using a JWT token for OIDC/JWT auth.
// In headless environments, provide the JWT directly. Falls back to VAULT_OIDC_TOKEN.
func (c *VaultClient) AuthOIDC(ctx context.Context, role, jwt, mountPoint string) error {
	if jwt == "" {
		jwt = os.Getenv("VAULT_OIDC_TOKEN")
	}
	if mountPoint == "" {
		mountPoint = "oidc"
	}
	if jwt == "" {
		return &AuthError{Method: "oidc", Detail: "no JWT provided and VAULT_OIDC_TOKEN not set; interactive OIDC not supported"}
	}

	body := map[string]interface{}{
		"role": role,
		"jwt":  jwt,
	}
	resp, err := c.doRequest(ctx, "POST", fmt.Sprintf("/v1/auth/%s/login", mountPoint), body)
	if err != nil {
		return &AuthError{Method: "oidc", Detail: err.Error()}
	}
	auth, ok := resp["auth"].(map[string]interface{})
	if !ok {
		return &AuthError{Method: "oidc", Detail: "missing auth in response"}
	}
	tok, _ := auth["client_token"].(string)
	if tok == "" {
		return &AuthError{Method: "oidc", Detail: "empty client_token in response"}
	}
	c.token = tok
	return nil
}

// --------------------------------------------------------------------
// KV v2 Operations
// --------------------------------------------------------------------

// KVRead reads a secret from KV v2 at the given path.
// Returns the secret data map. Version 0 means latest.
func (c *VaultClient) KVRead(ctx context.Context, path string, version int) (map[string]interface{}, error) {
	url := fmt.Sprintf("/v1/%s/data/%s", c.kvMount, path)
	if version > 0 {
		url = fmt.Sprintf("%s?version=%d", url, version)
	}
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		if isNotFound(err) {
			return nil, &SecretNotFoundError{Path: path}
		}
		return nil, fmt.Errorf("vault kv read %s: %w", path, err)
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return nil, &SecretNotFoundError{Path: path}
	}
	inner, ok := data["data"].(map[string]interface{})
	if !ok {
		return nil, &SecretNotFoundError{Path: path}
	}
	return inner, nil
}

// KVWrite writes secret data to KV v2 at the given path.
// Returns metadata about the written version.
func (c *VaultClient) KVWrite(ctx context.Context, path string, data map[string]interface{}) (*SecretMetadata, error) {
	url := fmt.Sprintf("/v1/%s/data/%s", c.kvMount, path)
	body := map[string]interface{}{
		"data": data,
	}
	resp, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("vault kv write %s: %w", path, err)
	}
	meta := &SecretMetadata{Path: path, Version: 1}
	if d, ok := resp["data"].(map[string]interface{}); ok {
		if v, ok := d["version"].(float64); ok {
			meta.Version = int(v)
		}
		if ct, ok := d["created_time"].(string); ok {
			meta.CreatedTime = ct
		}
	}
	return meta, nil
}

// KVDelete soft-deletes a secret version at the given KV v2 path.
func (c *VaultClient) KVDelete(ctx context.Context, path string) error {
	url := fmt.Sprintf("/v1/%s/data/%s", c.kvMount, path)
	_, err := c.doRequest(ctx, "DELETE", url, nil)
	if err != nil {
		if isNotFound(err) {
			return &SecretNotFoundError{Path: path}
		}
		return fmt.Errorf("vault kv delete %s: %w", path, err)
	}
	return nil
}

// --------------------------------------------------------------------
// Dynamic Credentials
// --------------------------------------------------------------------

// DynamicCreds generates dynamic credentials from a secrets engine.
// mount is the engine mount (e.g., "database"), role is the role name.
func (c *VaultClient) DynamicCreds(ctx context.Context, mount, role string) (*LeaseInfo, error) {
	url := fmt.Sprintf("/v1/%s/creds/%s", mount, role)
	resp, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault dynamic creds %s/%s: %w", mount, role, err)
	}
	lease := &LeaseInfo{}
	if v, ok := resp["lease_id"].(string); ok {
		lease.LeaseID = v
	}
	if v, ok := resp["lease_duration"].(float64); ok {
		lease.LeaseDuration = int(v)
	}
	if v, ok := resp["renewable"].(bool); ok {
		lease.Renewable = v
	}
	if v, ok := resp["request_id"].(string); ok {
		lease.RequestID = v
	}
	if v, ok := resp["data"].(map[string]interface{}); ok {
		lease.Data = v
	}
	return lease, nil
}

// --------------------------------------------------------------------
// PKI Certificate Issuance
// --------------------------------------------------------------------

// PKIIssue issues a certificate from the PKI secrets engine.
// mount is the PKI mount point (e.g., "pki"), role is the PKI role,
// commonName is the certificate CN, and opts provides optional parameters.
func (c *VaultClient) PKIIssue(ctx context.Context, mount, role, commonName string, opts *PKIIssueOpts) (*CertInfo, error) {
	if mount == "" {
		mount = "pki"
	}
	url := fmt.Sprintf("/v1/%s/issue/%s", mount, role)
	body := map[string]interface{}{
		"common_name": commonName,
	}
	if opts != nil {
		if len(opts.AltNames) > 0 {
			body["alt_names"] = strings.Join(opts.AltNames, ",")
		}
		if opts.TTL != "" {
			body["ttl"] = opts.TTL
		}
	}
	resp, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("vault pki issue %s/%s: %w", mount, role, err)
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return nil, fmt.Errorf("vault pki issue: missing data in response")
	}
	cert := &CertInfo{}
	cert.Certificate, _ = data["certificate"].(string)
	cert.IssuingCA, _ = data["issuing_ca"].(string)
	cert.PrivateKey, _ = data["private_key"].(string)
	cert.PrivateKeyType, _ = data["private_key_type"].(string)
	cert.SerialNumber, _ = data["serial_number"].(string)
	if exp, ok := data["expiration"].(float64); ok {
		cert.Expiration = int64(exp)
	}
	if chain, ok := data["ca_chain"].([]interface{}); ok {
		for _, v := range chain {
			if s, ok := v.(string); ok {
				cert.CAChain = append(cert.CAChain, s)
			}
		}
	}
	return cert, nil
}

// --------------------------------------------------------------------
// SSH Certificate Signing
// --------------------------------------------------------------------

// SSHSign signs an SSH public key using the SSH secrets engine.
// mount is the SSH mount (e.g., "ssh"), role is the SSH role.
func (c *VaultClient) SSHSign(ctx context.Context, mount, role, publicKey string) (*SSHCertInfo, error) {
	if mount == "" {
		mount = "ssh"
	}
	url := fmt.Sprintf("/v1/%s/sign/%s", mount, role)
	body := map[string]interface{}{
		"public_key": publicKey,
	}
	resp, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("vault ssh sign %s/%s: %w", mount, role, err)
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return nil, fmt.Errorf("vault ssh sign: missing data in response")
	}
	info := &SSHCertInfo{}
	info.SignedKey, _ = data["signed_key"].(string)
	info.SerialNumber, _ = data["serial_number"].(string)
	return info, nil
}

// --------------------------------------------------------------------
// Transit Encrypt / Decrypt
// --------------------------------------------------------------------

// TransitEncrypt encrypts plaintext using the Transit secrets engine.
// mount is the Transit mount (e.g., "transit"), key is the encryption key name.
func (c *VaultClient) TransitEncrypt(ctx context.Context, mount, key string, plaintext []byte) (*TransitResult, error) {
	if mount == "" {
		mount = "transit"
	}
	url := fmt.Sprintf("/v1/%s/encrypt/%s", mount, key)
	b64 := base64.StdEncoding.EncodeToString(plaintext)
	body := map[string]interface{}{
		"plaintext": b64,
	}
	resp, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("vault transit encrypt %s/%s: %w", mount, key, err)
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return nil, fmt.Errorf("vault transit encrypt: missing data in response")
	}
	result := &TransitResult{}
	result.Ciphertext, _ = data["ciphertext"].(string)
	if kv, ok := data["key_version"].(float64); ok {
		result.KeyVersion = int(kv)
	}
	return result, nil
}

// TransitDecrypt decrypts ciphertext using the Transit secrets engine.
// mount is the Transit mount (e.g., "transit"), key is the encryption key name.
// ciphertext should be in the form "vault:v1:...".
func (c *VaultClient) TransitDecrypt(ctx context.Context, mount, key, ciphertext string) (*TransitResult, error) {
	if mount == "" {
		mount = "transit"
	}
	url := fmt.Sprintf("/v1/%s/decrypt/%s", mount, key)
	body := map[string]interface{}{
		"ciphertext": ciphertext,
	}
	resp, err := c.doRequest(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt %s/%s: %w", mount, key, err)
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return nil, fmt.Errorf("vault transit decrypt: missing data in response")
	}
	b64, _ := data["plaintext"].(string)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt: invalid base64 plaintext: %w", err)
	}
	return &TransitResult{Plaintext: string(decoded)}, nil
}

// --------------------------------------------------------------------
// Token Lifecycle
// --------------------------------------------------------------------

// RenewToken renews the current token with the given increment (e.g., "1h").
func (c *VaultClient) RenewToken(ctx context.Context, increment string) (map[string]interface{}, error) {
	if increment == "" {
		increment = "1h"
	}
	body := map[string]interface{}{
		"increment": increment,
	}
	resp, err := c.doRequest(ctx, "POST", "/v1/auth/token/renew-self", body)
	if err != nil {
		return nil, &LeaseError{LeaseID: "self", Operation: "renew", Detail: err.Error()}
	}
	auth, _ := resp["auth"].(map[string]interface{})
	return auth, nil
}

// RenewTokenBackground starts a background goroutine that renews the token
// at the given interval. Call the returned cancel function to stop renewal.
func (c *VaultClient) RenewTokenBackground(ctx context.Context, interval time.Duration, increment string) context.CancelFunc {
	c.mu.Lock()
	if c.renewCancel != nil {
		c.renewCancel()
	}
	rctx, cancel := context.WithCancel(ctx)
	c.renewCancel = cancel
	c.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-rctx.Done():
				return
			case <-ticker.C:
				_, _ = c.RenewToken(rctx, increment)
			}
		}
	}()
	return cancel
}

// --------------------------------------------------------------------
// Health
// --------------------------------------------------------------------

// Health checks Vault connectivity, seal status, and token validity.
func (c *VaultClient) Health(ctx context.Context) *HealthReport {
	report := &HealthReport{
		Timestamp: time.Now().UTC(),
		Checks:    make([]HealthCheck, 0, 2),
	}

	// Connectivity + seal check
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", c.addr+"/v1/sys/health", nil)
	if err != nil {
		report.Checks = append(report.Checks, HealthCheck{
			Name:   "vault_connectivity",
			Status: HealthStatusUnhealthy,
			Detail: err.Error(),
		})
		return report
	}
	resp, err := c.httpClient.Do(req)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		report.Checks = append(report.Checks, HealthCheck{
			Name:      "vault_connectivity",
			Status:    HealthStatusUnhealthy,
			Detail:    err.Error(),
			LatencyMs: latency,
		})
	} else {
		defer resp.Body.Close()
		var healthResp map[string]interface{}
		bodyBytes, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(bodyBytes, &healthResp)

		initialized, _ := healthResp["initialized"].(bool)
		sealed, _ := healthResp["sealed"].(bool)

		switch {
		case initialized && !sealed:
			report.Checks = append(report.Checks, HealthCheck{
				Name:      "vault_connectivity",
				Status:    HealthStatusHealthy,
				Detail:    fmt.Sprintf("Vault at %s is initialized and unsealed", c.addr),
				LatencyMs: latency,
			})
		case sealed:
			report.Checks = append(report.Checks, HealthCheck{
				Name:      "vault_connectivity",
				Status:    HealthStatusUnhealthy,
				Detail:    "Vault is sealed",
				LatencyMs: latency,
			})
		default:
			report.Checks = append(report.Checks, HealthCheck{
				Name:      "vault_connectivity",
				Status:    HealthStatusDegraded,
				Detail:    "Vault is not initialized",
				LatencyMs: latency,
			})
		}
	}

	// Auth check
	if c.token != "" {
		_, err := c.doRequest(ctx, "GET", "/v1/auth/token/lookup-self", nil)
		if err != nil {
			report.Checks = append(report.Checks, HealthCheck{
				Name:   "vault_auth",
				Status: HealthStatusUnhealthy,
				Detail: "Token is invalid or expired",
			})
		} else {
			report.Checks = append(report.Checks, HealthCheck{
				Name:   "vault_auth",
				Status: HealthStatusHealthy,
				Detail: "Token is valid",
			})
		}
	} else {
		report.Checks = append(report.Checks, HealthCheck{
			Name:   "vault_auth",
			Status: HealthStatusUnhealthy,
			Detail: "No token configured",
		})
	}

	return report
}

// --------------------------------------------------------------------
// HTTP Transport
// --------------------------------------------------------------------

func (c *VaultClient) doRequest(ctx context.Context, method, path string, body interface{}) (map[string]interface{}, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = strings.NewReader(string(b))
	}

	url := c.addr + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ConnectionError{Addr: c.addr, Detail: err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &apiError{StatusCode: resp.StatusCode, Message: "not found"}
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, &AuthError{Method: "token", Detail: "permission denied"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := string(respBody)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, &apiError{StatusCode: resp.StatusCode, Message: msg}
	}

	// Some endpoints (DELETE) may return empty body
	if len(respBody) == 0 {
		return map[string]interface{}{}, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

// --------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------

// AuthError is returned when Vault authentication fails.
type AuthError struct {
	Method string
	Detail string
}

func (e *AuthError) Error() string {
	msg := fmt.Sprintf("vault auth failed using %s", e.Method)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// SecretNotFoundError is returned when a KV path does not exist.
type SecretNotFoundError struct {
	Path string
}

func (e *SecretNotFoundError) Error() string {
	return fmt.Sprintf("secret not found at path: %s", e.Path)
}

// ConnectionError is returned when Vault is unreachable.
type ConnectionError struct {
	Addr   string
	Detail string
}

func (e *ConnectionError) Error() string {
	msg := fmt.Sprintf("cannot connect to Vault at %s", e.Addr)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// LeaseError is returned when a lease operation fails.
type LeaseError struct {
	LeaseID   string
	Operation string
	Detail    string
}

func (e *LeaseError) Error() string {
	msg := fmt.Sprintf("lease %s failed for %s", e.Operation, e.LeaseID)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// apiError is an internal error for non-2xx Vault API responses.
type apiError struct {
	StatusCode int
	Message    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("vault API error (status %d): %s", e.StatusCode, e.Message)
}

func isNotFound(err error) bool {
	if ae, ok := err.(*apiError); ok {
		return ae.StatusCode == http.StatusNotFound
	}
	return false
}
