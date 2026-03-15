// go-mtls-server.go — HTTPS server with mutual TLS authentication.
//
// Demonstrates configuring Go's crypto/tls for mTLS using certificates
// issued by Vault's PKI engine. The server requires connecting clients
// to present a valid certificate signed by the trusted CA.
//
// Environment variables:
//
//	MTLS_SERVER_CERT  - Path to server certificate PEM (required)
//	MTLS_SERVER_KEY   - Path to server private key PEM (required)
//	MTLS_CA_BUNDLE    - Path to CA bundle for client verification (required)
//	MTLS_LISTEN_ADDR  - Listen address (default: :8443)
//	MTLS_MIN_TLS      - Minimum TLS version: 1.2 or 1.3 (default: 1.2)
//
// Usage:
//
//	export MTLS_SERVER_CERT=./certs/server.pem
//	export MTLS_SERVER_KEY=./certs/server-key.pem
//	export MTLS_CA_BUNDLE=./certs/ca-bundle.pem
//	go run go-mtls-server.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// Read configuration from environment
	serverCert := requireEnv("MTLS_SERVER_CERT")
	serverKey := requireEnv("MTLS_SERVER_KEY")
	caBundlePath := requireEnv("MTLS_CA_BUNDLE")
	listenAddr := envOrDefault("MTLS_LISTEN_ADDR", ":8443")
	minTLS := envOrDefault("MTLS_MIN_TLS", "1.2")

	// Load the CA bundle for client certificate verification
	caBundlePEM, err := os.ReadFile(caBundlePath)
	if err != nil {
		log.Fatalf("Failed to read CA bundle %s: %v", caBundlePath, err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBundlePEM) {
		log.Fatal("Failed to parse CA bundle — no valid certificates found")
	}

	// Determine minimum TLS version
	var minVersion uint16
	switch minTLS {
	case "1.3":
		minVersion = tls.VersionTLS13
	default:
		minVersion = tls.VersionTLS12
	}

	// Configure TLS with mutual authentication
	tlsConfig := &tls.Config{
		// RequireAndVerifyClientCert is the core mTLS setting.
		// The server demands a client certificate and verifies it
		// against the CA pool before allowing the connection.
		ClientAuth: tls.RequireAndVerifyClientCert,

		// CA pool used to verify client certificates
		ClientCAs: caPool,

		// Minimum TLS version
		MinVersion: minVersion,

		// Cipher suites for TLS 1.2 (TLS 1.3 suites are not configurable
		// in Go — they are always enabled and preferred when both sides
		// support TLS 1.3)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},

		// Prefer the server's cipher order
		PreferServerCipherSuites: true,
	}

	// Set up HTTP handlers
	mux := http.NewServeMux()

	// /whoami — returns the authenticated client's certificate identity
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		clientInfo := extractClientCert(r)
		log.Printf("Authenticated request from %s (serial: %s)",
			clientInfo["subject_cn"], clientInfo["serial"])

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message":     "mTLS authentication successful",
			"client":      clientInfo,
			"server_time": time.Now().UTC().Format(time.RFC3339),
		})
	})

	// /healthz — health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})

	// Root handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			respondJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		clientInfo := extractClientCert(r)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "mTLS server",
			"client":  clientInfo,
		})
	})

	// Create the HTTPS server
	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("mTLS server listening on %s", listenAddr)
	log.Printf("Server cert: %s", serverCert)
	log.Printf("CA bundle:   %s", caBundlePath)
	log.Printf("Min TLS:     %s", minTLS)
	log.Print("Clients must present a certificate signed by the trusted CA")

	// ListenAndServeTLS loads the server cert/key and starts the listener
	if err := server.ListenAndServeTLS(serverCert, serverKey); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// extractClientCert pulls identity information from the verified client
// certificate. By the time the request reaches the handler, Go has already
// verified the certificate chain against the CA pool configured in
// tls.Config.ClientCAs.
func extractClientCert(r *http.Request) map[string]interface{} {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return map[string]interface{}{"error": "no client certificate"}
	}

	cert := r.TLS.PeerCertificates[0]

	// Collect Subject Alternative Names
	sans := make([]string, 0)
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, "URI:"+uri.String())
	}

	return map[string]interface{}{
		"subject_cn": cert.Subject.CommonName,
		"subject_o":  firstOrEmpty(cert.Subject.Organization),
		"issuer_cn":  cert.Issuer.CommonName,
		"serial":     cert.SerialNumber.String(),
		"not_before": cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  cert.NotAfter.UTC().Format(time.RFC3339),
		"san":        sans,
	}
}

func respondJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func requireEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		fmt.Fprintf(os.Stderr, "ERROR: %s is required\n", key)
		os.Exit(1)
	}
	return val
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
