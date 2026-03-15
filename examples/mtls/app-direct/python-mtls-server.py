#!/usr/bin/env python3
"""mTLS server — HTTPS server that requires client certificate authentication.

Demonstrates how to configure Python's ssl module for mutual TLS using
certificates issued by Vault's PKI engine. The server verifies that
connecting clients present a valid certificate signed by the trusted CA.

Environment variables:
    MTLS_SERVER_CERT    - Path to server certificate PEM (required)
    MTLS_SERVER_KEY     - Path to server private key PEM (required)
    MTLS_CA_BUNDLE      - Path to CA bundle for client verification (required)
    MTLS_LISTEN_HOST    - Listen address (default: 0.0.0.0)
    MTLS_LISTEN_PORT    - Listen port (default: 8443)
    MTLS_MIN_TLS        - Minimum TLS version: 1.2 or 1.3 (default: 1.2)

Usage:
    export MTLS_SERVER_CERT=./certs/server.pem
    export MTLS_SERVER_KEY=./certs/server-key.pem
    export MTLS_CA_BUNDLE=./certs/ca-bundle.pem
    python3 python-mtls-server.py
"""

import http.server
import json
import logging
import os
import ssl
import sys
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("mtls-server")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_CERT = os.environ.get("MTLS_SERVER_CERT")
SERVER_KEY = os.environ.get("MTLS_SERVER_KEY")
CA_BUNDLE = os.environ.get("MTLS_CA_BUNDLE")
LISTEN_HOST = os.environ.get("MTLS_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("MTLS_LISTEN_PORT", "8443"))
MIN_TLS = os.environ.get("MTLS_MIN_TLS", "1.2")


def validate_config() -> None:
    """Validate that required certificate paths are set and files exist."""
    missing = []
    for name, path in [
        ("MTLS_SERVER_CERT", SERVER_CERT),
        ("MTLS_SERVER_KEY", SERVER_KEY),
        ("MTLS_CA_BUNDLE", CA_BUNDLE),
    ]:
        if not path:
            missing.append(f"{name} is required")
        elif not os.path.isfile(path):
            missing.append(f"{name}={path} — file not found")

    if missing:
        for msg in missing:
            log.error(msg)
        sys.exit(1)


# ---------------------------------------------------------------------------
# TLS context
# ---------------------------------------------------------------------------

def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context configured for mTLS.

    Key settings:
    - CERT_REQUIRED: the server demands a valid client certificate
    - load_verify_locations: the CA bundle used to verify client certs
    - load_cert_chain: the server's own certificate and key
    """
    # Start with a server-side context using modern defaults
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Minimum TLS version
    if MIN_TLS == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Maximum TLS version — always allow the highest available
    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    # Require client certificates — this is the core of mTLS
    # CERT_REQUIRED means the handshake fails if the client does not
    # present a certificate or presents one not signed by a trusted CA.
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load the CA bundle used to verify client certificates
    ctx.load_verify_locations(cafile=CA_BUNDLE)

    # Load the server's own certificate and key
    ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

    # Security hardening
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_SINGLE_ECDH_USE

    log.info("SSL context created: min_tls=%s, verify_mode=CERT_REQUIRED", MIN_TLS)
    return ctx


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class MTLSHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that extracts and logs client certificate information."""

    def do_GET(self) -> None:
        """Handle GET requests — return client cert info as JSON."""
        # Extract the client certificate from the SSL socket
        peer_cert = self.request.getpeercert()

        if self.path == "/healthz":
            self._respond(200, {"status": "healthy"})
            return

        if self.path == "/" or self.path == "/whoami":
            # Parse client identity from the certificate
            client_info = self._parse_client_cert(peer_cert)
            log.info(
                "Authenticated request: subject=%s, issuer=%s",
                client_info.get("subject_cn", "unknown"),
                client_info.get("issuer_cn", "unknown"),
            )
            self._respond(200, {
                "message": "mTLS authentication successful",
                "client": client_info,
                "server_time": datetime.now(timezone.utc).isoformat(),
            })
            return

        self._respond(404, {"error": "not found"})

    def _parse_client_cert(self, cert: dict) -> dict:
        """Extract useful fields from the peer certificate dict."""
        if not cert:
            return {"error": "no client certificate"}

        # Python's ssl module returns subject as a tuple of tuples
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))

        return {
            "subject_cn": subject.get("commonName", ""),
            "subject_o": subject.get("organizationName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "serial": cert.get("serialNumber", ""),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "san": cert.get("subjectAltName", []),
        }

    def _respond(self, status: int, body: dict) -> None:
        """Send a JSON response."""
        payload = json.dumps(body, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:
        """Override default logging to use structured logger."""
        log.info("HTTP %s", format % args)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    validate_config()
    ssl_ctx = create_ssl_context()

    server = http.server.HTTPServer((LISTEN_HOST, LISTEN_PORT), MTLSHandler)
    server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

    log.info("mTLS server listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    log.info("Server cert: %s", SERVER_CERT)
    log.info("CA bundle:   %s", CA_BUNDLE)
    log.info("Clients must present a certificate signed by the trusted CA")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
