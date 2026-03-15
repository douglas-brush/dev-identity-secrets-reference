#!/usr/bin/env python3
"""mTLS client — HTTPS client that presents a client certificate for authentication.

Demonstrates how to make HTTPS requests with mutual TLS using certificates
issued by Vault's PKI engine. The client presents its certificate to the
server and verifies the server's certificate against the trusted CA.

Environment variables:
    MTLS_CLIENT_CERT    - Path to client certificate PEM (required)
    MTLS_CLIENT_KEY     - Path to client private key PEM (required)
    MTLS_CA_BUNDLE      - Path to CA bundle for server verification (required)
    MTLS_SERVER_URL     - Server URL to connect to (default: https://localhost:8443)
    MTLS_MIN_TLS        - Minimum TLS version: 1.2 or 1.3 (default: 1.2)

Usage:
    export MTLS_CLIENT_CERT=./certs/client.pem
    export MTLS_CLIENT_KEY=./certs/client-key.pem
    export MTLS_CA_BUNDLE=./certs/ca-bundle.pem
    python3 python-mtls-client.py
"""

import json
import logging
import os
import ssl
import sys
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("mtls-client")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLIENT_CERT = os.environ.get("MTLS_CLIENT_CERT")
CLIENT_KEY = os.environ.get("MTLS_CLIENT_KEY")
CA_BUNDLE = os.environ.get("MTLS_CA_BUNDLE")
SERVER_URL = os.environ.get("MTLS_SERVER_URL", "https://localhost:8443")
MIN_TLS = os.environ.get("MTLS_MIN_TLS", "1.2")


def validate_config() -> None:
    """Validate that required certificate paths are set and files exist."""
    missing = []
    for name, path in [
        ("MTLS_CLIENT_CERT", CLIENT_CERT),
        ("MTLS_CLIENT_KEY", CLIENT_KEY),
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
    """Create an SSL context for mTLS client connections.

    Key settings:
    - CERT_REQUIRED: verify the server's certificate
    - load_cert_chain: present the client certificate to the server
    - load_verify_locations: trust the CA that signed the server's cert
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Minimum TLS version
    if MIN_TLS == "1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    # Verify the server's certificate against our CA bundle
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=CA_BUNDLE)

    # Present the client certificate — this is what the server requires for mTLS
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    log.info("SSL context created: min_tls=%s, client_cert=%s", MIN_TLS, CLIENT_CERT)
    return ctx


# ---------------------------------------------------------------------------
# HTTP request
# ---------------------------------------------------------------------------

def make_request(ssl_ctx: ssl.SSLContext, path: str = "/whoami") -> dict:
    """Make an HTTPS request with mutual TLS.

    Uses urllib from the standard library to avoid external dependencies.
    For production use, consider the `requests` library with a custom
    SSLContext or `httpx` which has native mTLS support.
    """
    url = f"{SERVER_URL}{path}"
    log.info("Requesting %s", url)

    handler = urllib.request.HTTPSHandler(context=ssl_ctx)
    opener = urllib.request.build_opener(handler)

    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")

    try:
        with opener.open(req, timeout=10) as response:
            body = response.read().decode("utf-8")
            status = response.status
            log.info("Response: HTTP %d", status)
            return json.loads(body)

    except urllib.error.HTTPError as e:
        log.error("HTTP error: %d %s", e.code, e.reason)
        body = e.read().decode("utf-8")
        return {"error": f"HTTP {e.code}", "body": body}

    except urllib.error.URLError as e:
        log.error("Connection error: %s", e.reason)
        return {"error": str(e.reason)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    validate_config()
    ssl_ctx = create_ssl_context()

    log.info("Connecting to %s with client certificate", SERVER_URL)

    # Request the /whoami endpoint which returns our client cert identity
    result = make_request(ssl_ctx, "/whoami")
    print(json.dumps(result, indent=2))

    # Also check health endpoint
    health = make_request(ssl_ctx, "/healthz")
    log.info("Health check: %s", health.get("status", "unknown"))


if __name__ == "__main__":
    main()
