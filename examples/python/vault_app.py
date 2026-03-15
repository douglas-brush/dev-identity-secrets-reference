#!/usr/bin/env python3
"""Vault-integrated application demonstrating OIDC/AppRole auth,
KV v2 secret reading, and dynamic database credential acquisition.

Environment variables:
    VAULT_ADDR          - Vault server URL (required)
    VAULT_AUTH_METHOD   - "oidc" or "approle" (default: approle)
    VAULT_ROLE          - Vault role name for authentication
    VAULT_ROLE_ID       - AppRole role ID (required if approle)
    VAULT_SECRET_ID     - AppRole secret ID (required if approle)
    VAULT_KV_PATH       - KV v2 secret path (default: kv/data/dev/apps/myapp/config)
    VAULT_DB_ROLE       - Database secret engine role (default: myapp-db)
    VAULT_NAMESPACE     - Vault namespace (optional, for enterprise)
"""

import logging
import os
import signal
import sys
import threading
import time

import hvac
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("vault-app")

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def authenticate(client: hvac.Client, method: str, role: str) -> None:
    """Authenticate to Vault using the configured method.

    OIDC auth relies on a browser flow or a pre-obtained JWT token
    supplied via VAULT_OIDC_TOKEN for headless environments.
    AppRole uses role_id + secret_id — the secret_id is single-use
    and should be delivered via a trusted init container or orchestrator.
    """
    if method == "oidc":
        token = os.environ.get("VAULT_OIDC_TOKEN")
        if not token:
            raise EnvironmentError(
                "VAULT_OIDC_TOKEN required for headless OIDC auth"
            )
        # Exchange the OIDC JWT for a Vault token
        resp = client.auth.oidc.oidc_callback(
            role=role,
            code=token,
            state="headless",
        )
        client.token = resp["auth"]["client_token"]
        log.info("Authenticated via OIDC, lease TTL %ss", resp["auth"]["lease_duration"])

    elif method == "approle":
        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")
        if not role_id or not secret_id:
            raise EnvironmentError(
                "VAULT_ROLE_ID and VAULT_SECRET_ID required for AppRole auth"
            )
        resp = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        client.token = resp["auth"]["client_token"]
        log.info("Authenticated via AppRole, lease TTL %ss", resp["auth"]["lease_duration"])

    else:
        raise ValueError(f"Unsupported auth method: {method}")


# ---------------------------------------------------------------------------
# Secret operations
# ---------------------------------------------------------------------------

def read_kv_secret(client: hvac.Client, path: str) -> dict:
    """Read a KV v2 secret and return the data payload.

    KV v2 stores versioned secrets. We read the latest version and
    expose the inner 'data' map which contains the actual key-value pairs.
    """
    mount, _, secret_path = path.partition("/data/")
    if not secret_path:
        # Caller passed path without /data/ prefix — treat entire path as mount + path
        parts = path.split("/", 1)
        mount, secret_path = parts[0], parts[1] if len(parts) > 1 else ""

    resp = client.secrets.kv.v2.read_secret_version(
        path=secret_path,
        mount_point=mount,
    )
    log.info("Read KV secret at %s (version %s)", path, resp["data"]["metadata"]["version"])
    return resp["data"]["data"]


def get_db_credentials(client: hvac.Client, role: str) -> dict:
    """Request dynamic database credentials from the database secret engine.

    These credentials are short-lived and tied to a Vault lease.
    The application must be prepared to re-acquire credentials when
    the lease expires or when a database connection fails.
    """
    resp = client.secrets.databases.generate_credentials(name=role)
    lease_id = resp["lease_id"]
    ttl = resp["lease_duration"]
    creds = resp["data"]
    log.info(
        "Acquired DB creds for role=%s user=%s lease_ttl=%ss lease_id=%s",
        role, creds["username"], ttl, lease_id[:16] + "...",
    )
    return {"username": creds["username"], "password": creds["password"],
            "lease_id": lease_id, "lease_duration": ttl}


def export_as_env(secrets: dict, prefix: str = "APP_") -> None:
    """Template secrets into environment variables for child processes.

    This is useful when wrapping legacy apps that read config from env.
    The prefix avoids collisions with system variables.
    """
    for key, value in secrets.items():
        env_key = f"{prefix}{key.upper()}"
        os.environ[env_key] = str(value)
        log.info("Exported %s", env_key)


# ---------------------------------------------------------------------------
# Token / lease renewal
# ---------------------------------------------------------------------------

class RenewalManager:
    """Background thread that renews the Vault token and any active leases.

    Renewal happens at 2/3 of the TTL to provide margin for transient
    failures. If renewal fails three times consecutively, the manager
    triggers re-authentication.
    """

    def __init__(self, client: hvac.Client, auth_method: str, role: str):
        self._client = client
        self._auth_method = auth_method
        self._role = role
        self._leases: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def track_lease(self, lease_id: str) -> None:
        self._leases.append(lease_id)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                # Renew the auth token
                resp = self._client.auth.token.renew_self()
                ttl = resp["auth"]["lease_duration"]
                log.info("Token renewed, new TTL %ss", ttl)

                # Renew tracked leases
                for lease_id in list(self._leases):
                    try:
                        self._client.sys.renew_lease(lease_id=lease_id)
                    except hvac.exceptions.InvalidRequest:
                        log.warning("Lease %s expired, removing", lease_id[:16])
                        self._leases.remove(lease_id)

                failures = 0
                # Sleep for 2/3 of the token TTL before next renewal
                sleep_secs = max(ttl * 2 // 3, 5)
                self._stop.wait(sleep_secs)

            except Exception as exc:
                failures += 1
                log.error("Renewal failed (attempt %d): %s", failures, exc)
                if failures >= 3:
                    log.warning("3 consecutive renewal failures — re-authenticating")
                    try:
                        authenticate(self._client, self._auth_method, self._role)
                        failures = 0
                    except Exception as auth_exc:
                        log.error("Re-authentication failed: %s", auth_exc)
                self._stop.wait(5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    vault_addr = os.environ.get("VAULT_ADDR")
    if not vault_addr:
        log.error("VAULT_ADDR is required")
        sys.exit(1)

    auth_method = os.environ.get("VAULT_AUTH_METHOD", "approle")
    role = os.environ.get("VAULT_ROLE", "myapp")
    kv_path = os.environ.get("VAULT_KV_PATH", "kv/data/dev/apps/myapp/config")
    db_role = os.environ.get("VAULT_DB_ROLE", "myapp-db")
    namespace = os.environ.get("VAULT_NAMESPACE")

    # Build client — TLS verification is on by default.
    # Set VAULT_CACERT or REQUESTS_CA_BUNDLE for custom CA bundles.
    client = hvac.Client(url=vault_addr, namespace=namespace)

    # Step 1: Authenticate
    authenticate(client, auth_method, role)

    if not client.is_authenticated():
        log.error("Authentication succeeded but token is not valid")
        sys.exit(1)

    # Step 2: Start renewal manager before reading secrets
    renewer = RenewalManager(client, auth_method, role)
    renewer.start()

    # Step 3: Read static KV secrets
    kv_data = read_kv_secret(client, kv_path)
    export_as_env(kv_data)

    # Step 4: Acquire dynamic database credentials
    db_creds = get_db_credentials(client, db_role)
    renewer.track_lease(db_creds["lease_id"])
    export_as_env({"db_username": db_creds["username"],
                    "db_password": db_creds["password"]}, prefix="APP_")

    log.info("Vault integration ready — secrets loaded, renewal active")
    log.info("Static secrets: %s", list(kv_data.keys()))
    log.info("DB user: %s (TTL %ss)", db_creds["username"], db_creds["lease_duration"])

    # Keep running until interrupted
    stop_event = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())

    stop_event.wait()
    renewer.stop()
    log.info("Shutting down")


if __name__ == "__main__":
    main()
