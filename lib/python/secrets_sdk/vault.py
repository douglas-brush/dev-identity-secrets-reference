"""Vault client wrapper providing typed access to HashiCorp Vault operations.

Supports OIDC, AppRole, and token authentication. All operations handle missing
connectivity gracefully by raising clear exceptions.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from typing import Any

import hvac  # type: ignore[import-untyped,unused-ignore]
import hvac.exceptions  # type: ignore[import-untyped,unused-ignore]

from secrets_sdk.exceptions import (
    VaultAuthError,
    VaultConnectionError,
    VaultLeaseError,
    VaultSecretNotFound,
)
from secrets_sdk.models import (
    AuditEvent,
    AuditEventType,
    CertInfo,
    HealthCheck,
    HealthReport,
    HealthStatus,
    LeaseInfo,
    SSHCertInfo,
    SecretMetadata,
    TransitResult,
)

logger = logging.getLogger(__name__)


class VaultClient:
    """High-level Vault client wrapping hvac with typed operations.

    Instantiate from environment variables, explicit config, or an existing
    hvac client instance.

    Environment variables used (when not explicitly provided):
        VAULT_ADDR: Vault server URL
        VAULT_TOKEN: Token for token-based auth
        VAULT_NAMESPACE: Vault namespace (enterprise)
        VAULT_SKIP_VERIFY: Skip TLS verification ("1" or "true")
        VAULT_ROLE_ID / VAULT_SECRET_ID: AppRole credentials
    """

    def __init__(
        self,
        addr: str | None = None,
        token: str | None = None,
        namespace: str | None = None,
        verify: bool | None = None,
        kv_mount: str = "kv",
        client: Any | None = None,
    ) -> None:
        self._addr = addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
        self._namespace = namespace or os.environ.get("VAULT_NAMESPACE")
        self._kv_mount = kv_mount
        self._audit_events: list[AuditEvent] = []

        if verify is None:
            skip = os.environ.get("VAULT_SKIP_VERIFY", "").lower()
            self._verify = skip not in ("1", "true")
        else:
            self._verify = verify

        if client is not None:
            self._client = client
        else:
            self._client = hvac.Client(
                url=self._addr,
                token=token or os.environ.get("VAULT_TOKEN"),
                namespace=self._namespace,
                verify=self._verify,
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def client(self) -> Any:
        """Access the underlying hvac.Client instance."""
        return self._client

    @property
    def is_authenticated(self) -> bool:
        """Check if the current token is valid."""
        try:
            return bool(self._client.is_authenticated())
        except Exception:
            return False

    @property
    def audit_log(self) -> list[AuditEvent]:
        """Return collected audit events."""
        return list(self._audit_events)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def auth_token(self, token: str | None = None) -> None:
        """Authenticate using a Vault token.

        Args:
            token: Vault token. Falls back to VAULT_TOKEN env var.

        Raises:
            VaultAuthError: If the token is invalid or missing.
        """
        t = token or os.environ.get("VAULT_TOKEN")
        if not t:
            raise VaultAuthError("token", "No token provided and VAULT_TOKEN not set")
        self._client.token = t
        try:
            result = self._client.auth.token.lookup_self()
            if result is None:
                raise VaultAuthError("token", "Token lookup returned None")
            self._emit(AuditEventType.AUTH_SUCCESS, detail="method=token")
        except hvac.exceptions.Forbidden:
            self._emit(AuditEventType.AUTH_FAILURE, detail="method=token", success=False)
            raise VaultAuthError("token", "Token is invalid or expired")
        except hvac.exceptions.VaultError as exc:
            self._emit(AuditEventType.AUTH_FAILURE, detail="method=token", success=False)
            raise VaultAuthError("token", str(exc))
        except Exception as exc:
            self._emit(AuditEventType.AUTH_FAILURE, detail="method=token", success=False)
            raise VaultConnectionError(self._addr, str(exc))

    def auth_approle(
        self,
        role_id: str | None = None,
        secret_id: str | None = None,
        mount_point: str = "approle",
    ) -> None:
        """Authenticate using AppRole.

        Args:
            role_id: AppRole role ID. Falls back to VAULT_ROLE_ID env var.
            secret_id: AppRole secret ID. Falls back to VAULT_SECRET_ID env var.
            mount_point: Auth mount point.

        Raises:
            VaultAuthError: If credentials are missing or invalid.
        """
        rid = role_id or os.environ.get("VAULT_ROLE_ID", "")
        sid = secret_id or os.environ.get("VAULT_SECRET_ID", "")
        if not rid:
            raise VaultAuthError("approle", "No role_id provided and VAULT_ROLE_ID not set")
        try:
            result = self._client.auth.approle.login(
                role_id=rid,
                secret_id=sid,
                mount_point=mount_point,
            )
            self._client.token = result["auth"]["client_token"]
            self._emit(AuditEventType.AUTH_SUCCESS, detail="method=approle")
        except hvac.exceptions.InvalidRequest as exc:
            self._emit(AuditEventType.AUTH_FAILURE, detail="method=approle", success=False)
            raise VaultAuthError("approle", str(exc))
        except hvac.exceptions.VaultError as exc:
            self._emit(AuditEventType.AUTH_FAILURE, detail="method=approle", success=False)
            raise VaultAuthError("approle", str(exc))
        except Exception as exc:
            self._emit(AuditEventType.AUTH_FAILURE, detail="method=approle", success=False)
            raise VaultConnectionError(self._addr, str(exc))

    def auth_oidc(
        self,
        role: str = "",
        mount_point: str = "oidc",
    ) -> None:
        """Authenticate using OIDC (JWT).

        This triggers the OIDC auth flow. In non-interactive contexts,
        set the VAULT_OIDC_TOKEN env var to provide a JWT directly.

        Args:
            role: Vault role to authenticate against.
            mount_point: Auth mount point.

        Raises:
            VaultAuthError: If OIDC flow fails.
        """
        jwt_token = os.environ.get("VAULT_OIDC_TOKEN", "")
        if jwt_token:
            # Direct JWT login (for CI or headless environments)
            try:
                result = self._client.auth.jwt.jwt_login(
                    role=role,
                    jwt=jwt_token,
                    path=mount_point,
                )
                self._client.token = result["auth"]["client_token"]
                self._emit(AuditEventType.AUTH_SUCCESS, detail="method=oidc/jwt")
                return
            except hvac.exceptions.VaultError as exc:
                self._emit(AuditEventType.AUTH_FAILURE, detail="method=oidc/jwt", success=False)
                raise VaultAuthError("oidc", str(exc))
            except Exception as exc:
                self._emit(AuditEventType.AUTH_FAILURE, detail="method=oidc/jwt", success=False)
                raise VaultConnectionError(self._addr, str(exc))
        # Interactive OIDC flow is not supported in SDK context
        raise VaultAuthError(
            "oidc",
            "Interactive OIDC not supported. Set VAULT_OIDC_TOKEN for headless JWT login.",
        )

    # ------------------------------------------------------------------
    # KV v2 Operations
    # ------------------------------------------------------------------

    def kv_read(self, path: str, version: int | None = None) -> dict[str, Any]:
        """Read a secret from KV v2.

        Args:
            path: Secret path (without mount prefix).
            version: Specific version to read. None for latest.

        Returns:
            The secret data dictionary.

        Raises:
            VaultSecretNotFound: If the path does not exist.
            VaultConnectionError: If Vault is unreachable.
        """
        try:
            result = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version,
                mount_point=self._kv_mount,
            )
            self._emit(AuditEventType.SECRET_READ, path=f"{self._kv_mount}/{path}")
            if result is None or "data" not in result or "data" not in result["data"]:
                raise VaultSecretNotFound(path)
            return dict(result["data"]["data"])
        except hvac.exceptions.InvalidPath:
            self._emit(
                AuditEventType.SECRET_READ,
                path=f"{self._kv_mount}/{path}",
                success=False,
            )
            raise VaultSecretNotFound(path)
        except VaultSecretNotFound:
            raise
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def kv_write(self, path: str, data: dict[str, Any]) -> SecretMetadata:
        """Write a secret to KV v2.

        Args:
            path: Secret path (without mount prefix).
            data: Key-value data to store.

        Returns:
            Metadata about the written secret version.

        Raises:
            VaultConnectionError: If Vault is unreachable.
        """
        try:
            result = self._client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self._kv_mount,
            )
            self._emit(AuditEventType.SECRET_WRITE, path=f"{self._kv_mount}/{path}")
            meta = result.get("data", {})
            return SecretMetadata(
                path=path,
                version=meta.get("version", 1),
                created_time=meta.get("created_time"),
            )
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def kv_list(self, path: str = "") -> list[str]:
        """List secrets at a KV v2 path.

        Args:
            path: Directory path to list.

        Returns:
            List of key names at the path.

        Raises:
            VaultSecretNotFound: If the path does not exist.
            VaultConnectionError: If Vault is unreachable.
        """
        try:
            result = self._client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=self._kv_mount,
            )
            if result is None:
                return []
            return list(result.get("data", {}).get("keys", []))
        except hvac.exceptions.InvalidPath:
            raise VaultSecretNotFound(path)
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def kv_metadata(self, path: str) -> SecretMetadata:
        """Read metadata for a KV v2 secret (without the secret data).

        Args:
            path: Secret path.

        Returns:
            SecretMetadata with version info and custom metadata.

        Raises:
            VaultSecretNotFound: If the path does not exist.
        """
        try:
            result = self._client.secrets.kv.v2.read_secret_metadata(
                path=path,
                mount_point=self._kv_mount,
            )
            if result is None:
                raise VaultSecretNotFound(path)
            data = result.get("data", {})
            current = data.get("current_version", 1)
            versions = data.get("versions", {})
            version_data = versions.get(str(current), {})
            return SecretMetadata(
                path=path,
                version=current,
                created_time=version_data.get("created_time"),
                destroyed=version_data.get("destroyed", False),
                custom_metadata=data.get("custom_metadata") or {},
            )
        except hvac.exceptions.InvalidPath:
            raise VaultSecretNotFound(path)
        except VaultSecretNotFound:
            raise
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    # ------------------------------------------------------------------
    # Dynamic Database Credentials
    # ------------------------------------------------------------------

    def db_creds(self, role: str, mount_point: str = "database") -> LeaseInfo:
        """Generate dynamic database credentials.

        Args:
            role: Database role name.
            mount_point: Database secrets engine mount point.

        Returns:
            LeaseInfo with credentials in .data and lease details.

        Raises:
            VaultConnectionError: If Vault is unreachable.
        """
        try:
            result = self._client.secrets.database.generate_credentials(
                name=role,
                mount_point=mount_point,
            )
            return LeaseInfo(
                lease_id=result.get("lease_id", ""),
                lease_duration=result.get("lease_duration", 0),
                renewable=result.get("renewable", False),
                request_id=result.get("request_id", ""),
                data=result.get("data", {}),
            )
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    # ------------------------------------------------------------------
    # PKI Certificate Issuance
    # ------------------------------------------------------------------

    def pki_issue(
        self,
        role: str,
        common_name: str,
        alt_names: list[str] | None = None,
        ttl: str = "8760h",
        mount_point: str = "pki",
    ) -> CertInfo:
        """Issue a PKI certificate.

        Args:
            role: PKI role name.
            common_name: Certificate CN.
            alt_names: Subject alternative names.
            ttl: Certificate TTL (e.g., "720h").
            mount_point: PKI secrets engine mount point.

        Returns:
            CertInfo with certificate, CA chain, and private key.
        """
        try:
            kwargs: dict[str, Any] = {
                "name": role,
                "common_name": common_name,
                "mount_point": mount_point,
                "extra_params": {"ttl": ttl},
            }
            if alt_names:
                kwargs["extra_params"]["alt_names"] = ",".join(alt_names)

            result = self._client.secrets.pki.generate_certificate(**kwargs)
            data = result.get("data", {})
            self._emit(AuditEventType.CERT_ISSUE, path=f"{mount_point}/issue/{role}")
            return CertInfo(
                certificate=data.get("certificate", ""),
                issuing_ca=data.get("issuing_ca", ""),
                ca_chain=data.get("ca_chain", []),
                private_key=data.get("private_key", ""),
                private_key_type=data.get("private_key_type", ""),
                serial_number=data.get("serial_number", ""),
                expiration=data.get("expiration", 0),
            )
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    # ------------------------------------------------------------------
    # SSH Certificate Signing
    # ------------------------------------------------------------------

    def ssh_sign(
        self,
        role: str,
        public_key: str,
        valid_principals: str = "",
        ttl: str = "",
        cert_type: str = "user",
        mount_point: str = "ssh",
    ) -> SSHCertInfo:
        """Sign an SSH public key.

        Args:
            role: SSH role name.
            public_key: The SSH public key to sign.
            valid_principals: Comma-separated list of principals.
            ttl: Certificate TTL.
            cert_type: "user" or "host".
            mount_point: SSH secrets engine mount point.

        Returns:
            SSHCertInfo with the signed key.
        """
        try:
            extra: dict[str, str] = {"cert_type": cert_type}
            if valid_principals:
                extra["valid_principals"] = valid_principals
            if ttl:
                extra["ttl"] = ttl

            result = self._client.secrets.ssh.sign_ssh_key(
                name=role,
                public_key=public_key,
                mount_point=mount_point,
                **extra,
            )
            data = result.get("data", {})
            self._emit(AuditEventType.SSH_SIGN, path=f"{mount_point}/sign/{role}")
            return SSHCertInfo(
                signed_key=data.get("signed_key", ""),
                serial_number=data.get("serial_number", ""),
            )
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    # ------------------------------------------------------------------
    # Transit Encrypt / Decrypt
    # ------------------------------------------------------------------

    def transit_encrypt(
        self,
        key_name: str,
        plaintext: str | bytes,
        mount_point: str = "transit",
    ) -> TransitResult:
        """Encrypt data using Vault Transit.

        Args:
            key_name: Transit key name.
            plaintext: Data to encrypt (string or bytes).
            mount_point: Transit secrets engine mount point.

        Returns:
            TransitResult with ciphertext.
        """
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode()
        else:
            plaintext_bytes = plaintext
        b64 = base64.b64encode(plaintext_bytes).decode()

        try:
            result = self._client.secrets.transit.encrypt_data(
                name=key_name,
                plaintext=b64,
                mount_point=mount_point,
            )
            data = result.get("data", {})
            self._emit(AuditEventType.TRANSIT_ENCRYPT, path=f"{mount_point}/encrypt/{key_name}")
            return TransitResult(
                ciphertext=data.get("ciphertext", ""),
                key_version=data.get("key_version", 0),
            )
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def transit_decrypt(
        self,
        key_name: str,
        ciphertext: str,
        mount_point: str = "transit",
    ) -> TransitResult:
        """Decrypt data using Vault Transit.

        Args:
            key_name: Transit key name.
            ciphertext: Vault ciphertext string (vault:v1:...).
            mount_point: Transit secrets engine mount point.

        Returns:
            TransitResult with plaintext.
        """
        try:
            result = self._client.secrets.transit.decrypt_data(
                name=key_name,
                ciphertext=ciphertext,
                mount_point=mount_point,
            )
            data = result.get("data", {})
            b64 = data.get("plaintext", "")
            decoded = base64.b64decode(b64).decode() if b64 else ""
            self._emit(AuditEventType.TRANSIT_DECRYPT, path=f"{mount_point}/decrypt/{key_name}")
            return TransitResult(plaintext=decoded)
        except hvac.exceptions.VaultError as exc:
            raise VaultConnectionError(self._addr, str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    # ------------------------------------------------------------------
    # Token Lifecycle
    # ------------------------------------------------------------------

    def token_renew(self, increment: str = "1h") -> dict[str, Any]:
        """Renew the current token.

        Args:
            increment: TTL increment (e.g., "1h", "30m").

        Returns:
            Token auth info dict from Vault.

        Raises:
            VaultLeaseError: If renewal fails.
        """
        try:
            result = self._client.auth.token.renew_self(increment=increment)
            self._emit(AuditEventType.LEASE_RENEW, detail="self-token")
            return dict(result.get("auth", {}))
        except hvac.exceptions.VaultError as exc:
            self._emit(AuditEventType.LEASE_RENEW, detail="self-token", success=False)
            raise VaultLeaseError("self", "renew", str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def token_revoke_self(self) -> None:
        """Revoke the current token."""
        try:
            self._client.auth.token.revoke_self()
            self._emit(AuditEventType.LEASE_REVOKE, detail="self-token")
        except hvac.exceptions.VaultError as exc:
            raise VaultLeaseError("self", "revoke", str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def lease_renew(self, lease_id: str, increment: int = 3600) -> LeaseInfo:
        """Renew a lease by ID.

        Args:
            lease_id: The lease ID to renew.
            increment: TTL increment in seconds.

        Returns:
            Updated LeaseInfo.
        """
        try:
            result = self._client.sys.renew_lease(
                lease_id=lease_id,
                increment=increment,
            )
            self._emit(AuditEventType.LEASE_RENEW, detail=f"lease={lease_id}")
            return LeaseInfo(
                lease_id=result.get("lease_id", lease_id),
                lease_duration=result.get("lease_duration", 0),
                renewable=result.get("renewable", False),
            )
        except hvac.exceptions.VaultError as exc:
            self._emit(AuditEventType.LEASE_RENEW, detail=f"lease={lease_id}", success=False)
            raise VaultLeaseError(lease_id, "renew", str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    def lease_revoke(self, lease_id: str) -> None:
        """Revoke a lease by ID.

        Args:
            lease_id: The lease ID to revoke.
        """
        try:
            self._client.sys.revoke_lease(lease_id=lease_id)
            self._emit(AuditEventType.LEASE_REVOKE, detail=f"lease={lease_id}")
        except hvac.exceptions.VaultError as exc:
            raise VaultLeaseError(lease_id, "revoke", str(exc))
        except Exception as exc:
            raise VaultConnectionError(self._addr, str(exc))

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> HealthReport:
        """Check Vault health, seal status, and auth validity.

        Returns:
            HealthReport with individual check results.
        """
        checks: list[HealthCheck] = []
        # Connectivity check
        t0 = time.monotonic()
        try:
            status = self._client.sys.read_health_status(method="GET")
            latency = (time.monotonic() - t0) * 1000
            if isinstance(status, dict):
                initialized = status.get("initialized", False)
                sealed = status.get("sealed", True)
                if initialized and not sealed:
                    checks.append(
                        HealthCheck(
                            name="vault_connectivity",
                            status=HealthStatus.HEALTHY,
                            detail=f"Vault at {self._addr} is initialized and unsealed",
                            latency_ms=latency,
                        )
                    )
                elif sealed:
                    checks.append(
                        HealthCheck(
                            name="vault_connectivity",
                            status=HealthStatus.UNHEALTHY,
                            detail="Vault is sealed",
                            latency_ms=latency,
                        )
                    )
                else:
                    checks.append(
                        HealthCheck(
                            name="vault_connectivity",
                            status=HealthStatus.DEGRADED,
                            detail="Vault is not initialized",
                            latency_ms=latency,
                        )
                    )
            else:
                # status may be a Response object for non-200 codes
                checks.append(
                    HealthCheck(
                        name="vault_connectivity",
                        status=HealthStatus.DEGRADED,
                        detail=f"Unexpected response type: {type(status).__name__}",
                        latency_ms=latency,
                    )
                )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            checks.append(
                HealthCheck(
                    name="vault_connectivity",
                    status=HealthStatus.UNHEALTHY,
                    detail=str(exc),
                    latency_ms=latency,
                )
            )

        # Auth check
        try:
            if self._client.is_authenticated():
                checks.append(
                    HealthCheck(
                        name="vault_auth",
                        status=HealthStatus.HEALTHY,
                        detail="Token is valid",
                    )
                )
            else:
                checks.append(
                    HealthCheck(
                        name="vault_auth",
                        status=HealthStatus.UNHEALTHY,
                        detail="Token is invalid or expired",
                    )
                )
        except Exception as exc:
            checks.append(
                HealthCheck(
                    name="vault_auth",
                    status=HealthStatus.UNHEALTHY,
                    detail=str(exc),
                )
            )

        return HealthReport(checks=checks)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit(
        self,
        event_type: AuditEventType,
        path: str = "",
        detail: str = "",
        success: bool = True,
    ) -> None:
        """Emit an audit event."""
        event = AuditEvent(
            event_type=event_type,
            path=path,
            success=success,
            detail=detail,
        )
        self._audit_events.append(event)
        logger.debug(event.as_log_line())
