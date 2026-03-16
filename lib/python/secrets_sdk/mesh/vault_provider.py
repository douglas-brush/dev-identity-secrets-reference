"""Vault implementation of SecretProvider.

Wraps the existing VaultClient to conform to the SecretProvider interface,
enabling Vault as a backend in the Secrets Mesh.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from secrets_sdk.exceptions import VaultConnectionError, VaultSecretNotFound
from secrets_sdk.mesh.provider import (
    ProviderHealth,
    ProviderStatus,
    SecretProvider,
    SecretValue,
)
from secrets_sdk.vault import VaultClient

logger = logging.getLogger(__name__)


class VaultProvider(SecretProvider):
    """Secret provider backed by HashiCorp Vault KV v2.

    Args:
        vault_client: An authenticated VaultClient instance.
        prefix: Optional path prefix prepended to all key lookups.
            For example, prefix="app/config" means get_secret("db_pass")
            reads from "app/config/db_pass".
        value_key: The key within the KV data dict that holds the secret
            value. Defaults to "value". If the secret is stored as
            {"value": "s3cret"}, this extracts "s3cret".
    """

    def __init__(
        self,
        vault_client: VaultClient,
        prefix: str = "",
        value_key: str = "value",
    ) -> None:
        self._client = vault_client
        self._prefix = prefix.strip("/")
        self._value_key = value_key

    @property
    def name(self) -> str:
        return "vault"

    def _resolve_path(self, key: str) -> str:
        """Build the full Vault KV path from prefix + key."""
        if self._prefix:
            return f"{self._prefix}/{key}"
        return key

    def get_secret(self, key: str) -> SecretValue:
        """Read a secret from Vault KV v2.

        Raises:
            KeyError: If the secret path does not exist.
            ConnectionError: If Vault is unreachable.
        """
        path = self._resolve_path(key)
        try:
            data = self._client.kv_read(path)
        except VaultSecretNotFound:
            raise KeyError(f"Secret not found in Vault: {path}")
        except VaultConnectionError as exc:
            raise ConnectionError(str(exc)) from exc

        # Extract the value — if value_key exists use it, otherwise serialize all data
        if self._value_key in data:
            value = str(data[self._value_key])
        else:
            # Return the full data dict as a JSON string
            import json

            value = json.dumps(data)

        return SecretValue(
            key=key,
            value=value,
            provider=self.name,
            metadata={"path": path, "keys": list(data.keys())},
        )

    def put_secret(self, key: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        """Write a secret to Vault KV v2.

        Raises:
            ConnectionError: If Vault is unreachable.
        """
        path = self._resolve_path(key)
        data: dict[str, Any] = {self._value_key: value}
        if metadata:
            data.update(metadata)
        try:
            self._client.kv_write(path, data)
        except VaultConnectionError as exc:
            raise ConnectionError(str(exc)) from exc

    def delete_secret(self, key: str) -> bool:
        """Delete a secret from Vault KV v2.

        Uses kv_write with empty data to soft-delete (Vault KV v2
        versioned delete). Returns True if the path existed.

        Raises:
            ConnectionError: If Vault is unreachable.
        """
        path = self._resolve_path(key)
        try:
            # Verify it exists first
            self._client.kv_read(path)
        except VaultSecretNotFound:
            return False
        except VaultConnectionError as exc:
            raise ConnectionError(str(exc)) from exc

        try:
            # Use the underlying client for delete
            self._client.client.secrets.kv.v2.delete_latest_version_of_secret(
                path=path,
                mount_point=self._client._kv_mount,
            )
            return True
        except Exception as exc:
            raise ConnectionError(f"Failed to delete {path}: {exc}") from exc

    def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret keys at a Vault KV v2 path.

        Raises:
            ConnectionError: If Vault is unreachable.
        """
        path = self._resolve_path(prefix) if prefix else self._prefix
        try:
            return self._client.kv_list(path)
        except VaultSecretNotFound:
            return []
        except VaultConnectionError as exc:
            raise ConnectionError(str(exc)) from exc

    def health_check(self) -> ProviderHealth:
        """Check Vault health via the VaultClient health endpoint."""
        t0 = time.monotonic()
        try:
            report = self._client.health()
            latency = (time.monotonic() - t0) * 1000

            # Map VaultClient HealthStatus to ProviderStatus
            from secrets_sdk.models import HealthStatus

            status_map = {
                HealthStatus.HEALTHY: ProviderStatus.HEALTHY,
                HealthStatus.DEGRADED: ProviderStatus.DEGRADED,
                HealthStatus.UNHEALTHY: ProviderStatus.UNHEALTHY,
                HealthStatus.UNKNOWN: ProviderStatus.UNKNOWN,
            }
            provider_status = status_map.get(report.overall_status, ProviderStatus.UNKNOWN)

            return ProviderHealth(
                provider_name=self.name,
                status=provider_status,
                latency_ms=latency,
                detail=report.summary(),
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ProviderHealth(
                provider_name=self.name,
                status=ProviderStatus.UNHEALTHY,
                latency_ms=latency,
                detail=f"Health check failed: {exc}",
            )
