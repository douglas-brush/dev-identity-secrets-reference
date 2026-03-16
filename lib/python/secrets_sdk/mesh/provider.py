"""Abstract SecretProvider base class for the Secrets Mesh.

Defines the protocol that all secret providers must implement,
enabling pluggable backends (Vault, env vars, SOPS files, etc.).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ProviderStatus(str, Enum):
    """Health status of a secret provider."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ProviderHealth(BaseModel):
    """Health check result for a secret provider."""

    provider_name: str
    status: ProviderStatus = ProviderStatus.UNKNOWN
    latency_ms: float = 0.0
    detail: str = ""
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecretValue(BaseModel):
    """A secret value returned from a provider."""

    key: str
    value: str
    provider: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    cached: bool = False


class SecretProvider(ABC):
    """Abstract base class for secret providers.

    All providers must implement get_secret, put_secret, delete_secret,
    list_secrets, and health_check. Providers are registered with the
    SecretsMesh orchestrator which handles fallback chains and caching.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider name used for identification and logging."""
        ...

    @abstractmethod
    def get_secret(self, key: str) -> SecretValue:
        """Retrieve a secret by key.

        Args:
            key: The secret key/path to retrieve.

        Returns:
            SecretValue with the secret data.

        Raises:
            KeyError: If the secret does not exist.
            ConnectionError: If the provider is unreachable.
        """
        ...

    @abstractmethod
    def put_secret(self, key: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        """Store a secret.

        Args:
            key: The secret key/path.
            value: The secret value to store.
            metadata: Optional metadata to associate with the secret.

        Raises:
            ConnectionError: If the provider is unreachable.
            PermissionError: If the provider is read-only.
        """
        ...

    @abstractmethod
    def delete_secret(self, key: str) -> bool:
        """Delete a secret by key.

        Args:
            key: The secret key/path to delete.

        Returns:
            True if deleted, False if the key did not exist.

        Raises:
            ConnectionError: If the provider is unreachable.
            PermissionError: If the provider is read-only.
        """
        ...

    @abstractmethod
    def list_secrets(self, prefix: str = "") -> list[str]:
        """List secret keys, optionally filtered by prefix.

        Args:
            prefix: Key prefix to filter by (empty for all).

        Returns:
            List of secret keys matching the prefix.

        Raises:
            ConnectionError: If the provider is unreachable.
        """
        ...

    @abstractmethod
    def health_check(self) -> ProviderHealth:
        """Check the health/availability of this provider.

        Returns:
            ProviderHealth with status and latency information.
        """
        ...
