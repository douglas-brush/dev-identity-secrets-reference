"""Environment variable provider for the Secrets Mesh.

Reads secrets from environment variables with configurable prefix mapping.
Intended for local development where secrets are injected as env vars
(e.g., from .env files, docker-compose, or CI pipelines).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from secrets_sdk.mesh.provider import (
    ProviderHealth,
    ProviderStatus,
    SecretProvider,
    SecretValue,
)

logger = logging.getLogger(__name__)


class EnvProvider(SecretProvider):
    """Secret provider backed by environment variables.

    Keys are mapped to env var names by uppercasing, replacing
    path separators with underscores, and prepending the configured
    prefix. For example, with prefix="APP":
        get_secret("db/password") -> reads APP_DB_PASSWORD

    Args:
        prefix: Environment variable prefix (e.g., "APP", "MYSERVICE").
            If empty, keys are used as-is after normalization.
        separator: Character used to join prefix and key segments.
            Defaults to "_".
        env_override: Optional dict to use instead of os.environ.
            Useful for testing.
    """

    def __init__(
        self,
        prefix: str = "",
        separator: str = "_",
        env_override: dict[str, str] | None = None,
    ) -> None:
        self._prefix = prefix.upper()
        self._separator = separator
        self._env = env_override

    @property
    def name(self) -> str:
        return "env"

    @property
    def _environ(self) -> dict[str, str]:
        """Resolve the environment dict."""
        if self._env is not None:
            return self._env
        return dict(os.environ)

    def _normalize_key(self, key: str) -> str:
        """Convert a secret key to an env var name.

        Replaces / and . with separator, uppercases everything,
        and prepends the prefix.
        """
        normalized = key.replace("/", self._separator).replace(".", self._separator).replace("-", self._separator)
        normalized = normalized.upper()
        if self._prefix:
            return f"{self._prefix}{self._separator}{normalized}"
        return normalized

    def get_secret(self, key: str) -> SecretValue:
        """Read a secret from environment variables.

        Raises:
            KeyError: If the env var does not exist.
        """
        env_key = self._normalize_key(key)
        env = self._environ
        if env_key not in env:
            raise KeyError(f"Environment variable not found: {env_key}")

        return SecretValue(
            key=key,
            value=env[env_key],
            provider=self.name,
            metadata={"env_var": env_key},
        )

    def put_secret(self, key: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        """Set an environment variable.

        Only modifies the override dict or os.environ for the current process.
        Changes do not persist beyond process lifetime.
        """
        env_key = self._normalize_key(key)
        if self._env is not None:
            self._env[env_key] = value
        else:
            os.environ[env_key] = value

    def delete_secret(self, key: str) -> bool:
        """Remove an environment variable.

        Returns True if the variable existed and was removed.
        """
        env_key = self._normalize_key(key)
        if self._env is not None:
            if env_key in self._env:
                del self._env[env_key]
                return True
            return False
        else:
            if env_key in os.environ:
                del os.environ[env_key]
                return True
            return False

    def list_secrets(self, prefix: str = "") -> list[str]:
        """List env var names matching the provider prefix.

        Returns the raw env var names (not reverse-mapped to keys).
        If a sub-prefix is provided, additionally filters by that.
        """
        env = self._environ
        full_prefix = self._prefix
        if prefix:
            search_prefix = self._normalize_key(prefix)
        elif full_prefix:
            search_prefix = full_prefix + self._separator
        else:
            search_prefix = ""

        if search_prefix:
            return sorted(k for k in env if k.startswith(search_prefix))
        return sorted(env.keys())

    def health_check(self) -> ProviderHealth:
        """Environment provider is always healthy if env is accessible."""
        t0 = time.monotonic()
        try:
            env = self._environ
            latency = (time.monotonic() - t0) * 1000
            matching = sum(1 for k in env if self._prefix and k.startswith(self._prefix))
            detail = f"{matching} vars with prefix '{self._prefix}'" if self._prefix else f"{len(env)} total vars"
            return ProviderHealth(
                provider_name=self.name,
                status=ProviderStatus.HEALTHY,
                latency_ms=latency,
                detail=detail,
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ProviderHealth(
                provider_name=self.name,
                status=ProviderStatus.UNHEALTHY,
                latency_ms=latency,
                detail=str(exc),
            )
