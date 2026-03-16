"""SecretsMesh orchestrator — multi-provider secret access with fallback, caching, and audit.

The mesh registers multiple SecretProviders with priority ordering and
provides a unified interface for secret access. Features:
- Priority-based provider ordering
- Fallback chains (try provider A, fall back to B, C, ...)
- Read-through TTL caching
- Provider health monitoring
- Audit logging of all secret access
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from secrets_sdk.mesh.cache import TTLCache
from secrets_sdk.mesh.provider import (
    ProviderHealth,
    ProviderStatus,
    SecretProvider,
    SecretValue,
)

logger = logging.getLogger(__name__)


class MeshAuditEntry(BaseModel):
    """Audit log entry for mesh operations."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    operation: str
    key: str = ""
    provider: str = ""
    success: bool = True
    cached: bool = False
    latency_ms: float = 0.0
    detail: str = ""
    fallback_chain: list[str] = Field(default_factory=list)

    def as_log_line(self) -> str:
        """Format as a structured log line."""
        status = "OK" if self.success else "FAIL"
        ts = self.timestamp.isoformat()
        parts = [
            f"ts={ts}",
            f"op={self.operation}",
            f"status={status}",
        ]
        if self.key:
            parts.append(f"key={self.key}")
        if self.provider:
            parts.append(f"provider={self.provider}")
        if self.cached:
            parts.append("cached=true")
        if self.latency_ms > 0:
            parts.append(f"latency_ms={self.latency_ms:.1f}")
        if self.fallback_chain:
            parts.append(f"chain={','.join(self.fallback_chain)}")
        if self.detail:
            parts.append(f"detail={self.detail}")
        return " ".join(parts)


class _RegisteredProvider:
    """Internal wrapper for a registered provider with priority."""

    __slots__ = ("provider", "priority", "enabled")

    def __init__(self, provider: SecretProvider, priority: int) -> None:
        self.provider = provider
        self.priority = priority
        self.enabled = True


class MeshStatus(BaseModel):
    """Overall mesh status report."""

    providers: list[ProviderHealth] = Field(default_factory=list)
    cache_stats: dict[str, float | int] = Field(default_factory=dict)
    audit_count: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def overall_status(self) -> ProviderStatus:
        """Derive overall status from provider health checks."""
        if not self.providers:
            return ProviderStatus.UNKNOWN
        statuses = {p.status for p in self.providers}
        if all(s == ProviderStatus.HEALTHY for s in statuses):
            return ProviderStatus.HEALTHY
        if ProviderStatus.UNHEALTHY in statuses:
            healthy_count = sum(1 for s in statuses if s == ProviderStatus.HEALTHY)
            if healthy_count > 0:
                return ProviderStatus.DEGRADED
            return ProviderStatus.UNHEALTHY
        return ProviderStatus.DEGRADED

    def summary(self) -> str:
        """One-line summary of mesh status."""
        overall = self.overall_status.value.upper()
        parts = [f"{p.provider_name}:{p.status.value}" for p in self.providers]
        return f"[{overall}] " + " | ".join(parts)


class SecretsMesh:
    """Multi-provider secret access orchestrator.

    Registers providers with priority ordering (lower number = higher
    priority). On get_secret, tries providers in priority order with
    fallback. Supports read-through caching with configurable TTL.

    Args:
        cache_ttl: Default TTL in seconds for cached secrets. 0 disables caching.
        cache_max_size: Maximum number of cached entries.
        audit_max_size: Maximum audit log entries to retain (0 = unlimited).
    """

    def __init__(
        self,
        cache_ttl: float = 300.0,
        cache_max_size: int = 1000,
        audit_max_size: int = 10000,
    ) -> None:
        self._providers: list[_RegisteredProvider] = []
        self._cache: TTLCache[SecretValue] | None = None
        self._cache_ttl = cache_ttl
        if cache_ttl > 0:
            self._cache = TTLCache(default_ttl=cache_ttl, max_size=cache_max_size)
        self._audit_log: list[MeshAuditEntry] = []
        self._audit_max_size = audit_max_size

    @property
    def providers(self) -> list[SecretProvider]:
        """Return registered providers sorted by priority."""
        return [rp.provider for rp in self._sorted_providers()]

    @property
    def provider_names(self) -> list[str]:
        """Return registered provider names sorted by priority."""
        return [rp.provider.name for rp in self._sorted_providers()]

    @property
    def audit_log(self) -> list[MeshAuditEntry]:
        """Return the audit log (copy)."""
        return list(self._audit_log)

    @property
    def cache(self) -> TTLCache[SecretValue] | None:
        """Access the underlying cache instance."""
        return self._cache

    def _sorted_providers(self) -> list[_RegisteredProvider]:
        """Return providers sorted by priority (lower = higher priority)."""
        return sorted(
            [rp for rp in self._providers if rp.enabled],
            key=lambda rp: rp.priority,
        )

    def register(self, provider: SecretProvider, priority: int = 100) -> None:
        """Register a secret provider with a priority.

        Args:
            provider: The SecretProvider to register.
            priority: Priority ordering (lower = tried first). Default 100.

        Raises:
            ValueError: If a provider with the same name is already registered.
        """
        existing_names = {rp.provider.name for rp in self._providers}
        if provider.name in existing_names:
            raise ValueError(f"Provider '{provider.name}' is already registered")
        self._providers.append(_RegisteredProvider(provider, priority))
        logger.info("Registered provider '%s' with priority %d", provider.name, priority)

    def unregister(self, name: str) -> bool:
        """Remove a provider by name. Returns True if found and removed."""
        for i, rp in enumerate(self._providers):
            if rp.provider.name == name:
                self._providers.pop(i)
                logger.info("Unregistered provider '%s'", name)
                return True
        return False

    def enable_provider(self, name: str) -> bool:
        """Enable a disabled provider. Returns True if found."""
        for rp in self._providers:
            if rp.provider.name == name:
                rp.enabled = True
                return True
        return False

    def disable_provider(self, name: str) -> bool:
        """Disable a provider (skip during fallback). Returns True if found."""
        for rp in self._providers:
            if rp.provider.name == name:
                rp.enabled = False
                return True
        return False

    def get_secret(self, key: str, skip_cache: bool = False) -> SecretValue:
        """Retrieve a secret using the fallback chain.

        Tries each enabled provider in priority order. If caching is
        enabled and the secret is cached, returns the cached value
        (unless skip_cache is True).

        Args:
            key: The secret key to retrieve.
            skip_cache: If True, bypass the cache and fetch from providers.

        Returns:
            SecretValue from the first provider that has the secret.

        Raises:
            KeyError: If no provider has the secret.
        """
        t0 = time.monotonic()

        # Check cache first
        if self._cache is not None and not skip_cache:
            cached = self._cache.get(key)
            if cached is not None:
                latency = (time.monotonic() - t0) * 1000
                cached_copy = cached.model_copy(update={"cached": True})
                self._emit_audit(
                    operation="get_secret",
                    key=key,
                    provider=cached.provider,
                    cached=True,
                    latency_ms=latency,
                )
                return cached_copy

        # Fallback chain
        sorted_providers = self._sorted_providers()
        if not sorted_providers:
            self._emit_audit(
                operation="get_secret",
                key=key,
                success=False,
                detail="No providers registered",
                latency_ms=(time.monotonic() - t0) * 1000,
            )
            raise KeyError(f"No providers registered in mesh for key: {key}")

        errors: list[str] = []
        chain: list[str] = []

        for rp in sorted_providers:
            chain.append(rp.provider.name)
            try:
                result = rp.provider.get_secret(key)
                latency = (time.monotonic() - t0) * 1000

                # Cache the result
                if self._cache is not None:
                    self._cache.put(key, result)

                self._emit_audit(
                    operation="get_secret",
                    key=key,
                    provider=rp.provider.name,
                    latency_ms=latency,
                    fallback_chain=chain,
                )
                return result
            except (KeyError, ConnectionError, Exception) as exc:
                errors.append(f"{rp.provider.name}: {exc}")
                logger.debug(
                    "Provider '%s' failed for key '%s': %s",
                    rp.provider.name,
                    key,
                    exc,
                )
                continue

        latency = (time.monotonic() - t0) * 1000
        detail = "; ".join(errors)
        self._emit_audit(
            operation="get_secret",
            key=key,
            success=False,
            latency_ms=latency,
            detail=f"All providers failed: {detail}",
            fallback_chain=chain,
        )
        raise KeyError(f"Secret '{key}' not found in any provider. Errors: {detail}")

    def put_secret(
        self,
        key: str,
        value: str,
        provider_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a secret in a specific provider or the highest-priority writable one.

        Args:
            key: The secret key.
            value: The secret value.
            provider_name: Target provider name. If None, uses first writable provider.
            metadata: Optional metadata to associate.

        Raises:
            KeyError: If the specified provider is not registered.
            PermissionError: If no writable provider is available.
        """
        t0 = time.monotonic()

        if provider_name:
            provider = self._get_provider(provider_name)
            try:
                provider.put_secret(key, value, metadata)
                # Invalidate cache
                if self._cache is not None:
                    self._cache.invalidate(key)
                self._emit_audit(
                    operation="put_secret",
                    key=key,
                    provider=provider_name,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
                return
            except PermissionError:
                raise
            except Exception as exc:
                raise ConnectionError(f"Failed to write to {provider_name}: {exc}") from exc

        # Try writable providers in priority order
        for rp in self._sorted_providers():
            try:
                rp.provider.put_secret(key, value, metadata)
                if self._cache is not None:
                    self._cache.invalidate(key)
                self._emit_audit(
                    operation="put_secret",
                    key=key,
                    provider=rp.provider.name,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
                return
            except PermissionError:
                continue
            except Exception as exc:
                logger.debug("put_secret failed on %s: %s", rp.provider.name, exc)
                continue

        self._emit_audit(
            operation="put_secret",
            key=key,
            success=False,
            detail="No writable provider available",
            latency_ms=(time.monotonic() - t0) * 1000,
        )
        raise PermissionError("No writable provider available in mesh")

    def delete_secret(self, key: str, provider_name: str | None = None) -> bool:
        """Delete a secret from a specific or first-available provider.

        Args:
            key: The secret key.
            provider_name: Target provider. If None, tries all.

        Returns:
            True if deleted from any provider.
        """
        t0 = time.monotonic()

        if provider_name:
            provider = self._get_provider(provider_name)
            try:
                result = provider.delete_secret(key)
                if self._cache is not None:
                    self._cache.invalidate(key)
                self._emit_audit(
                    operation="delete_secret",
                    key=key,
                    provider=provider_name,
                    success=result,
                    latency_ms=(time.monotonic() - t0) * 1000,
                )
                return result
            except PermissionError:
                raise
            except Exception as exc:
                raise ConnectionError(f"Failed to delete from {provider_name}: {exc}") from exc

        deleted = False
        for rp in self._sorted_providers():
            try:
                if rp.provider.delete_secret(key):
                    deleted = True
            except (PermissionError, Exception):
                continue

        if self._cache is not None:
            self._cache.invalidate(key)

        self._emit_audit(
            operation="delete_secret",
            key=key,
            success=deleted,
            latency_ms=(time.monotonic() - t0) * 1000,
        )
        return deleted

    def list_secrets(self, prefix: str = "", provider_name: str | None = None) -> list[str]:
        """List secrets, optionally from a specific provider.

        If no provider is specified, aggregates keys from all providers.
        """
        t0 = time.monotonic()

        if provider_name:
            provider = self._get_provider(provider_name)
            keys = provider.list_secrets(prefix)
            self._emit_audit(
                operation="list_secrets",
                provider=provider_name,
                latency_ms=(time.monotonic() - t0) * 1000,
            )
            return keys

        all_keys: set[str] = set()
        for rp in self._sorted_providers():
            try:
                keys = rp.provider.list_secrets(prefix)
                all_keys.update(keys)
            except Exception as exc:
                logger.debug("list_secrets failed on %s: %s", rp.provider.name, exc)

        self._emit_audit(
            operation="list_secrets",
            latency_ms=(time.monotonic() - t0) * 1000,
        )
        return sorted(all_keys)

    def health_check(self) -> MeshStatus:
        """Run health checks on all registered providers.

        Returns:
            MeshStatus with per-provider health and cache statistics.
        """
        provider_health: list[ProviderHealth] = []
        for rp in self._providers:
            try:
                health = rp.provider.health_check()
                if not rp.enabled:
                    health.detail = f"[DISABLED] {health.detail}"
                provider_health.append(health)
            except Exception as exc:
                provider_health.append(
                    ProviderHealth(
                        provider_name=rp.provider.name,
                        status=ProviderStatus.UNHEALTHY,
                        detail=f"Health check error: {exc}",
                    )
                )

        cache_stats: dict[str, float | int] = {}
        if self._cache is not None:
            cache_stats = self._cache.stats()

        self._emit_audit(operation="health_check")

        return MeshStatus(
            providers=provider_health,
            cache_stats=cache_stats,
            audit_count=len(self._audit_log),
        )

    def invalidate_cache(self, key: str | None = None) -> None:
        """Invalidate cached secrets.

        Args:
            key: Specific key to invalidate. If None, clears entire cache.
        """
        if self._cache is None:
            return
        if key:
            self._cache.invalidate(key)
        else:
            self._cache.clear()

    def _get_provider(self, name: str) -> SecretProvider:
        """Look up a provider by name.

        Raises:
            KeyError: If the provider is not registered.
        """
        for rp in self._providers:
            if rp.provider.name == name:
                return rp.provider
        raise KeyError(f"Provider '{name}' is not registered")

    def _emit_audit(
        self,
        operation: str,
        key: str = "",
        provider: str = "",
        success: bool = True,
        cached: bool = False,
        latency_ms: float = 0.0,
        detail: str = "",
        fallback_chain: list[str] | None = None,
    ) -> None:
        """Record an audit log entry."""
        entry = MeshAuditEntry(
            operation=operation,
            key=key,
            provider=provider,
            success=success,
            cached=cached,
            latency_ms=latency_ms,
            detail=detail,
            fallback_chain=fallback_chain or [],
        )
        self._audit_log.append(entry)
        logger.debug(entry.as_log_line())

        # Trim audit log if needed
        if self._audit_max_size > 0 and len(self._audit_log) > self._audit_max_size:
            excess = len(self._audit_log) - self._audit_max_size
            self._audit_log = self._audit_log[excess:]
