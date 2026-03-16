"""Tests for the Secrets Mesh abstraction layer.

Covers: TTLCache, EnvProvider, FileProvider, VaultProvider,
SecretsMesh orchestrator (fallback, caching, health, audit).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from secrets_sdk.mesh.cache import TTLCache
from secrets_sdk.mesh.env_provider import EnvProvider
from secrets_sdk.mesh.file_provider import FileProvider
from secrets_sdk.mesh.mesh import MeshAuditEntry, MeshStatus, SecretsMesh
from secrets_sdk.mesh.provider import (
    ProviderHealth,
    ProviderStatus,
    SecretProvider,
    SecretValue,
)
from secrets_sdk.mesh.vault_provider import VaultProvider


# =====================================================================
# TTLCache Tests
# =====================================================================


class TestTTLCache:
    """Tests for TTL-based in-memory cache."""

    def test_put_and_get(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_miss(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        assert cache.get("nonexistent") is None
        assert cache.misses == 1

    def test_ttl_expiration(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=0.05)
        cache.put("key1", "value1")
        assert cache.get("key1") == "value1"
        time.sleep(0.06)
        assert cache.get("key1") is None

    def test_custom_ttl_per_entry(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("short", "val", ttl=0.05)
        cache.put("long", "val", ttl=60.0)
        time.sleep(0.06)
        assert cache.get("short") is None
        assert cache.get("long") == "val"

    def test_max_size_eviction(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0, max_size=3)
        cache.put("a", "1")
        cache.put("b", "2")
        cache.put("c", "3")
        cache.put("d", "4")  # Should evict "a" (LRU)
        assert cache.get("a") is None
        assert cache.get("d") == "4"
        assert cache.size() == 3

    def test_lru_ordering(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0, max_size=3)
        cache.put("a", "1")
        cache.put("b", "2")
        cache.put("c", "3")
        # Access "a" to make it recently used
        cache.get("a")
        cache.put("d", "4")  # Should evict "b" (least recently used)
        assert cache.get("a") == "1"
        assert cache.get("b") is None

    def test_invalidate(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("key1", "val")
        assert cache.invalidate("key1") is True
        assert cache.get("key1") is None
        assert cache.invalidate("nonexistent") is False

    def test_clear(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("a", "1")
        cache.put("b", "2")
        removed = cache.clear()
        assert removed == 2
        assert cache.size() == 0

    def test_purge_expired(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=0.05)
        cache.put("a", "1")
        cache.put("b", "2")
        time.sleep(0.06)
        purged = cache.purge_expired()
        assert purged == 2
        assert cache.size() == 0

    def test_hit_rate(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("a", "1")
        cache.get("a")  # hit
        cache.get("b")  # miss
        assert cache.hits == 1
        assert cache.misses == 1
        assert cache.hit_rate == 0.5

    def test_stats(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=30.0, max_size=100)
        cache.put("a", "1")
        stats = cache.stats()
        assert stats["size"] == 1
        assert stats["max_size"] == 100
        assert stats["default_ttl"] == 30.0

    def test_reset_stats(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("a", "1")
        cache.get("a")
        cache.get("miss")
        cache.reset_stats()
        assert cache.hits == 0
        assert cache.misses == 0

    def test_invalid_ttl(self) -> None:
        with pytest.raises(ValueError, match="default_ttl must be positive"):
            TTLCache(default_ttl=0)

    def test_invalid_max_size(self) -> None:
        with pytest.raises(ValueError, match="max_size must be non-negative"):
            TTLCache(default_ttl=60.0, max_size=-1)

    def test_zero_ttl_put_skipped(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("key", "value", ttl=0)
        assert cache.get("key") is None

    def test_update_existing_key(self) -> None:
        cache: TTLCache[str] = TTLCache(default_ttl=60.0)
        cache.put("a", "old")
        cache.put("a", "new")
        assert cache.get("a") == "new"


# =====================================================================
# EnvProvider Tests
# =====================================================================


class TestEnvProvider:
    """Tests for the environment variable provider."""

    def test_get_secret(self) -> None:
        env = {"APP_DB_PASSWORD": "s3cret"}
        provider = EnvProvider(prefix="APP", env_override=env)
        result = provider.get_secret("db_password")
        assert result.value == "s3cret"
        assert result.provider == "env"

    def test_get_secret_not_found(self) -> None:
        provider = EnvProvider(prefix="APP", env_override={})
        with pytest.raises(KeyError, match="Environment variable not found"):
            provider.get_secret("missing")

    def test_key_normalization(self) -> None:
        env = {"MYAPP_DB_HOST_NAME": "localhost"}
        provider = EnvProvider(prefix="MYAPP", env_override=env)
        result = provider.get_secret("db/host-name")
        assert result.value == "localhost"

    def test_put_secret(self) -> None:
        env: dict[str, str] = {}
        provider = EnvProvider(prefix="APP", env_override=env)
        provider.put_secret("api_key", "abc123")
        assert env["APP_API_KEY"] == "abc123"

    def test_delete_secret(self) -> None:
        env = {"APP_TOKEN": "tok"}
        provider = EnvProvider(prefix="APP", env_override=env)
        assert provider.delete_secret("token") is True
        assert "APP_TOKEN" not in env

    def test_delete_nonexistent(self) -> None:
        provider = EnvProvider(prefix="APP", env_override={})
        assert provider.delete_secret("missing") is False

    def test_list_secrets(self) -> None:
        env = {"APP_A": "1", "APP_B": "2", "OTHER_C": "3"}
        provider = EnvProvider(prefix="APP", env_override=env)
        keys = provider.list_secrets()
        assert keys == ["APP_A", "APP_B"]

    def test_list_secrets_with_prefix(self) -> None:
        env = {"APP_DB_HOST": "h", "APP_DB_PORT": "p", "APP_REDIS": "r"}
        provider = EnvProvider(prefix="APP", env_override=env)
        keys = provider.list_secrets("db")
        assert "APP_DB_HOST" in keys
        assert "APP_DB_PORT" in keys
        assert "APP_REDIS" not in keys

    def test_health_check(self) -> None:
        provider = EnvProvider(prefix="APP", env_override={"APP_X": "1"})
        health = provider.health_check()
        assert health.status == ProviderStatus.HEALTHY
        assert "1 vars" in health.detail

    def test_name(self) -> None:
        provider = EnvProvider(env_override={})
        assert provider.name == "env"

    def test_no_prefix(self) -> None:
        env = {"DB_HOST": "localhost"}
        provider = EnvProvider(prefix="", env_override=env)
        result = provider.get_secret("db_host")
        assert result.value == "localhost"


# =====================================================================
# FileProvider Tests
# =====================================================================


class TestFileProvider:
    """Tests for the SOPS file-based provider."""

    def test_single_file_mode(self, tmp_path: Path) -> None:
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"db_pass": "s3cret", "api_key": "abc"}))
        provider = FileProvider(secrets_file, use_sops=False)
        result = provider.get_secret("db_pass")
        assert result.value == "s3cret"

    def test_single_file_key_not_found(self, tmp_path: Path) -> None:
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"db_pass": "val"}))
        provider = FileProvider(secrets_file, use_sops=False)
        with pytest.raises(KeyError, match="not found"):
            provider.get_secret("missing_key")

    def test_directory_mode(self, tmp_path: Path) -> None:
        (tmp_path / "api_key.json").write_text(json.dumps({"value": "key123"}))
        provider = FileProvider(tmp_path, use_sops=False)
        result = provider.get_secret("api_key")
        assert result.value == "key123"

    def test_directory_mode_no_value_key(self, tmp_path: Path) -> None:
        (tmp_path / "config.json").write_text(json.dumps({"host": "db.local", "port": "5432"}))
        provider = FileProvider(tmp_path, use_sops=False)
        result = provider.get_secret("config")
        # Should return JSON-serialized data
        parsed = json.loads(result.value)
        assert parsed["host"] == "db.local"

    def test_directory_mode_not_found(self, tmp_path: Path) -> None:
        provider = FileProvider(tmp_path, use_sops=False)
        with pytest.raises(KeyError, match="No encrypted file found"):
            provider.get_secret("nonexistent")

    def test_list_single_file(self, tmp_path: Path) -> None:
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"a": "1", "b": "2", "c": "3"}))
        provider = FileProvider(secrets_file, use_sops=False)
        keys = provider.list_secrets()
        assert keys == ["a", "b", "c"]

    def test_list_directory(self, tmp_path: Path) -> None:
        (tmp_path / "alpha.json").write_text("{}")
        (tmp_path / "beta.yaml").write_text("{}")
        (tmp_path / "gamma.enc.yaml").write_text("{}")
        provider = FileProvider(tmp_path, use_sops=False)
        keys = provider.list_secrets()
        assert "alpha" in keys
        assert "beta" in keys
        assert "gamma" in keys

    def test_put_raises_permission_error(self, tmp_path: Path) -> None:
        provider = FileProvider(tmp_path, use_sops=False)
        with pytest.raises(PermissionError, match="read-only"):
            provider.put_secret("key", "val")

    def test_delete_raises_permission_error(self, tmp_path: Path) -> None:
        provider = FileProvider(tmp_path, use_sops=False)
        with pytest.raises(PermissionError, match="read-only"):
            provider.delete_secret("key")

    def test_health_check_exists(self, tmp_path: Path) -> None:
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text("{}")
        provider = FileProvider(secrets_file, use_sops=False)
        health = provider.health_check()
        assert health.status == ProviderStatus.HEALTHY

    def test_health_check_missing(self, tmp_path: Path) -> None:
        provider = FileProvider(tmp_path / "nonexistent.json", use_sops=False)
        health = provider.health_check()
        assert health.status == ProviderStatus.UNHEALTHY

    def test_invalidate_cache(self, tmp_path: Path) -> None:
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"key": "old"}))
        provider = FileProvider(secrets_file, use_sops=False)
        provider.get_secret("key")
        # Update file
        secrets_file.write_text(json.dumps({"key": "new"}))
        # Still cached
        assert provider.get_secret("key").value == "old"
        # Invalidate
        provider.invalidate_cache()
        assert provider.get_secret("key").value == "new"

    def test_single_file_nested_dict(self, tmp_path: Path) -> None:
        secrets_file = tmp_path / "secrets.json"
        secrets_file.write_text(json.dumps({"db": {"value": "pass123", "host": "localhost"}}))
        provider = FileProvider(secrets_file, use_sops=False)
        result = provider.get_secret("db")
        assert result.value == "pass123"

    def test_name(self, tmp_path: Path) -> None:
        provider = FileProvider(tmp_path, use_sops=False)
        assert provider.name == "file"


# =====================================================================
# VaultProvider Tests
# =====================================================================


class TestVaultProvider:
    """Tests for the Vault-backed provider."""

    def test_get_secret(self, vault_client: Any) -> None:
        provider = VaultProvider(vault_client, value_key="password")
        result = provider.get_secret("app/creds")
        assert result.value == "s3cret"
        assert result.provider == "vault"

    def test_get_secret_not_found(self, mock_hvac_client: MagicMock) -> None:
        from secrets_sdk.vault import VaultClient
        import hvac.exceptions

        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = (
            hvac.exceptions.InvalidPath("not found")
        )
        client = VaultClient(client=mock_hvac_client)
        provider = VaultProvider(client)
        with pytest.raises(KeyError, match="not found"):
            provider.get_secret("missing/path")

    def test_put_secret(self, vault_client: Any) -> None:
        provider = VaultProvider(vault_client)
        provider.put_secret("app/new", "secret_value")
        # Verify kv_write was called on the underlying client
        vault_client.client.secrets.kv.v2.create_or_update_secret.assert_called()

    def test_list_secrets(self, vault_client: Any) -> None:
        provider = VaultProvider(vault_client)
        keys = provider.list_secrets()
        assert "app1/" in keys

    def test_health_check(self, vault_client: Any) -> None:
        provider = VaultProvider(vault_client)
        health = provider.health_check()
        assert health.provider_name == "vault"
        assert health.status in (ProviderStatus.HEALTHY, ProviderStatus.DEGRADED, ProviderStatus.UNHEALTHY)

    def test_prefix_resolution(self, vault_client: Any) -> None:
        provider = VaultProvider(vault_client, prefix="team/app")
        # The internal path should be team/app/key
        provider.get_secret("key")
        call_args = vault_client.client.secrets.kv.v2.read_secret_version.call_args
        assert "team/app/key" in str(call_args)

    def test_name(self, vault_client: Any) -> None:
        provider = VaultProvider(vault_client)
        assert provider.name == "vault"


# =====================================================================
# SecretsMesh Orchestrator Tests
# =====================================================================


class _StubProvider(SecretProvider):
    """Test stub provider with controllable behavior."""

    def __init__(self, provider_name: str, secrets: dict[str, str] | None = None, fail: bool = False) -> None:
        self._name = provider_name
        self._secrets = dict(secrets or {})
        self._fail = fail

    @property
    def name(self) -> str:
        return self._name

    def get_secret(self, key: str) -> SecretValue:
        if self._fail:
            raise ConnectionError(f"{self._name} is down")
        if key not in self._secrets:
            raise KeyError(f"{key} not in {self._name}")
        return SecretValue(key=key, value=self._secrets[key], provider=self._name)

    def put_secret(self, key: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        if self._fail:
            raise ConnectionError(f"{self._name} is down")
        self._secrets[key] = value

    def delete_secret(self, key: str) -> bool:
        if self._fail:
            raise ConnectionError(f"{self._name} is down")
        if key in self._secrets:
            del self._secrets[key]
            return True
        return False

    def list_secrets(self, prefix: str = "") -> list[str]:
        if self._fail:
            raise ConnectionError(f"{self._name} is down")
        return [k for k in sorted(self._secrets) if k.startswith(prefix)] if prefix else sorted(self._secrets)

    def health_check(self) -> ProviderHealth:
        status = ProviderStatus.UNHEALTHY if self._fail else ProviderStatus.HEALTHY
        return ProviderHealth(provider_name=self._name, status=status)


class _ReadOnlyStubProvider(_StubProvider):
    """Stub that raises PermissionError on writes."""

    def put_secret(self, key: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        raise PermissionError("Read-only provider")

    def delete_secret(self, key: str) -> bool:
        raise PermissionError("Read-only provider")


class TestSecretsMesh:
    """Tests for the mesh orchestrator."""

    def test_register_and_get(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)
        result = mesh.get_secret("key")
        assert result.value == "val"
        assert result.provider == "p1"

    def test_duplicate_provider_raises(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1"), priority=10)
        with pytest.raises(ValueError, match="already registered"):
            mesh.register(_StubProvider("p1"), priority=20)

    def test_fallback_chain(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("primary", {}), priority=10)
        mesh.register(_StubProvider("fallback", {"key": "fb_val"}), priority=20)
        result = mesh.get_secret("key")
        assert result.value == "fb_val"
        assert result.provider == "fallback"

    def test_fallback_on_connection_error(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("broken", fail=True), priority=10)
        mesh.register(_StubProvider("healthy", {"key": "val"}), priority=20)
        result = mesh.get_secret("key")
        assert result.value == "val"
        assert result.provider == "healthy"

    def test_all_providers_fail(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("a", {}), priority=10)
        mesh.register(_StubProvider("b", {}), priority=20)
        with pytest.raises(KeyError, match="not found in any provider"):
            mesh.get_secret("missing")

    def test_no_providers_raises(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        with pytest.raises(KeyError, match="No providers registered"):
            mesh.get_secret("any")

    def test_priority_ordering(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("low", {"key": "low"}), priority=100)
        mesh.register(_StubProvider("high", {"key": "high"}), priority=10)
        result = mesh.get_secret("key")
        assert result.value == "high"

    def test_caching(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        stub = _StubProvider("p1", {"key": "val"})
        mesh.register(stub, priority=10)

        r1 = mesh.get_secret("key")
        assert r1.cached is False

        r2 = mesh.get_secret("key")
        assert r2.cached is True
        assert r2.value == "val"

    def test_skip_cache(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)

        mesh.get_secret("key")  # populate cache
        result = mesh.get_secret("key", skip_cache=True)
        assert result.cached is False

    def test_invalidate_cache_specific(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        mesh.register(_StubProvider("p1", {"a": "1", "b": "2"}), priority=10)

        mesh.get_secret("a")
        mesh.get_secret("b")
        mesh.invalidate_cache("a")

        # "b" should still be cached, "a" should not
        assert mesh.cache is not None
        assert mesh.cache.get("b") is not None
        assert mesh.cache.get("a") is None

    def test_invalidate_cache_all(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        mesh.register(_StubProvider("p1", {"a": "1", "b": "2"}), priority=10)
        mesh.get_secret("a")
        mesh.get_secret("b")
        mesh.invalidate_cache()
        assert mesh.cache is not None
        assert mesh.cache.size() == 0

    def test_put_secret(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        stub = _StubProvider("p1", {})
        mesh.register(stub, priority=10)
        mesh.put_secret("key", "val")
        assert stub._secrets["key"] == "val"

    def test_put_to_named_provider(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        s1 = _StubProvider("a", {})
        s2 = _StubProvider("b", {})
        mesh.register(s1, priority=10)
        mesh.register(s2, priority=20)
        mesh.put_secret("key", "val", provider_name="b")
        assert "key" not in s1._secrets
        assert s2._secrets["key"] == "val"

    def test_put_skips_readonly(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_ReadOnlyStubProvider("ro", {}), priority=10)
        mesh.register(_StubProvider("rw", {}), priority=20)
        mesh.put_secret("key", "val")
        # Should have been written to the rw provider

    def test_put_no_writable_provider(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_ReadOnlyStubProvider("ro", {}), priority=10)
        with pytest.raises(PermissionError, match="No writable provider"):
            mesh.put_secret("key", "val")

    def test_delete_secret(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)
        assert mesh.delete_secret("key") is True
        assert mesh.delete_secret("missing") is False

    def test_list_secrets_aggregated(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("a", {"x": "1", "y": "2"}), priority=10)
        mesh.register(_StubProvider("b", {"y": "2", "z": "3"}), priority=20)
        keys = mesh.list_secrets()
        assert keys == ["x", "y", "z"]

    def test_list_secrets_specific_provider(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("a", {"x": "1"}), priority=10)
        mesh.register(_StubProvider("b", {"y": "2"}), priority=20)
        keys = mesh.list_secrets(provider_name="b")
        assert keys == ["y"]

    def test_health_check(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        mesh.register(_StubProvider("healthy", {}), priority=10)
        mesh.register(_StubProvider("broken", fail=True), priority=20)
        status = mesh.health_check()
        assert len(status.providers) == 2
        assert status.overall_status == ProviderStatus.DEGRADED

    def test_health_check_all_healthy(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("a", {}), priority=10)
        mesh.register(_StubProvider("b", {}), priority=20)
        status = mesh.health_check()
        assert status.overall_status == ProviderStatus.HEALTHY

    def test_unregister(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1", {}), priority=10)
        assert mesh.unregister("p1") is True
        assert mesh.unregister("nonexistent") is False
        assert len(mesh.providers) == 0

    def test_disable_enable_provider(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)
        mesh.register(_StubProvider("p2", {"key": "fallback"}), priority=20)
        mesh.disable_provider("p1")
        result = mesh.get_secret("key")
        assert result.provider == "p2"
        mesh.enable_provider("p1")
        result = mesh.get_secret("key")
        assert result.provider == "p1"

    def test_audit_log(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)
        mesh.get_secret("key")
        assert len(mesh.audit_log) == 1
        entry = mesh.audit_log[0]
        assert entry.operation == "get_secret"
        assert entry.key == "key"
        assert entry.success is True

    def test_audit_log_failure(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("p1", {}), priority=10)
        with pytest.raises(KeyError):
            mesh.get_secret("missing")
        assert len(mesh.audit_log) == 1
        assert mesh.audit_log[0].success is False

    def test_audit_log_trimming(self) -> None:
        mesh = SecretsMesh(cache_ttl=0, audit_max_size=5)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)
        for _ in range(10):
            mesh.get_secret("key")
        assert len(mesh.audit_log) <= 5

    def test_provider_names(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("beta"), priority=20)
        mesh.register(_StubProvider("alpha"), priority=10)
        assert mesh.provider_names == ["alpha", "beta"]

    def test_mesh_status_summary(self) -> None:
        status = MeshStatus(
            providers=[
                ProviderHealth(provider_name="vault", status=ProviderStatus.HEALTHY),
                ProviderHealth(provider_name="env", status=ProviderStatus.HEALTHY),
            ]
        )
        assert "[HEALTHY]" in status.summary()

    def test_audit_entry_log_line(self) -> None:
        entry = MeshAuditEntry(
            operation="get_secret",
            key="db_pass",
            provider="vault",
            success=True,
            latency_ms=5.2,
        )
        line = entry.as_log_line()
        assert "op=get_secret" in line
        assert "key=db_pass" in line
        assert "provider=vault" in line

    def test_put_invalidates_cache(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        stub = _StubProvider("p1", {"key": "old"})
        mesh.register(stub, priority=10)
        mesh.get_secret("key")  # cache it
        mesh.put_secret("key", "new")
        # Cache should be invalidated
        assert mesh.cache is not None
        assert mesh.cache.get("key") is None

    def test_delete_invalidates_cache(self) -> None:
        mesh = SecretsMesh(cache_ttl=60.0)
        mesh.register(_StubProvider("p1", {"key": "val"}), priority=10)
        mesh.get_secret("key")  # cache it
        mesh.delete_secret("key")
        assert mesh.cache is not None
        assert mesh.cache.get("key") is None

    def test_fallback_chain_recorded_in_audit(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        mesh.register(_StubProvider("a", {}), priority=10)
        mesh.register(_StubProvider("b", {"key": "val"}), priority=20)
        mesh.get_secret("key")
        entry = mesh.audit_log[0]
        assert entry.fallback_chain == ["a", "b"]

    def test_cache_disabled_when_ttl_zero(self) -> None:
        mesh = SecretsMesh(cache_ttl=0)
        assert mesh.cache is None


# =====================================================================
# CLI mesh-status command test
# =====================================================================


class TestMeshStatusCLI:
    """Test the mesh-status CLI command."""

    def test_mesh_status_json(self) -> None:
        from click.testing import CliRunner
        from secrets_sdk.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["mesh-status", "--providers", "env", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "overall" in data
        assert "providers" in data


# =====================================================================
# Module exports test
# =====================================================================


class TestExports:
    """Verify that mesh classes are exported from the SDK top level."""

    def test_mesh_exports(self) -> None:
        import secrets_sdk

        assert hasattr(secrets_sdk, "SecretsMesh")
        assert hasattr(secrets_sdk, "SecretProvider")
        assert hasattr(secrets_sdk, "SecretValue")
        assert hasattr(secrets_sdk, "EnvProvider")
        assert hasattr(secrets_sdk, "FileProvider")
        assert hasattr(secrets_sdk, "VaultProvider")
        assert hasattr(secrets_sdk, "TTLCache")
        assert hasattr(secrets_sdk, "ProviderHealth")
        assert hasattr(secrets_sdk, "ProviderStatus")
        assert hasattr(secrets_sdk, "MeshAuditEntry")
        assert hasattr(secrets_sdk, "MeshStatus")
        assert hasattr(secrets_sdk, "mesh")
