"""Secrets Mesh — multi-provider secret access with fallback, caching, and audit.

The mesh abstraction layer enables pluggable secret backends (Vault, env vars,
SOPS files) with priority-based fallback chains, read-through TTL caching,
health monitoring, and audit logging.
"""

from __future__ import annotations

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

__all__ = [
    # Orchestrator
    "SecretsMesh",
    "MeshAuditEntry",
    "MeshStatus",
    # Base
    "SecretProvider",
    "SecretValue",
    "ProviderHealth",
    "ProviderStatus",
    # Providers
    "VaultProvider",
    "EnvProvider",
    "FileProvider",
    # Cache
    "TTLCache",
]
