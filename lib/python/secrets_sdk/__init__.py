"""secrets-sdk — Python SDK for developer identity and secrets management.

Provides typed access to HashiCorp Vault, SOPS encryption/decryption,
configuration validation, secret rotation policy, and a CLI toolkit.
"""

from __future__ import annotations

__version__ = "0.1.0"

from secrets_sdk.exceptions import (
    ConfigValidationError,
    RotationError,
    SecretsSDKError,
    SopsDecryptError,
    SopsEncryptError,
    SopsNotInstalledError,
    VaultAuthError,
    VaultConnectionError,
    VaultLeaseError,
    VaultSecretNotFound,
)
from secrets_sdk.models import (
    AgeReport,
    AuditEvent,
    AuditEventType,
    CertInfo,
    HealthCheck,
    HealthReport,
    HealthStatus,
    LeaseInfo,
    SSHCertInfo,
    SecretFinding,
    SecretMetadata,
    TransitResult,
)
from secrets_sdk.vault import VaultClient

__all__ = [
    "__version__",
    # Client
    "VaultClient",
    # Models
    "AgeReport",
    "AuditEvent",
    "AuditEventType",
    "CertInfo",
    "HealthCheck",
    "HealthReport",
    "HealthStatus",
    "LeaseInfo",
    "SSHCertInfo",
    "SecretFinding",
    "SecretMetadata",
    "TransitResult",
    # Exceptions
    "ConfigValidationError",
    "RotationError",
    "SecretsSDKError",
    "SopsDecryptError",
    "SopsEncryptError",
    "SopsNotInstalledError",
    "VaultAuthError",
    "VaultConnectionError",
    "VaultLeaseError",
    "VaultSecretNotFound",
]
