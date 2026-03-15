"""Custom exceptions for the secrets SDK."""

from __future__ import annotations


class SecretsSDKError(Exception):
    """Base exception for all SDK errors."""


class VaultError(SecretsSDKError):
    """Base exception for Vault-related errors."""


class VaultAuthError(VaultError):
    """Raised when Vault authentication fails.

    Common causes: expired token, invalid OIDC callback, bad AppRole
    credentials, or missing authentication configuration.
    """

    def __init__(self, method: str, detail: str = "") -> None:
        self.method = method
        self.detail = detail
        msg = f"Vault authentication failed using {method}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class VaultSecretNotFound(VaultError):
    """Raised when a requested secret path does not exist in Vault."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"Secret not found at path: {path}")


class VaultConnectionError(VaultError):
    """Raised when Vault is unreachable."""

    def __init__(self, addr: str, detail: str = "") -> None:
        self.addr = addr
        self.detail = detail
        msg = f"Cannot connect to Vault at {addr}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class VaultLeaseError(VaultError):
    """Raised when a lease operation fails (renew, revoke)."""

    def __init__(self, lease_id: str, operation: str, detail: str = "") -> None:
        self.lease_id = lease_id
        self.operation = operation
        self.detail = detail
        msg = f"Lease {operation} failed for {lease_id}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class SopsError(SecretsSDKError):
    """Base exception for SOPS-related errors."""


class SopsDecryptError(SopsError):
    """Raised when SOPS decryption fails."""

    def __init__(self, path: str, detail: str = "") -> None:
        self.path = path
        self.detail = detail
        msg = f"SOPS decryption failed for {path}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class SopsEncryptError(SopsError):
    """Raised when SOPS encryption fails."""

    def __init__(self, path: str, detail: str = "") -> None:
        self.path = path
        self.detail = detail
        msg = f"SOPS encryption failed for {path}"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class SopsNotInstalledError(SopsError):
    """Raised when the sops binary is not found on PATH."""

    def __init__(self) -> None:
        super().__init__(
            "sops binary not found on PATH. Install from https://github.com/getsops/sops"
        )


class ConfigValidationError(SecretsSDKError):
    """Raised when configuration validation fails."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        count = len(issues)
        summary = f"Configuration validation found {count} issue{'s' if count != 1 else ''}"
        detail = "\n  - ".join([""] + issues)
        super().__init__(f"{summary}:{detail}")


class RotationError(SecretsSDKError):
    """Raised when a secret rotation operation fails."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Secret rotation failed: {detail}")
