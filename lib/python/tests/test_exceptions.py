"""Tests for the exception hierarchy, message formatting, and attributes."""

from __future__ import annotations

import pytest

from secrets_sdk.exceptions import (
    ConfigValidationError,
    RotationError,
    SecretsSDKError,
    SopsDecryptError,
    SopsEncryptError,
    SopsError,
    SopsNotInstalledError,
    VaultAuthError,
    VaultConnectionError,
    VaultError,
    VaultLeaseError,
    VaultSecretNotFound,
)


class TestExceptionHierarchy:
    """Verify the inheritance tree so except blocks work correctly."""

    def test_vault_errors_are_sdk_errors(self) -> None:
        assert issubclass(VaultError, SecretsSDKError)
        assert issubclass(VaultAuthError, VaultError)
        assert issubclass(VaultSecretNotFound, VaultError)
        assert issubclass(VaultConnectionError, VaultError)
        assert issubclass(VaultLeaseError, VaultError)

    def test_sops_errors_are_sdk_errors(self) -> None:
        assert issubclass(SopsError, SecretsSDKError)
        assert issubclass(SopsDecryptError, SopsError)
        assert issubclass(SopsEncryptError, SopsError)
        assert issubclass(SopsNotInstalledError, SopsError)

    def test_config_and_rotation_are_sdk_errors(self) -> None:
        assert issubclass(ConfigValidationError, SecretsSDKError)
        assert issubclass(RotationError, SecretsSDKError)


class TestVaultAuthError:
    def test_message_with_detail(self) -> None:
        exc = VaultAuthError("token", "expired")
        assert "token" in str(exc)
        assert "expired" in str(exc)
        assert exc.method == "token"
        assert exc.detail == "expired"

    def test_message_without_detail(self) -> None:
        exc = VaultAuthError("approle")
        assert "approle" in str(exc)
        assert exc.detail == ""


class TestVaultSecretNotFound:
    def test_message(self) -> None:
        exc = VaultSecretNotFound("kv/data/dev/app")
        assert "kv/data/dev/app" in str(exc)
        assert exc.path == "kv/data/dev/app"


class TestVaultConnectionError:
    def test_message_with_detail(self) -> None:
        exc = VaultConnectionError("http://vault:8200", "connection refused")
        assert "http://vault:8200" in str(exc)
        assert "connection refused" in str(exc)
        assert exc.addr == "http://vault:8200"


class TestVaultLeaseError:
    def test_message(self) -> None:
        exc = VaultLeaseError("lease-123", "renew", "permission denied")
        assert "lease-123" in str(exc)
        assert "renew" in str(exc)
        assert "permission denied" in str(exc)
        assert exc.lease_id == "lease-123"
        assert exc.operation == "renew"


class TestSopsErrors:
    def test_decrypt_error(self) -> None:
        exc = SopsDecryptError("/path/to/file.enc.yaml", "bad key")
        assert "/path/to/file.enc.yaml" in str(exc)
        assert "bad key" in str(exc)
        assert exc.path == "/path/to/file.enc.yaml"

    def test_encrypt_error(self) -> None:
        exc = SopsEncryptError("/path/to/file.enc.json", "no matching rule")
        assert "no matching rule" in str(exc)

    def test_not_installed_error(self) -> None:
        exc = SopsNotInstalledError()
        assert "sops binary not found" in str(exc)
        assert "getsops" in str(exc)


class TestConfigValidationError:
    def test_single_issue(self) -> None:
        exc = ConfigValidationError(["Missing .sops.yaml"])
        assert "1 issue" in str(exc)
        assert "Missing .sops.yaml" in str(exc)
        assert exc.issues == ["Missing .sops.yaml"]

    def test_multiple_issues(self) -> None:
        issues = ["Issue A", "Issue B", "Issue C"]
        exc = ConfigValidationError(issues)
        assert "3 issues" in str(exc)
        assert all(i in str(exc) for i in issues)


class TestRotationError:
    def test_message(self) -> None:
        exc = RotationError("sops not found")
        assert "sops not found" in str(exc)
        assert exc.detail == "sops not found"


class TestCatchWithBase:
    """Verify catching via base class works for all exceptions."""

    def test_catch_vault_with_sdk_base(self) -> None:
        with pytest.raises(SecretsSDKError):
            raise VaultAuthError("token")

    def test_catch_sops_with_sdk_base(self) -> None:
        with pytest.raises(SecretsSDKError):
            raise SopsDecryptError("file.enc.json")

    def test_catch_config_with_sdk_base(self) -> None:
        with pytest.raises(SecretsSDKError):
            raise ConfigValidationError(["issue"])
