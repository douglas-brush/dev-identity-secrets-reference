"""Unit tests for the Vault client wrapper."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import MagicMock

import hvac.exceptions  # type: ignore[import-untyped]
import pytest

from secrets_sdk.exceptions import (
    VaultAuthError,
    VaultConnectionError,
    VaultLeaseError,
    VaultSecretNotFound,
)
from secrets_sdk.models import (
    AuditEventType,
    CertInfo,
    HealthStatus,
    LeaseInfo,
    SSHCertInfo,
    SecretMetadata,
    TransitResult,
)
from secrets_sdk.vault import VaultClient


# ------------------------------------------------------------------
# Authentication
# ------------------------------------------------------------------


class TestTokenAuth:
    def test_auth_token_success(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        vault_client.auth_token("s.valid-token")
        mock_hvac_client.auth.token.lookup_self.assert_called_once()
        assert mock_hvac_client.token == "s.valid-token"

    def test_auth_token_no_token(self) -> None:
        client = VaultClient(addr="http://x:8200", client=MagicMock())
        with pytest.raises(VaultAuthError, match="No token provided"):
            client.auth_token(None)

    def test_auth_token_forbidden(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.auth.token.lookup_self.side_effect = hvac.exceptions.Forbidden("denied")
        with pytest.raises(VaultAuthError, match="invalid or expired"):
            vault_client.auth_token("s.bad")

    def test_auth_token_connection_error(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.auth.token.lookup_self.side_effect = ConnectionError("refused")
        with pytest.raises(VaultConnectionError):
            vault_client.auth_token("s.token")


class TestAppRoleAuth:
    def test_auth_approle_success(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        vault_client.auth_approle(role_id="role-123", secret_id="secret-456")
        mock_hvac_client.auth.approle.login.assert_called_once_with(
            role_id="role-123",
            secret_id="secret-456",
            mount_point="approle",
        )
        assert mock_hvac_client.token == "s.approle-token"

    def test_auth_approle_no_role_id(self, vault_client: VaultClient) -> None:
        with pytest.raises(VaultAuthError, match="No role_id"):
            vault_client.auth_approle(role_id="", secret_id="x")

    def test_auth_approle_invalid(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.auth.approle.login.side_effect = hvac.exceptions.InvalidRequest("bad creds")
        with pytest.raises(VaultAuthError, match="approle"):
            vault_client.auth_approle(role_id="bad", secret_id="creds")


class TestOIDCAuth:
    def test_auth_oidc_jwt(self, vault_client: VaultClient, mock_hvac_client: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VAULT_OIDC_TOKEN", "eyJ.test.jwt")
        vault_client.auth_oidc(role="dev")
        mock_hvac_client.auth.jwt.jwt_login.assert_called_once()
        assert mock_hvac_client.token == "s.oidc-token"

    def test_auth_oidc_no_token_interactive(self, vault_client: VaultClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VAULT_OIDC_TOKEN", raising=False)
        with pytest.raises(VaultAuthError, match="Interactive OIDC not supported"):
            vault_client.auth_oidc()


# ------------------------------------------------------------------
# KV v2
# ------------------------------------------------------------------


class TestKVRead:
    def test_read_success(self, vault_client: VaultClient) -> None:
        data = vault_client.kv_read("dev/apps/myapp")
        assert data == {"username": "admin", "password": "s3cret"}

    def test_read_not_found(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.InvalidPath("not found")
        with pytest.raises(VaultSecretNotFound, match="dev/apps/missing"):
            vault_client.kv_read("dev/apps/missing")

    def test_read_with_version(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        vault_client.kv_read("dev/apps/myapp", version=2)
        mock_hvac_client.secrets.kv.v2.read_secret_version.assert_called_with(
            path="dev/apps/myapp", version=2, mount_point="kv"
        )


class TestKVWrite:
    def test_write_success(self, vault_client: VaultClient) -> None:
        meta = vault_client.kv_write("dev/apps/myapp", {"key": "value"})
        assert isinstance(meta, SecretMetadata)
        assert meta.version == 4

    def test_write_connection_error(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.secrets.kv.v2.create_or_update_secret.side_effect = ConnectionError("down")
        with pytest.raises(VaultConnectionError):
            vault_client.kv_write("dev/x", {"k": "v"})


class TestKVList:
    def test_list_success(self, vault_client: VaultClient) -> None:
        keys = vault_client.kv_list("dev/apps")
        assert keys == ["app1/", "app2/", "shared/"]

    def test_list_not_found(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.secrets.kv.v2.list_secrets.side_effect = hvac.exceptions.InvalidPath("nope")
        with pytest.raises(VaultSecretNotFound):
            vault_client.kv_list("nonexistent/")


class TestKVMetadata:
    def test_metadata_success(self, vault_client: VaultClient) -> None:
        meta = vault_client.kv_metadata("dev/apps/myapp")
        assert meta.version == 3
        assert meta.custom_metadata == {"owner": "team-platform"}
        assert meta.destroyed is False

    def test_metadata_not_found(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.side_effect = hvac.exceptions.InvalidPath("nope")
        with pytest.raises(VaultSecretNotFound):
            vault_client.kv_metadata("missing/path")


# ------------------------------------------------------------------
# Dynamic DB Creds
# ------------------------------------------------------------------


class TestDBCreds:
    def test_db_creds_success(self, vault_client: VaultClient) -> None:
        lease = vault_client.db_creds("dev-app")
        assert isinstance(lease, LeaseInfo)
        assert lease.lease_duration == 3600
        assert lease.renewable is True
        assert lease.data["username"] == "v-dev-app-abc"


# ------------------------------------------------------------------
# PKI
# ------------------------------------------------------------------


class TestPKI:
    def test_pki_issue_success(self, vault_client: VaultClient) -> None:
        cert = vault_client.pki_issue("web-server", "app.example.com")
        assert isinstance(cert, CertInfo)
        assert "CERTIFICATE" in cert.certificate
        assert cert.serial_number == "aa:bb:cc:dd"

    def test_pki_issue_with_alt_names(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        vault_client.pki_issue("web", "app.example.com", alt_names=["api.example.com"])
        call_kwargs = mock_hvac_client.secrets.pki.generate_certificate.call_args
        assert "api.example.com" in call_kwargs.kwargs["extra_params"]["alt_names"]


# ------------------------------------------------------------------
# SSH
# ------------------------------------------------------------------


class TestSSH:
    def test_ssh_sign_success(self, vault_client: VaultClient) -> None:
        result = vault_client.ssh_sign("dev-admin", "ssh-rsa AAAA...")
        assert isinstance(result, SSHCertInfo)
        assert "ssh-rsa-cert" in result.signed_key


# ------------------------------------------------------------------
# Transit
# ------------------------------------------------------------------


class TestTransit:
    def test_encrypt_success(self, vault_client: VaultClient) -> None:
        result = vault_client.transit_encrypt("my-key", "hello world")
        assert isinstance(result, TransitResult)
        assert result.ciphertext == "vault:v1:ENCRYPTED_DATA"

    def test_encrypt_bytes(self, vault_client: VaultClient) -> None:
        result = vault_client.transit_encrypt("my-key", b"binary data")
        assert result.ciphertext == "vault:v1:ENCRYPTED_DATA"

    def test_decrypt_success(self, vault_client: VaultClient) -> None:
        result = vault_client.transit_decrypt("my-key", "vault:v1:ENCRYPTED_DATA")
        assert result.plaintext == "hello world"


# ------------------------------------------------------------------
# Token Lifecycle
# ------------------------------------------------------------------


class TestTokenLifecycle:
    def test_renew_self(self, vault_client: VaultClient) -> None:
        info = vault_client.token_renew("2h")
        assert info["client_token"] == "s.mock-token"

    def test_revoke_self(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        vault_client.token_revoke_self()
        mock_hvac_client.auth.token.revoke_self.assert_called_once()

    def test_renew_self_error(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.auth.token.renew_self.side_effect = hvac.exceptions.Forbidden("denied")
        with pytest.raises(VaultLeaseError, match="renew"):
            vault_client.token_renew()


class TestLeaseManagement:
    def test_lease_renew(self, vault_client: VaultClient) -> None:
        result = vault_client.lease_renew("database/creds/dev-app/abc123", increment=7200)
        assert isinstance(result, LeaseInfo)

    def test_lease_revoke(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        vault_client.lease_revoke("database/creds/dev-app/abc123")
        mock_hvac_client.sys.revoke_lease.assert_called_once_with(
            lease_id="database/creds/dev-app/abc123"
        )


# ------------------------------------------------------------------
# Health
# ------------------------------------------------------------------


class TestHealth:
    def test_health_ok(self, vault_client: VaultClient) -> None:
        report = vault_client.health()
        assert report.overall_status == HealthStatus.HEALTHY
        assert len(report.checks) == 2

    def test_health_sealed(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.sys.read_health_status.return_value = {
            "initialized": True,
            "sealed": True,
        }
        report = vault_client.health()
        assert report.overall_status == HealthStatus.UNHEALTHY

    def test_health_unreachable(self, vault_client: VaultClient, mock_hvac_client: MagicMock) -> None:
        mock_hvac_client.sys.read_health_status.side_effect = ConnectionError("refused")
        mock_hvac_client.is_authenticated.side_effect = ConnectionError("refused")
        report = vault_client.health()
        assert report.overall_status == HealthStatus.UNHEALTHY


# ------------------------------------------------------------------
# Audit Log
# ------------------------------------------------------------------


class TestAuditLog:
    def test_audit_events_collected(self, vault_client: VaultClient) -> None:
        vault_client.kv_read("test/path")
        events = vault_client.audit_log
        assert len(events) >= 1
        assert events[-1].event_type == AuditEventType.SECRET_READ

    def test_audit_event_log_line(self, vault_client: VaultClient) -> None:
        vault_client.kv_read("test/path")
        line = vault_client.audit_log[-1].as_log_line()
        assert "event=secret_read" in line
        assert "status=OK" in line


# ------------------------------------------------------------------
# Constructor
# ------------------------------------------------------------------


class TestConstructor:
    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VAULT_ADDR", "http://env-vault:8200")
        monkeypatch.setenv("VAULT_TOKEN", "s.env-token")
        monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
        # We can't fully test without a real Vault, but verify the client is constructed
        vc = VaultClient()
        assert vc._addr == "http://env-vault:8200"
        assert vc._verify is False

    def test_explicit_config(self) -> None:
        mock = MagicMock()
        vc = VaultClient(addr="http://x:1234", namespace="ns1", verify=True, client=mock)
        assert vc._addr == "http://x:1234"
        assert vc._namespace == "ns1"
        assert vc._verify is True
        assert vc.client is mock
