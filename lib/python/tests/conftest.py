"""Shared pytest fixtures for secrets-sdk tests."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, PropertyMock

import pytest

import hvac.exceptions  # type: ignore[import-untyped]


# ------------------------------------------------------------------
# Vault fixtures
# ------------------------------------------------------------------


@pytest.fixture
def mock_hvac_client() -> MagicMock:
    """Create a mock hvac.Client with all expected sub-clients wired up."""
    client = MagicMock()

    # Auth backends
    client.is_authenticated.return_value = True
    client.auth.token.lookup_self.return_value = {
        "data": {"id": "s.mock-token", "ttl": 3600}
    }
    client.auth.token.renew_self.return_value = {
        "auth": {"client_token": "s.mock-token", "ttl": 3600}
    }
    client.auth.approle.login.return_value = {
        "auth": {"client_token": "s.approle-token"}
    }
    client.auth.jwt.jwt_login.return_value = {
        "auth": {"client_token": "s.oidc-token"}
    }

    # KV v2
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {"username": "admin", "password": "s3cret"},
            "metadata": {
                "version": 3,
                "created_time": "2025-01-15T10:30:00Z",
            },
        }
    }
    client.secrets.kv.v2.create_or_update_secret.return_value = {
        "data": {"version": 4, "created_time": "2025-06-01T12:00:00Z"}
    }
    client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["app1/", "app2/", "shared/"]}
    }
    client.secrets.kv.v2.read_secret_metadata.return_value = {
        "data": {
            "current_version": 3,
            "versions": {
                "3": {
                    "created_time": "2025-01-15T10:30:00Z",
                    "destroyed": False,
                }
            },
            "custom_metadata": {"owner": "team-platform"},
        }
    }

    # Database
    client.secrets.database.generate_credentials.return_value = {
        "lease_id": "database/creds/dev-app/abc123",
        "lease_duration": 3600,
        "renewable": True,
        "request_id": "req-001",
        "data": {"username": "v-dev-app-abc", "password": "dynamic-pass"},
    }

    # PKI
    client.secrets.pki.generate_certificate.return_value = {
        "data": {
            "certificate": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
            "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
            "ca_chain": [],
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----",
            "private_key_type": "rsa",
            "serial_number": "aa:bb:cc:dd",
            "expiration": 1893456000,
        }
    }

    # SSH
    client.secrets.ssh.sign_ssh_key.return_value = {
        "data": {
            "signed_key": "ssh-rsa-cert-v01@openssh.com AAAA...",
            "serial_number": "12345",
        }
    }

    # Transit
    client.secrets.transit.encrypt_data.return_value = {
        "data": {"ciphertext": "vault:v1:ENCRYPTED_DATA", "key_version": 1}
    }
    client.secrets.transit.decrypt_data.return_value = {
        "data": {"plaintext": "aGVsbG8gd29ybGQ="}  # base64("hello world")
    }

    # Sys
    client.sys.read_health_status.return_value = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "server_time_utc": 1700000000,
    }
    client.sys.renew_lease.return_value = {
        "lease_id": "database/creds/dev-app/abc123",
        "lease_duration": 3600,
        "renewable": True,
    }
    client.sys.revoke_lease.return_value = None

    return client


@pytest.fixture
def vault_client(mock_hvac_client: MagicMock) -> Any:
    """Create a VaultClient with the mock hvac client injected."""
    from secrets_sdk.vault import VaultClient

    return VaultClient(
        addr="http://mock-vault:8200",
        token="s.mock-token",
        client=mock_hvac_client,
    )


# ------------------------------------------------------------------
# Repo structure fixtures
# ------------------------------------------------------------------


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a minimal valid repo structure for testing."""
    # .sops.yaml
    sops_yaml = tmp_path / ".sops.yaml"
    sops_yaml.write_text(textwrap.dedent("""\
        creation_rules:
          - path_regex: secrets/dev/.*\\.enc\\.(ya?ml|json)$
            age: 'age1testkey123'
            encrypted_regex: '^(data|stringData|secrets|env|password|token|client_secret|private_key|api_key|connection_string|credentials)$'
          - path_regex: secrets/staging/.*\\.enc\\.(ya?ml|json)$
            age: 'age1testkey123'
            encrypted_regex: '^(data|stringData|secrets|env|password|token|client_secret|private_key|api_key|connection_string|credentials)$'
          - path_regex: secrets/prod/.*\\.enc\\.(ya?ml|json)$
            age: 'age1testkey123'
            encrypted_regex: '^(data|stringData|secrets|env|password|token|client_secret|private_key|api_key|connection_string|credentials)$'
    """))

    # Directory structure
    (tmp_path / "platform" / "vault" / "policies").mkdir(parents=True)
    (tmp_path / "secrets" / "dev").mkdir(parents=True)
    (tmp_path / "secrets" / "staging").mkdir(parents=True)
    (tmp_path / "secrets" / "prod").mkdir(parents=True)
    (tmp_path / "docs").mkdir()

    # A valid Vault policy
    policy = tmp_path / "platform" / "vault" / "policies" / "dev-read.hcl"
    policy.write_text(textwrap.dedent("""\
        path "kv/data/dev/*" {
          capabilities = ["read", "list"]
        }
    """))

    # Gitkeep in secrets
    (tmp_path / "secrets" / "dev" / ".gitkeep").touch()
    (tmp_path / "secrets" / "staging" / ".gitkeep").touch()
    (tmp_path / "secrets" / "prod" / ".gitkeep").touch()

    return tmp_path


@pytest.fixture
def real_repo_root() -> Path:
    """Return the actual dev-identity-secrets-reference repo root, if running inside it."""
    # Walk up from this test file to find the repo root
    candidate = Path(__file__).resolve().parent.parent.parent.parent
    if (candidate / ".sops.yaml").exists() and (candidate / "platform" / "vault").is_dir():
        return candidate
    # Fallback: try CWD
    cwd = Path.cwd()
    if (cwd / ".sops.yaml").exists():
        return cwd
    pytest.skip("Not running inside the dev-identity-secrets-reference repo")
    return cwd  # unreachable but satisfies type checker
