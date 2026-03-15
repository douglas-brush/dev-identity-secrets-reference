"""Unit tests for secret rotation helpers."""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from secrets_sdk.exceptions import RotationError, VaultSecretNotFound
from secrets_sdk.models import AgeReport, SecretMetadata
from secrets_sdk.rotation import (
    DEFAULT_POLICIES,
    RotationPolicy,
    _glob_to_regex,
    check_secret_age,
    check_secrets_batch,
    rotate_sops_keys,
)


# ------------------------------------------------------------------
# RotationPolicy
# ------------------------------------------------------------------


class TestRotationPolicy:
    def test_default_warn_age(self) -> None:
        policy = RotationPolicy(name="test", max_age_days=100)
        assert policy.warn_age_days == 80.0

    def test_custom_warn_age(self) -> None:
        policy = RotationPolicy(name="test", max_age_days=100, warn_age_days=50)
        assert policy.warn_age_days == 50.0

    def test_matches_path_exact(self) -> None:
        policy = RotationPolicy(name="test", paths=["kv/data/dev/db/main"])
        assert policy.matches_path("kv/data/dev/db/main") is True
        assert policy.matches_path("kv/data/dev/db/other") is False

    def test_matches_path_wildcard(self) -> None:
        policy = RotationPolicy(name="test", paths=["kv/data/*/database/*"])
        assert policy.matches_path("kv/data/dev/database/creds") is True
        assert policy.matches_path("kv/data/prod/database/main") is True
        assert policy.matches_path("kv/data/dev/api-keys/stripe") is False

    def test_matches_multiple_patterns(self) -> None:
        policy = RotationPolicy(name="test", paths=["kv/data/*/db/*", "kv/data/*/database/*"])
        assert policy.matches_path("kv/data/dev/db/main") is True
        assert policy.matches_path("kv/data/dev/database/main") is True

    def test_default_policies_exist(self) -> None:
        assert len(DEFAULT_POLICIES) > 0
        names = {p.name for p in DEFAULT_POLICIES}
        assert "database-credentials" in names
        assert "api-keys" in names


# ------------------------------------------------------------------
# check_secret_age
# ------------------------------------------------------------------


class TestCheckSecretAge:
    def test_fresh_secret(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        """Secret created recently should not need rotation."""
        now = datetime.now(timezone.utc)
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.return_value = {
            "data": {
                "current_version": 1,
                "versions": {
                    "1": {
                        "created_time": now.isoformat(),
                        "destroyed": False,
                    }
                },
                "custom_metadata": None,
            }
        }

        report = check_secret_age(vault_client, "dev/apps/fresh", max_age_days=90)
        assert isinstance(report, AgeReport)
        assert report.needs_rotation is False
        assert report.age_days < 1

    def test_old_secret(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        """Secret older than max_age_days should need rotation."""
        old_time = datetime.now(timezone.utc) - timedelta(days=120)
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.return_value = {
            "data": {
                "current_version": 2,
                "versions": {
                    "2": {
                        "created_time": old_time.isoformat(),
                        "destroyed": False,
                    }
                },
                "custom_metadata": None,
            }
        }

        report = check_secret_age(vault_client, "dev/apps/old", max_age_days=90)
        assert report.needs_rotation is True
        assert report.age_days > 90
        assert "overdue" in report.detail.lower()

    def test_warning_zone(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        """Secret in the warning zone (80-100% of max age)."""
        warn_time = datetime.now(timezone.utc) - timedelta(days=75)
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.return_value = {
            "data": {
                "current_version": 1,
                "versions": {
                    "1": {
                        "created_time": warn_time.isoformat(),
                        "destroyed": False,
                    }
                },
                "custom_metadata": None,
            }
        }

        report = check_secret_age(vault_client, "dev/apps/warn", max_age_days=90)
        assert report.needs_rotation is False
        assert "will need rotation" in report.detail.lower()

    def test_secret_not_found(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        """Missing secret should return a report (not raise)."""
        from hvac.exceptions import InvalidPath  # type: ignore[import-untyped]
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.side_effect = InvalidPath("not found")

        report = check_secret_age(vault_client, "dev/apps/missing")
        assert report.needs_rotation is False
        assert "not found" in report.detail.lower()

    def test_connection_error(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        """Connection error should raise RotationError."""
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.side_effect = ConnectionError("refused")

        with pytest.raises(RotationError, match="Cannot check age"):
            check_secret_age(vault_client, "dev/apps/unreachable")


# ------------------------------------------------------------------
# check_secrets_batch
# ------------------------------------------------------------------


class TestCheckSecretsBatch:
    def test_batch_multiple_paths(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        now = datetime.now(timezone.utc)
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.return_value = {
            "data": {
                "current_version": 1,
                "versions": {
                    "1": {
                        "created_time": now.isoformat(),
                        "destroyed": False,
                    }
                },
                "custom_metadata": None,
            }
        }

        reports = check_secrets_batch(vault_client, ["path/a", "path/b", "path/c"])
        assert len(reports) == 3
        assert all(isinstance(r, AgeReport) for r in reports)

    def test_batch_with_custom_policies(self, vault_client: Any, mock_hvac_client: MagicMock) -> None:
        now = datetime.now(timezone.utc)
        mock_hvac_client.secrets.kv.v2.read_secret_metadata.return_value = {
            "data": {
                "current_version": 1,
                "versions": {
                    "1": {
                        "created_time": now.isoformat(),
                        "destroyed": False,
                    }
                },
                "custom_metadata": None,
            }
        }

        policies = [RotationPolicy(name="strict", max_age_days=30, paths=["strict/*"])]
        reports = check_secrets_batch(vault_client, ["strict/secret"], policies=policies)
        assert len(reports) == 1
        assert reports[0].max_age_days == 30


# ------------------------------------------------------------------
# rotate_sops_keys
# ------------------------------------------------------------------


class TestRotateSopsKeys:
    def test_nonexistent_repo(self) -> None:
        with pytest.raises(RotationError, match="not found"):
            rotate_sops_keys("/nonexistent", "age1newkey")

    def test_missing_sops_yaml(self, tmp_path: Path) -> None:
        with pytest.raises(RotationError, match=".sops.yaml not found"):
            rotate_sops_keys(tmp_path, "age1newkey")

    @patch("secrets_sdk.rotation.shutil.which", return_value=None)
    def test_sops_not_installed(self, mock_which: MagicMock, tmp_path: Path) -> None:
        (tmp_path / ".sops.yaml").write_text("creation_rules:\n  - age: old\n")
        with pytest.raises(RotationError, match="sops binary not found"):
            rotate_sops_keys(tmp_path, "age1newkey")

    @patch("secrets_sdk.rotation.shutil.which", return_value="/usr/local/bin/sops")
    def test_dry_run(self, mock_which: MagicMock, tmp_path: Path) -> None:
        (tmp_path / ".sops.yaml").write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/.*
                age: 'age1oldkey'
                encrypted_regex: '^(password)$'
        """))
        # Create an encrypted file
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets" / "test.enc.yaml").write_text("password: ENC[...]")

        results = rotate_sops_keys(
            tmp_path,
            new_key="age1newkey",
            old_key="age1oldkey",
            dry_run=True,
        )
        assert len(results) >= 1
        assert all(r["status"].startswith("would_") for r in results)

    @patch("secrets_sdk.rotation.subprocess.run")
    @patch("secrets_sdk.rotation.shutil.which", return_value="/usr/local/bin/sops")
    def test_actual_rotation(self, mock_which: MagicMock, mock_run: MagicMock, tmp_path: Path) -> None:
        (tmp_path / ".sops.yaml").write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/.*
                age: 'age1oldkey'
                encrypted_regex: '^(password)$'
        """))
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets" / "test.enc.yaml").write_text("password: ENC[...]")

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        results = rotate_sops_keys(
            tmp_path,
            new_key="age1newkey",
            old_key="age1oldkey",
        )
        # Should have updated .sops.yaml + re-encrypted the file
        assert any(r["status"] == "rotated" for r in results)

        # Verify .sops.yaml was updated
        import yaml
        updated = yaml.safe_load((tmp_path / ".sops.yaml").read_text())
        assert updated["creation_rules"][0]["age"] == "age1newkey"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


class TestGlobToRegex:
    def test_exact_match(self) -> None:
        import re
        pattern = _glob_to_regex("kv/data/dev/app")
        assert re.match(pattern, "kv/data/dev/app")
        assert not re.match(pattern, "kv/data/dev/other")

    def test_wildcard(self) -> None:
        import re
        pattern = _glob_to_regex("kv/data/*/app")
        assert re.match(pattern, "kv/data/dev/app")
        assert re.match(pattern, "kv/data/prod/app")
        assert not re.match(pattern, "kv/data/dev/nested/app")

    def test_special_chars_escaped(self) -> None:
        import re
        pattern = _glob_to_regex("kv/data/dev.test/app")
        assert re.match(pattern, "kv/data/dev.test/app")
        assert not re.match(pattern, "kv/data/devXtest/app")
