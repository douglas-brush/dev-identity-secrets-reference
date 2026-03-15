"""Unit tests for SOPS helpers."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secrets_sdk.exceptions import SopsDecryptError, SopsEncryptError, SopsNotInstalledError
from secrets_sdk.sops import (
    SopsConfig,
    SopsCreationRule,
    _detect_format,
    _parse_dotenv,
    decrypt_file,
    decrypt_value,
    encrypt_file,
)


# ------------------------------------------------------------------
# SopsConfig Parsing
# ------------------------------------------------------------------


class TestSopsConfig:
    def test_parse_valid(self, tmp_path: Path) -> None:
        sops_yaml = tmp_path / ".sops.yaml"
        sops_yaml.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/dev/.*\\.enc\\.yaml$
                age: 'age1abc'
                encrypted_regex: '^(password|token)$'
              - path_regex: secrets/prod/.*\\.enc\\.yaml$
                kms: 'arn:aws:kms:us-east-1:111:key/abc'
                age: 'age1xyz'
                encrypted_regex: '^(password|token)$'
        """))

        config = SopsConfig.from_file(sops_yaml)
        assert len(config.creation_rules) == 2
        assert config.creation_rules[0].age == "age1abc"
        assert config.creation_rules[1].kms.startswith("arn:aws")

    def test_parse_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            SopsConfig.from_file("/nonexistent/.sops.yaml")

    def test_parse_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text("not: a\n  valid: yaml: file: [")
        with pytest.raises(Exception):
            SopsConfig.from_file(f)

    def test_parse_no_creation_rules(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text("something_else: true\n")
        config = SopsConfig.from_file(f)
        assert config.creation_rules == []

    def test_has_cloud_kms(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: dev/.*
                age: 'age1abc'
              - path_regex: prod/.*
                kms: 'arn:aws:kms:us-east-1:111:key/abc'
        """))
        config = SopsConfig.from_file(f)
        assert config.has_cloud_kms() is True
        assert config.has_cloud_kms(rule_index=0) is False
        assert config.has_cloud_kms(rule_index=1) is True

    def test_rules_for_path(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/dev/.*\\.enc\\.yaml$
                age: 'age1dev'
              - path_regex: secrets/prod/.*\\.enc\\.yaml$
                age: 'age1prod'
        """))
        config = SopsConfig.from_file(f)
        matches = config.rules_for_path("secrets/dev/app.enc.yaml")
        assert len(matches) == 1
        assert matches[0].age == "age1dev"

        no_match = config.rules_for_path("other/file.yaml")
        assert len(no_match) == 0


# ------------------------------------------------------------------
# decrypt_file
# ------------------------------------------------------------------


class TestDecryptFile:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            decrypt_file("/nonexistent/file.enc.yaml")

    @patch("secrets_sdk.sops._find_sops", return_value="/usr/local/bin/sops")
    @patch("secrets_sdk.sops.subprocess.run")
    def test_decrypt_json(self, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path) -> None:
        enc_file = tmp_path / "secret.enc.json"
        enc_file.write_text('{"sops": {}, "password": "ENC[...]"}')

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"password": "plaintext-value"}',
            stderr="",
        )

        result = decrypt_file(enc_file)
        assert result == {"password": "plaintext-value"}

    @patch("secrets_sdk.sops._find_sops", return_value="/usr/local/bin/sops")
    @patch("secrets_sdk.sops.subprocess.run")
    def test_decrypt_yaml(self, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path) -> None:
        enc_file = tmp_path / "secret.enc.yaml"
        enc_file.write_text("password: ENC[...]")

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="password: my-secret\n",
            stderr="",
        )

        result = decrypt_file(enc_file)
        assert result == {"password": "my-secret"}

    @patch("secrets_sdk.sops._find_sops", return_value="/usr/local/bin/sops")
    @patch("secrets_sdk.sops.subprocess.run")
    def test_decrypt_failure(self, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path) -> None:
        enc_file = tmp_path / "bad.enc.json"
        enc_file.write_text("{}")

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error: could not decrypt",
        )

        with pytest.raises(SopsDecryptError, match="could not decrypt"):
            decrypt_file(enc_file)

    @patch("secrets_sdk.sops.shutil.which", return_value=None)
    def test_sops_not_installed(self, mock_which: MagicMock, tmp_path: Path) -> None:
        enc_file = tmp_path / "secret.enc.json"
        enc_file.write_text("{}")
        with pytest.raises(SopsNotInstalledError):
            decrypt_file(enc_file)


# ------------------------------------------------------------------
# encrypt_file
# ------------------------------------------------------------------


class TestEncryptFile:
    @patch("secrets_sdk.sops._find_sops", return_value="/usr/local/bin/sops")
    @patch("secrets_sdk.sops.subprocess.run")
    def test_encrypt_json(self, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path) -> None:
        out_path = tmp_path / "secret.enc.json"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"password": "ENC[AES256_GCM,data:abc]", "sops": {}}',
            stderr="",
        )

        result = encrypt_file(out_path, {"password": "my-secret"})
        assert result == out_path
        assert out_path.exists()

    @patch("secrets_sdk.sops._find_sops", return_value="/usr/local/bin/sops")
    @patch("secrets_sdk.sops.subprocess.run")
    def test_encrypt_failure(self, mock_run: MagicMock, mock_find: MagicMock, tmp_path: Path) -> None:
        out_path = tmp_path / "secret.enc.yaml"
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error: no matching creation rule",
        )

        with pytest.raises(SopsEncryptError, match="no matching creation rule"):
            encrypt_file(out_path, {"key": "val"})


# ------------------------------------------------------------------
# decrypt_value
# ------------------------------------------------------------------


class TestDecryptValue:
    @patch("secrets_sdk.sops._find_sops", return_value="/usr/local/bin/sops")
    @patch("secrets_sdk.sops.subprocess.run")
    def test_decrypt_value_success(self, mock_run: MagicMock, mock_find: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"value": "decrypted-secret"}',
            stderr="",
        )
        result = decrypt_value("ENC[AES256_GCM,data:abc]")
        assert result == "decrypted-secret"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


class TestHelpers:
    def test_detect_format_json(self) -> None:
        assert _detect_format(Path("secret.enc.json")) == "json"

    def test_detect_format_yaml(self) -> None:
        assert _detect_format(Path("secret.enc.yaml")) == "yaml"

    def test_detect_format_yml(self) -> None:
        assert _detect_format(Path("secret.enc.yml")) == "yaml"

    def test_detect_format_plain_yaml(self) -> None:
        assert _detect_format(Path("config.yaml")) == "yaml"

    def test_detect_format_unknown(self) -> None:
        assert _detect_format(Path("file.txt")) == "json"  # default

    def test_parse_dotenv(self) -> None:
        content = textwrap.dedent("""\
            # comment
            DB_HOST=localhost
            DB_PASS="quoted value"
            EMPTY=
        """)
        result = _parse_dotenv(content)
        assert result["DB_HOST"] == "localhost"
        assert result["DB_PASS"] == "quoted value"
        assert result["EMPTY"] == ""
