"""Unit tests for configuration validation."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from secrets_sdk.config import (
    scan_plaintext_secrets,
    validate_repo_structure,
    validate_sops_yaml,
    validate_vault_policy,
)
from secrets_sdk.models import SecretFinding


# ------------------------------------------------------------------
# validate_sops_yaml
# ------------------------------------------------------------------


class TestValidateSopsYaml:
    def test_valid_config(self, sample_repo: Path) -> None:
        issues = validate_sops_yaml(sample_repo / ".sops.yaml")
        # The prod rule has no cloud KMS, so expect that warning
        prod_issues = [i for i in issues if "cloud KMS" in i]
        assert len(prod_issues) == 1  # prod rule warning

    def test_missing_file(self) -> None:
        issues = validate_sops_yaml("/nonexistent/.sops.yaml")
        assert any("not found" in i.lower() for i in issues)

    def test_empty_rules(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text("creation_rules: []\n")
        issues = validate_sops_yaml(f)
        assert any("empty" in i.lower() for i in issues)

    def test_missing_path_regex(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - age: 'age1abc'
                encrypted_regex: '^(password)$'
        """))
        issues = validate_sops_yaml(f)
        assert any("path_regex" in i for i in issues)

    def test_invalid_regex(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: '[invalid'
                age: 'age1abc'
        """))
        issues = validate_sops_yaml(f)
        assert any("invalid regex" in i.lower() for i in issues)

    def test_no_key_source(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/dev/.*
                encrypted_regex: '^(password)$'
        """))
        issues = validate_sops_yaml(f)
        assert any("no encryption key" in i.lower() for i in issues)

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text("{{invalid yaml")
        issues = validate_sops_yaml(f)
        assert len(issues) > 0

    def test_prod_cloud_kms_warning(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/prod/.*\\.enc\\.yaml$
                age: 'age1onlyage'
                encrypted_regex: '^(password)$'
        """))
        issues = validate_sops_yaml(f)
        assert any("cloud KMS" in i for i in issues)

    def test_no_encrypted_regex_warning(self, tmp_path: Path) -> None:
        f = tmp_path / ".sops.yaml"
        f.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/dev/.*
                age: 'age1abc'
        """))
        issues = validate_sops_yaml(f)
        assert any("encrypted_regex" in i for i in issues)


# ------------------------------------------------------------------
# validate_vault_policy
# ------------------------------------------------------------------


class TestValidateVaultPolicy:
    def test_valid_policy(self, tmp_path: Path) -> None:
        f = tmp_path / "dev-read.hcl"
        f.write_text(textwrap.dedent("""\
            path "kv/data/dev/*" {
              capabilities = ["read", "list"]
            }
        """))
        issues = validate_vault_policy(f)
        assert issues == []

    def test_missing_file(self) -> None:
        issues = validate_vault_policy("/nonexistent.hcl")
        assert any("not found" in i.lower() for i in issues)

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.hcl"
        f.write_text("")
        issues = validate_vault_policy(f)
        assert any("empty" in i.lower() for i in issues)

    def test_no_path_blocks(self, tmp_path: Path) -> None:
        f = tmp_path / "nopath.hcl"
        f.write_text("# Just a comment\n")
        issues = validate_vault_policy(f)
        assert any("No 'path' blocks" in i for i in issues)

    def test_unknown_capability(self, tmp_path: Path) -> None:
        f = tmp_path / "bad-cap.hcl"
        f.write_text(textwrap.dedent("""\
            path "kv/data/*" {
              capabilities = ["read", "execute"]
            }
        """))
        issues = validate_vault_policy(f)
        assert any("unknown capability" in i for i in issues)

    def test_dangerous_capability_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "admin.hcl"
        f.write_text(textwrap.dedent("""\
            path "sys/policy/*" {
              capabilities = ["create", "read", "update", "delete", "sudo"]
            }
        """))
        issues = validate_vault_policy(f)
        dangerous = [i for i in issues if "dangerous" in i.lower()]
        assert len(dangerous) == 2  # delete + sudo

    def test_missing_capabilities(self, tmp_path: Path) -> None:
        f = tmp_path / "nocap.hcl"
        f.write_text(textwrap.dedent("""\
            path "kv/data/*" {
              # no capabilities
            }
        """))
        issues = validate_vault_policy(f)
        assert any("missing" in i.lower() and "capabilities" in i.lower() for i in issues)

    def test_broad_path_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "broad.hcl"
        f.write_text(textwrap.dedent("""\
            path "sys/*" {
              capabilities = ["read"]
            }
        """))
        issues = validate_vault_policy(f)
        assert any("root-level" in i for i in issues)


# ------------------------------------------------------------------
# validate_repo_structure
# ------------------------------------------------------------------


class TestValidateRepoStructure:
    def test_valid_structure(self, sample_repo: Path) -> None:
        issues = validate_repo_structure(sample_repo)
        # The prod rule has no cloud KMS — that's the only expected warning
        non_kms = [i for i in issues if "cloud KMS" not in i]
        assert non_kms == [], f"Unexpected issues: {non_kms}"

    def test_missing_dirs(self, tmp_path: Path) -> None:
        (tmp_path / ".sops.yaml").write_text("creation_rules: []\n")
        issues = validate_repo_structure(tmp_path)
        assert any("platform/vault/policies" in i for i in issues)
        assert any("secrets" in i for i in issues)

    def test_unencrypted_file_warning(self, sample_repo: Path) -> None:
        # Add an unencrypted file to secrets/
        (sample_repo / "secrets" / "dev" / "plaintext.yaml").write_text("password: bad\n")
        issues = validate_repo_structure(sample_repo)
        assert any("unencrypted" in i.lower() or "Potentially" in i for i in issues)

    def test_nonexistent_root(self) -> None:
        issues = validate_repo_structure("/nonexistent/repo")
        assert any("not found" in i.lower() for i in issues)

    def test_real_repo(self, real_repo_root: Path) -> None:
        """Validate the actual dev-identity-secrets-reference repo structure."""
        issues = validate_repo_structure(real_repo_root)
        # Should not have critical structural issues
        structural = [i for i in issues if "Missing expected" in i]
        assert structural == [], f"Real repo has structural issues: {structural}"


# ------------------------------------------------------------------
# scan_plaintext_secrets
# ------------------------------------------------------------------


class TestScanSecrets:
    def test_detect_aws_key(self, tmp_path: Path) -> None:
        f = tmp_path / "config.py"
        f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_plaintext_secrets(tmp_path)
        assert len(findings) >= 1
        assert any(f.pattern_name == "AWS Access Key" for f in findings)

    def test_detect_private_key(self, tmp_path: Path) -> None:
        f = tmp_path / "key.py"
        f.write_text('key = """-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----"""\n')
        findings = scan_plaintext_secrets(tmp_path)
        assert any(f.pattern_name == "Private Key Block" for f in findings)

    def test_detect_github_token(self, tmp_path: Path) -> None:
        f = tmp_path / "ci.yaml"
        f.write_text('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n')
        findings = scan_plaintext_secrets(tmp_path)
        assert any(f.pattern_name == "GitHub Token" for f in findings)

    def test_detect_connection_string(self, tmp_path: Path) -> None:
        f = tmp_path / "db.py"
        f.write_text('DSN = "postgres://user:password@host:5432/db"\n')
        findings = scan_plaintext_secrets(tmp_path)
        assert any(f.pattern_name == "Connection String with Password" for f in findings)

    def test_clean_file(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text('x = 42\nname = "hello"\n')
        findings = scan_plaintext_secrets(tmp_path)
        assert findings == []

    def test_skip_binary_extensions(self, tmp_path: Path) -> None:
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n" + b"AKIAIOSFODNN7EXAMPLE")
        findings = scan_plaintext_secrets(tmp_path)
        assert findings == []

    def test_respects_include_patterns(self, tmp_path: Path) -> None:
        f = tmp_path / "mixed.py"
        f.write_text(
            'key = "AKIAIOSFODNN7EXAMPLE"\n'
            'dsn = "postgres://u:p@h:5432/db"\n'
        )
        findings = scan_plaintext_secrets(tmp_path, include_patterns=["AWS Access Key"])
        assert all(f.pattern_name == "AWS Access Key" for f in findings)

    def test_redacts_matched_text(self, tmp_path: Path) -> None:
        f = tmp_path / "key.py"
        f.write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_plaintext_secrets(tmp_path)
        for finding in findings:
            # Should be redacted — not show the full key
            assert "..." in finding.matched_text

    def test_single_file_scan(self, tmp_path: Path) -> None:
        f = tmp_path / "single.py"
        f.write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_plaintext_secrets(f)
        assert len(findings) >= 1
