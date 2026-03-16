"""Tests for the Click CLI commands using CliRunner.

Covers: doctor, vault-health, scan, rotate-check, decrypt, sirm-init,
sirm-status, sirm-seal, sirm-report.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from secrets_sdk.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ------------------------------------------------------------------
# doctor
# ------------------------------------------------------------------


class TestDoctorCommand:
    def test_doctor_clean_repo(self, runner: CliRunner, sample_repo: Path) -> None:
        result = runner.invoke(cli, ["doctor", "--root", str(sample_repo)])
        # prod KMS warning causes exit 1
        assert result.exit_code in (0, 1)

    def test_doctor_json_output(self, runner: CliRunner, sample_repo: Path) -> None:
        result = runner.invoke(cli, ["doctor", "--root", str(sample_repo), "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "issues" in data
        assert "count" in data
        assert isinstance(data["count"], int)

    def test_doctor_missing_dirs(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / ".sops.yaml").write_text("creation_rules: []\n")
        result = runner.invoke(cli, ["doctor", "--root", str(tmp_path)])
        assert result.exit_code == 1
        assert "issue" in result.output.lower()

    def test_doctor_json_missing_dirs(self, runner: CliRunner, tmp_path: Path) -> None:
        (tmp_path / ".sops.yaml").write_text("creation_rules: []\n")
        result = runner.invoke(cli, ["doctor", "--root", str(tmp_path), "--json-output"])
        assert result.exit_code == 0  # JSON mode always exits 0
        data = json.loads(result.output)
        assert data["count"] > 0

    def test_doctor_all_pass(self, runner: CliRunner, tmp_path: Path) -> None:
        """Build a repo that passes all checks (no prod rules => no KMS warning)."""
        sops = tmp_path / ".sops.yaml"
        sops.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: secrets/dev/.*\\.enc\\.yaml$
                age: 'age1key'
                encrypted_regex: '^(password)$'
        """))
        (tmp_path / "platform" / "vault" / "policies").mkdir(parents=True)
        policy = tmp_path / "platform" / "vault" / "policies" / "dev.hcl"
        policy.write_text('path "kv/data/dev/*" {\n  capabilities = ["read"]\n}\n')
        for env in ("dev", "staging", "prod"):
            d = tmp_path / "secrets" / env
            d.mkdir(parents=True)
            (d / ".gitkeep").touch()
        (tmp_path / "docs").mkdir()

        result = runner.invoke(cli, ["doctor", "--root", str(tmp_path)])
        assert result.exit_code == 0
        assert "passed" in result.output.lower()


# ------------------------------------------------------------------
# vault-health
# ------------------------------------------------------------------


class TestVaultHealthCommand:
    def test_vault_health_healthy(self, runner: CliRunner) -> None:
        from secrets_sdk.models import HealthCheck, HealthReport, HealthStatus

        report = HealthReport(checks=[
            HealthCheck(name="vault_connectivity", status=HealthStatus.HEALTHY, detail="OK", latency_ms=5.0),
            HealthCheck(name="vault_auth", status=HealthStatus.HEALTHY, detail="Valid"),
        ])
        with patch("secrets_sdk.vault.VaultClient.health", return_value=report):
            result = runner.invoke(cli, ["vault-health"])
        assert result.exit_code == 0
        assert "healthy" in result.output.lower()

    def test_vault_health_json(self, runner: CliRunner) -> None:
        from secrets_sdk.models import HealthCheck, HealthReport, HealthStatus

        report = HealthReport(checks=[
            HealthCheck(name="vault_connectivity", status=HealthStatus.HEALTHY, latency_ms=3.0),
        ])
        with patch("secrets_sdk.vault.VaultClient.health", return_value=report):
            result = runner.invoke(cli, ["vault-health", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["overall"] == "healthy"

    def test_vault_health_unhealthy_exits_1(self, runner: CliRunner) -> None:
        from secrets_sdk.models import HealthCheck, HealthReport, HealthStatus

        report = HealthReport(checks=[
            HealthCheck(name="vault_connectivity", status=HealthStatus.UNHEALTHY, detail="sealed"),
        ])
        with patch("secrets_sdk.vault.VaultClient.health", return_value=report):
            result = runner.invoke(cli, ["vault-health"])
        assert result.exit_code == 1


# ------------------------------------------------------------------
# scan
# ------------------------------------------------------------------


class TestScanCommand:
    def test_scan_clean_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "clean.py"
        f.write_text("x = 42\n")
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        assert "No plaintext secrets" in result.output

    def test_scan_finds_secret(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "AWS Access Key" in result.output

    def test_scan_json(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        result = runner.invoke(cli, ["scan", str(tmp_path), "--json-output"])
        assert result.exit_code == 0  # JSON mode exits 0
        data = json.loads(result.output)
        assert len(data) >= 1
        assert data[0]["pattern"] == "AWS Access Key"

    def test_scan_with_pattern_filter(self, runner: CliRunner, tmp_path: Path) -> None:
        f = tmp_path / "mixed.py"
        f.write_text(
            'KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'DSN = "postgres://u:p@h:5432/db"\n'
        )
        result = runner.invoke(cli, [
            "scan", str(tmp_path),
            "--pattern", "AWS Access Key",
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all(d["pattern"] == "AWS Access Key" for d in data)


# ------------------------------------------------------------------
# rotate-check
# ------------------------------------------------------------------


class TestRotateCheckCommand:
    def test_rotate_check_ok(self, runner: CliRunner) -> None:
        from secrets_sdk.models import AgeReport

        report = AgeReport(
            path="dev/app", current_version=1, age_days=10, max_age_days=90,
            needs_rotation=False, detail="Within policy",
        )
        with patch("secrets_sdk.rotation.check_secret_age", return_value=report):
            result = runner.invoke(cli, ["rotate-check", "--path", "dev/app"])
        assert result.exit_code == 0
        assert "OK" in result.output

    def test_rotate_check_overdue(self, runner: CliRunner) -> None:
        from secrets_sdk.models import AgeReport

        report = AgeReport(
            path="dev/old", current_version=2, age_days=120, max_age_days=90,
            needs_rotation=True, detail="Overdue",
        )
        with patch("secrets_sdk.rotation.check_secret_age", return_value=report):
            result = runner.invoke(cli, ["rotate-check", "--path", "dev/old"])
        assert result.exit_code == 1
        assert "OVERDUE" in result.output

    def test_rotate_check_json(self, runner: CliRunner) -> None:
        from secrets_sdk.models import AgeReport

        report = AgeReport(
            path="dev/app", current_version=1, age_days=10, max_age_days=90,
            needs_rotation=False, detail="OK",
        )
        with patch("secrets_sdk.rotation.check_secret_age", return_value=report):
            result = runner.invoke(cli, ["rotate-check", "--path", "dev/app", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["needs_rotation"] is False


# ------------------------------------------------------------------
# decrypt
# ------------------------------------------------------------------


class TestDecryptCommand:
    def test_decrypt_json(self, runner: CliRunner, tmp_path: Path) -> None:
        enc_file = tmp_path / "secret.enc.json"
        enc_file.write_text("{}")
        with patch("secrets_sdk.sops.decrypt_file", return_value={"password": "plaintext"}):
            result = runner.invoke(cli, ["decrypt", str(enc_file)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["password"] == "plaintext"

    def test_decrypt_yaml_format(self, runner: CliRunner, tmp_path: Path) -> None:
        enc_file = tmp_path / "secret.enc.yaml"
        enc_file.write_text("")
        with patch("secrets_sdk.sops.decrypt_file", return_value={"key": "value"}):
            result = runner.invoke(cli, ["decrypt", str(enc_file), "--output-format", "yaml"])
        assert result.exit_code == 0
        assert "key:" in result.output

    def test_decrypt_failure(self, runner: CliRunner, tmp_path: Path) -> None:
        enc_file = tmp_path / "bad.enc.json"
        enc_file.write_text("{}")
        with patch("secrets_sdk.sops.decrypt_file", side_effect=Exception("decryption failed")):
            result = runner.invoke(cli, ["decrypt", str(enc_file)])
        assert result.exit_code == 1
        assert "failed" in result.output.lower()


# ------------------------------------------------------------------
# sirm-init
# ------------------------------------------------------------------


class TestSIRMInitCommand:
    def test_sirm_init_text(self, runner: CliRunner, tmp_path: Path) -> None:
        with patch("secrets_sdk.sirm.bootstrap.shutil.which", return_value="/usr/bin/tool"), \
             patch("secrets_sdk.sirm.context.subprocess.run",
                   return_value=MagicMock(returncode=0, stdout="main", stderr="")), \
             patch("secrets_sdk.sirm.context.shutil.which", return_value="/usr/bin/vault"):
            result = runner.invoke(cli, [
                "sirm-init",
                "--operator", "analyst",
                "--session-dir", str(tmp_path / "sessions"),
                "--repo-root", str(tmp_path),
            ])
        assert result.exit_code == 0

    def test_sirm_init_json(self, runner: CliRunner, tmp_path: Path) -> None:
        with patch("secrets_sdk.sirm.bootstrap.shutil.which", return_value="/usr/bin/tool"), \
             patch("secrets_sdk.sirm.context.subprocess.run",
                   return_value=MagicMock(returncode=0, stdout="main", stderr="")), \
             patch("secrets_sdk.sirm.context.shutil.which", return_value="/usr/bin/vault"):
            result = runner.invoke(cli, [
                "sirm-init",
                "--operator", "analyst",
                "--session-dir", str(tmp_path / "sessions"),
                "--repo-root", str(tmp_path),
                "--json-output",
            ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["operator"] == "analyst"
        assert data["state"] == "ACTIVE"

    def test_sirm_init_bootstrap_fail(self, runner: CliRunner, tmp_path: Path) -> None:
        def which_side(tool: str) -> str | None:
            return None if tool == "git" else f"/usr/bin/{tool}"

        with patch("secrets_sdk.sirm.bootstrap.shutil.which", side_effect=which_side):
            result = runner.invoke(cli, [
                "sirm-init",
                "--operator", "analyst",
                "--session-dir", str(tmp_path),
                "--repo-root", str(tmp_path),
            ])
        assert result.exit_code == 1

    def test_sirm_init_classification(self, runner: CliRunner, tmp_path: Path) -> None:
        with patch("secrets_sdk.sirm.bootstrap.shutil.which", return_value="/usr/bin/tool"), \
             patch("secrets_sdk.sirm.context.subprocess.run",
                   return_value=MagicMock(returncode=0, stdout="main", stderr="")), \
             patch("secrets_sdk.sirm.context.shutil.which", return_value="/usr/bin/vault"):
            result = runner.invoke(cli, [
                "sirm-init",
                "--operator", "analyst",
                "--classification", "SECRET",
                "--session-dir", str(tmp_path / "sessions"),
                "--repo-root", str(tmp_path),
                "--json-output",
            ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["classification"] == "SECRET"


# ------------------------------------------------------------------
# sirm-status
# ------------------------------------------------------------------


class TestSIRMStatusCommand:
    def test_sirm_status_text(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-status", str(saved)])
        assert result.exit_code == 0
        assert "ACTIVE" in result.output
        assert "analyst" in result.output

    def test_sirm_status_json(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-status", str(saved), "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["state"] == "ACTIVE"

    def test_sirm_status_sealed(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        session.close()
        session.seal()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-status", str(saved), "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["state"] == "SEALED"
        assert data["seal_hash"] is not None
        assert len(data["seal_hash"]) == 64

    def test_sirm_status_nonexistent(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["sirm-status", "/nonexistent/file.json"])
        assert result.exit_code != 0


# ------------------------------------------------------------------
# sirm-seal
# ------------------------------------------------------------------


class TestSIRMSealCommand:
    def test_sirm_seal_text(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-seal", str(saved), "--reason", "Test"])
        assert result.exit_code == 0
        assert "sealed" in result.output.lower()

    def test_sirm_seal_json(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-seal", str(saved), "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["state"] == "SEALED"
        assert len(data["seal_hash"]) == 64


# ------------------------------------------------------------------
# sirm-report
# ------------------------------------------------------------------


class TestSIRMReportCommand:
    def test_sirm_report_markdown(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-report", str(saved)])
        assert result.exit_code == 0
        assert "# SIRM Session Report" in result.output

    def test_sirm_report_json(self, runner: CliRunner, tmp_path: Path) -> None:
        from secrets_sdk.sirm import SIRMSession
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        result = runner.invoke(cli, ["sirm-report", str(saved), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "executive_summary" in data

    def test_sirm_report_nonexistent(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["sirm-report", "/nonexistent/session.json"])
        assert result.exit_code != 0


# ------------------------------------------------------------------
# version
# ------------------------------------------------------------------


class TestVersionCommand:
    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "secrets-sdk" in result.output
        assert "0.1.0" in result.output
