"""Tests for Pydantic models — validation, serialization, defaults, and computed properties."""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

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


# ------------------------------------------------------------------
# SecretMetadata
# ------------------------------------------------------------------


class TestSecretMetadata:
    def test_defaults(self) -> None:
        meta = SecretMetadata(path="dev/app")
        assert meta.path == "dev/app"
        assert meta.version == 1
        assert meta.created_time is None
        assert meta.deletion_time is None
        assert meta.destroyed is False
        assert meta.custom_metadata == {}

    def test_age_seconds_none_without_created(self) -> None:
        meta = SecretMetadata(path="test")
        assert meta.age_seconds is None

    def test_age_seconds_with_created(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        meta = SecretMetadata(path="test", created_time=past)
        age = meta.age_seconds
        assert age is not None
        assert 3500 < age < 3700  # ~1 hour

    def test_age_seconds_naive_created(self) -> None:
        past = datetime.now() - timedelta(hours=1)
        meta = SecretMetadata(path="test", created_time=past)
        age = meta.age_seconds
        assert age is not None
        assert age > 0

    def test_serialization_roundtrip(self) -> None:
        now = datetime.now(timezone.utc)
        meta = SecretMetadata(
            path="dev/app", version=3, created_time=now,
            custom_metadata={"owner": "team-a"},
        )
        data = meta.model_dump(mode="json")
        restored = SecretMetadata.model_validate(data)
        assert restored.path == "dev/app"
        assert restored.version == 3
        assert restored.custom_metadata == {"owner": "team-a"}


# ------------------------------------------------------------------
# LeaseInfo
# ------------------------------------------------------------------


class TestLeaseInfo:
    def test_defaults(self) -> None:
        lease = LeaseInfo(lease_id="abc", lease_duration=3600)
        assert lease.renewable is False
        assert lease.request_id == ""
        assert lease.data == {}

    def test_expires_at_returns_datetime(self) -> None:
        lease = LeaseInfo(lease_id="abc", lease_duration=3600)
        assert isinstance(lease.expires_at, datetime)


# ------------------------------------------------------------------
# CertInfo
# ------------------------------------------------------------------


class TestCertInfo:
    def test_not_expired(self) -> None:
        future = int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp())
        cert = CertInfo(
            certificate="CERT", issuing_ca="CA", expiration=future,
        )
        assert cert.is_expired is False
        assert cert.expires_at is not None

    def test_expired(self) -> None:
        past = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp())
        cert = CertInfo(certificate="CERT", issuing_ca="CA", expiration=past)
        assert cert.is_expired is True

    def test_no_expiration(self) -> None:
        cert = CertInfo(certificate="CERT", issuing_ca="CA")
        assert cert.expiration == 0
        assert cert.expires_at is None
        assert cert.is_expired is False


# ------------------------------------------------------------------
# TransitResult / SSHCertInfo
# ------------------------------------------------------------------


class TestTransitResult:
    def test_defaults(self) -> None:
        r = TransitResult()
        assert r.ciphertext == ""
        assert r.plaintext == ""
        assert r.key_version == 0


class TestSSHCertInfo:
    def test_defaults(self) -> None:
        info = SSHCertInfo(signed_key="ssh-cert")
        assert info.serial_number == ""


# ------------------------------------------------------------------
# AuditEvent
# ------------------------------------------------------------------


class TestAuditEvent:
    def test_defaults(self) -> None:
        event = AuditEvent(event_type=AuditEventType.SECRET_READ)
        assert event.success is True
        assert event.path == ""
        assert event.timestamp.tzinfo is not None

    def test_as_log_line(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.AUTH_FAILURE,
            path="auth/token",
            success=False,
            actor="operator",
            detail="expired",
        )
        line = event.as_log_line()
        assert "event=auth_failure" in line
        assert "status=FAIL" in line
        assert "path=auth/token" in line
        assert "actor=operator" in line
        assert "detail=expired" in line

    def test_all_event_types(self) -> None:
        for et in AuditEventType:
            event = AuditEvent(event_type=et)
            assert et.value in event.as_log_line()


# ------------------------------------------------------------------
# HealthCheck / HealthReport
# ------------------------------------------------------------------


class TestHealthCheck:
    def test_defaults(self) -> None:
        hc = HealthCheck(name="test")
        assert hc.status == HealthStatus.UNKNOWN
        assert hc.latency_ms == 0.0


class TestHealthReport:
    def test_overall_unknown_when_empty(self) -> None:
        report = HealthReport()
        assert report.overall_status == HealthStatus.UNKNOWN

    def test_overall_healthy(self) -> None:
        report = HealthReport(checks=[
            HealthCheck(name="a", status=HealthStatus.HEALTHY),
            HealthCheck(name="b", status=HealthStatus.HEALTHY),
        ])
        assert report.overall_status == HealthStatus.HEALTHY

    def test_overall_degraded(self) -> None:
        report = HealthReport(checks=[
            HealthCheck(name="a", status=HealthStatus.HEALTHY),
            HealthCheck(name="b", status=HealthStatus.DEGRADED),
        ])
        assert report.overall_status == HealthStatus.DEGRADED

    def test_overall_unhealthy_trumps_degraded(self) -> None:
        report = HealthReport(checks=[
            HealthCheck(name="a", status=HealthStatus.DEGRADED),
            HealthCheck(name="b", status=HealthStatus.UNHEALTHY),
        ])
        assert report.overall_status == HealthStatus.UNHEALTHY

    def test_summary_string(self) -> None:
        report = HealthReport(checks=[
            HealthCheck(name="connectivity", status=HealthStatus.HEALTHY),
        ])
        s = report.summary()
        assert "[HEALTHY]" in s
        assert "connectivity" in s


# ------------------------------------------------------------------
# SecretFinding
# ------------------------------------------------------------------


class TestSecretFinding:
    def test_defaults(self) -> None:
        f = SecretFinding(file_path="test.py", line_number=1, pattern_name="test")
        assert f.matched_text == ""
        assert f.severity == "high"

    def test_full_init(self) -> None:
        f = SecretFinding(
            file_path="app.py", line_number=42,
            pattern_name="AWS Access Key",
            matched_text="AKIA...",
            severity="critical",
        )
        assert f.file_path == "app.py"
        assert f.severity == "critical"


# ------------------------------------------------------------------
# AgeReport
# ------------------------------------------------------------------


class TestAgeReport:
    def test_defaults(self) -> None:
        r = AgeReport(path="test/secret")
        assert r.current_version == 0
        assert r.age_days == 0.0
        assert r.max_age_days == 90.0
        assert r.needs_rotation is False

    def test_full_init(self) -> None:
        now = datetime.now(timezone.utc)
        r = AgeReport(
            path="test/secret",
            current_version=5,
            created_time=now,
            age_days=100.0,
            max_age_days=90.0,
            needs_rotation=True,
            detail="Overdue",
        )
        assert r.needs_rotation is True
        assert r.detail == "Overdue"


# ------------------------------------------------------------------
# Enum coverage
# ------------------------------------------------------------------


class TestEnums:
    def test_health_status_values(self) -> None:
        assert set(s.value for s in HealthStatus) == {"healthy", "degraded", "unhealthy", "unknown"}

    def test_audit_event_type_count(self) -> None:
        assert len(AuditEventType) >= 14
