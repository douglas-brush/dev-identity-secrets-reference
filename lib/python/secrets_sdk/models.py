"""Shared data models for the secrets SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SecretMetadata(BaseModel):
    """Metadata about a secret stored in Vault KV v2."""

    path: str
    version: int = 1
    created_time: datetime | None = None
    deletion_time: datetime | None = None
    destroyed: bool = False
    custom_metadata: dict[str, str] = Field(default_factory=dict)

    @property
    def age_seconds(self) -> float | None:
        """Return the age of this secret in seconds, or None if no creation time."""
        if self.created_time is None:
            return None
        now = datetime.now(timezone.utc)
        ct = self.created_time
        if ct.tzinfo is None:
            ct = ct.replace(tzinfo=timezone.utc)
        return (now - ct).total_seconds()


class LeaseInfo(BaseModel):
    """Information about a Vault dynamic secret lease."""

    lease_id: str
    lease_duration: int  # seconds
    renewable: bool = False
    request_id: str = ""
    data: dict[str, Any] = Field(default_factory=dict)

    @property
    def expires_at(self) -> datetime:
        """Estimated expiration time based on creation + duration."""
        return datetime.now(timezone.utc)


class CertInfo(BaseModel):
    """Information about an issued certificate."""

    certificate: str
    issuing_ca: str
    ca_chain: list[str] = Field(default_factory=list)
    private_key: str = ""
    private_key_type: str = ""
    serial_number: str = ""
    expiration: int = 0  # Unix timestamp

    @property
    def expires_at(self) -> datetime | None:
        """Expiration as a datetime."""
        if self.expiration == 0:
            return None
        return datetime.fromtimestamp(self.expiration, tz=timezone.utc)

    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        exp = self.expires_at
        if exp is None:
            return False
        return datetime.now(timezone.utc) > exp


class SSHCertInfo(BaseModel):
    """Information about a signed SSH certificate."""

    signed_key: str
    serial_number: str = ""


class TransitResult(BaseModel):
    """Result of a Vault Transit encrypt/decrypt operation."""

    ciphertext: str = ""
    plaintext: str = ""
    key_version: int = 0


class AuditEventType(str, Enum):
    """Types of audit events the SDK can emit."""

    SECRET_READ = "secret_read"
    SECRET_WRITE = "secret_write"
    SECRET_DELETE = "secret_delete"
    SECRET_ROTATE = "secret_rotate"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    LEASE_RENEW = "lease_renew"
    LEASE_REVOKE = "lease_revoke"
    CERT_ISSUE = "cert_issue"
    SSH_SIGN = "ssh_sign"
    TRANSIT_ENCRYPT = "transit_encrypt"
    TRANSIT_DECRYPT = "transit_decrypt"
    CONFIG_VALIDATE = "config_validate"
    SOPS_DECRYPT = "sops_decrypt"
    SOPS_ENCRYPT = "sops_encrypt"
    SCAN_SECRETS = "scan_secrets"


class AuditEvent(BaseModel):
    """An auditable event from SDK operations."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType
    path: str = ""
    success: bool = True
    detail: str = ""
    actor: str = ""

    def as_log_line(self) -> str:
        """Format as a single structured log line."""
        status = "OK" if self.success else "FAIL"
        ts = self.timestamp.isoformat()
        parts = [f"ts={ts}", f"event={self.event_type.value}", f"status={status}"]
        if self.path:
            parts.append(f"path={self.path}")
        if self.actor:
            parts.append(f"actor={self.actor}")
        if self.detail:
            parts.append(f"detail={self.detail}")
        return " ".join(parts)


class HealthStatus(str, Enum):
    """Health check status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class HealthCheck(BaseModel):
    """A single health check result."""

    name: str
    status: HealthStatus = HealthStatus.UNKNOWN
    detail: str = ""
    latency_ms: float = 0.0


class HealthReport(BaseModel):
    """Aggregated health report across all checked systems."""

    checks: list[HealthCheck] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def overall_status(self) -> HealthStatus:
        """Derive overall status from individual checks."""
        if not self.checks:
            return HealthStatus.UNKNOWN
        statuses = {c.status for c in self.checks}
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY
        return HealthStatus.DEGRADED

    def summary(self) -> str:
        """One-line summary string."""
        parts: list[str] = []
        for check in self.checks:
            parts.append(f"{check.name}: {check.status.value}")
        overall = self.overall_status.value.upper()
        return f"[{overall}] " + " | ".join(parts)


class SecretFinding(BaseModel):
    """A finding from plaintext secret scanning."""

    file_path: str
    line_number: int
    pattern_name: str
    matched_text: str = ""
    severity: str = "high"


class AgeReport(BaseModel):
    """Report on the age of a secret."""

    path: str
    current_version: int = 0
    created_time: datetime | None = None
    age_days: float = 0.0
    max_age_days: float = 90.0
    needs_rotation: bool = False
    detail: str = ""
