"""Pydantic models for the SIRM (Security Incident Response Management) framework.

All data structures used across SIRM modules are defined here to maintain
a single source of truth and avoid circular imports.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SessionState(str, Enum):
    """SIRM session lifecycle states."""

    INITIALIZING = "INITIALIZING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"
    SEALED = "SEALED"


class PhaseResult(str, Enum):
    """Result of a bootstrap phase."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class ClaimClassification(str, Enum):
    """Douglas Mode claim classification codes.

    F = Fact (increases evidentiary weight)
    O = Observation (increases evidentiary weight)
    I = Inference (conditional weight only)
    H = Hypothesis (no weight until supported)
    """

    FACT = "F"
    OBSERVATION = "O"
    INFERENCE = "I"
    HYPOTHESIS = "H"


class ConfidenceLevel(str, Enum):
    """Correlation-scale confidence ratings per Douglas Mode."""

    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    DOMINANT = "dominant"


# ---------------------------------------------------------------------------
# Session models
# ---------------------------------------------------------------------------


class SessionLogEntry(BaseModel):
    """A single entry in the session audit log."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    operator: str = ""
    action: str
    detail: str = ""
    state_before: SessionState | None = None
    state_after: SessionState | None = None


class SessionRecord(BaseModel):
    """Persistent session record serialized to JSON."""

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    operator: str = ""
    classification: str = "UNCLASSIFIED"
    state: SessionState = SessionState.INITIALIZING
    session_dir: str = ""
    evidence_dir: str = ""
    log: list[SessionLogEntry] = Field(default_factory=list)
    context_snapshot: dict[str, Any] = Field(default_factory=dict)
    seal_hash: str = ""

    def compute_seal_hash(self) -> str:
        """Compute SHA-256 hash of the session record for tamper evidence.

        Excludes the seal_hash field itself from the computation.
        """
        data = self.model_dump(mode="json", exclude={"seal_hash"})
        canonical = _canonical_json(data)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Bootstrap models
# ---------------------------------------------------------------------------


class ToolCheck(BaseModel):
    """Result of checking a single required tool."""

    tool: str
    found: bool
    version: str = ""
    path: str = ""


class PhaseReport(BaseModel):
    """Result of a single bootstrap phase."""

    phase: int
    name: str
    result: PhaseResult
    detail: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class BootstrapReport(BaseModel):
    """Aggregated bootstrap result across all phases."""

    phases: list[PhaseReport] = Field(default_factory=list)
    overall: PhaseResult = PhaseResult.PASS
    session_id: str = ""

    @property
    def passed(self) -> bool:
        return self.overall != PhaseResult.FAIL


# ---------------------------------------------------------------------------
# Context models
# ---------------------------------------------------------------------------


class GitState(BaseModel):
    """Snapshot of git repository state."""

    branch: str = ""
    commit_hash: str = ""
    commit_message: str = ""
    is_dirty: bool = False
    untracked_count: int = 0
    remote_url: str = ""
    ahead: int = 0
    behind: int = 0


class VaultHealth(BaseModel):
    """Vault server health snapshot."""

    reachable: bool = False
    initialized: bool = False
    sealed: bool = True
    standby: bool = False
    version: str = ""
    addr: str = ""
    token_valid: bool = False
    token_ttl: int = 0


class SopsConfig(BaseModel):
    """SOPS configuration snapshot."""

    config_found: bool = False
    config_path: str = ""
    creation_rules_count: int = 0
    key_types: list[str] = Field(default_factory=list)


class IdentityInventory(BaseModel):
    """Current operator identity information."""

    git_user: str = ""
    git_email: str = ""
    vault_entity: str = ""
    vault_token_accessor: str = ""
    ssh_keys: list[str] = Field(default_factory=list)
    gpg_keys: list[str] = Field(default_factory=list)


class CertStatus(BaseModel):
    """Certificate status summary."""

    ca_certs_found: int = 0
    client_certs_found: int = 0
    expired_certs: int = 0
    expiring_soon: int = 0  # within 30 days


class PlatformInfo(BaseModel):
    """Host platform information."""

    os: str = ""
    os_version: str = ""
    hostname: str = ""
    python_version: str = ""
    arch: str = ""


class SessionContext(BaseModel):
    """Full environment context snapshot for a SIRM session."""

    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    git_state: GitState = Field(default_factory=GitState)
    vault_health: VaultHealth = Field(default_factory=VaultHealth)
    sops_config: SopsConfig = Field(default_factory=SopsConfig)
    identity_inventory: IdentityInventory = Field(default_factory=IdentityInventory)
    cert_status: CertStatus = Field(default_factory=CertStatus)
    environment_vars: dict[str, str] = Field(default_factory=dict)
    platform_info: PlatformInfo = Field(default_factory=PlatformInfo)


# ---------------------------------------------------------------------------
# Evidence models
# ---------------------------------------------------------------------------


class CustodyEntry(BaseModel):
    """A single chain-of-custody transfer record."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    from_party: str
    to_party: str
    reason: str = ""


class EvidenceItem(BaseModel):
    """A registered evidence item with integrity tracking."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    sha256: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    collected_by: str = ""
    description: str = ""
    classification: str = "UNCLASSIFIED"
    chain_of_custody: list[CustodyEntry] = Field(default_factory=list)


class EvidenceManifest(BaseModel):
    """Exportable manifest of all evidence items."""

    session_id: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    items: list[EvidenceItem] = Field(default_factory=list)
    manifest_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 of the manifest for integrity."""
        data = self.model_dump(mode="json", exclude={"manifest_hash"})
        canonical = _canonical_json(data)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Timeline models
# ---------------------------------------------------------------------------


class TimelineEvent(BaseModel):
    """A single event in an incident timeline."""

    timestamp: datetime
    source: str
    event_type: str
    description: str
    evidence_refs: list[str] = Field(default_factory=list)
    confidence: ClaimClassification = ClaimClassification.OBSERVATION


# ---------------------------------------------------------------------------
# Report models
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A finding from a SIRM session."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    confidence: ConfidenceLevel = ConfidenceLevel.MODERATE
    evidence_refs: list[str] = Field(default_factory=list)
    classification: ClaimClassification = ClaimClassification.OBSERVATION


class Recommendation(BaseModel):
    """A recommendation from a SIRM session."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    priority: str = "medium"  # critical, high, medium, low
    finding_refs: list[str] = Field(default_factory=list)


class ReportData(BaseModel):
    """Complete session report data structure."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""
    operator: str = ""
    classification: str = "UNCLASSIFIED"
    executive_summary: str = ""
    session_metadata: dict[str, Any] = Field(default_factory=dict)
    environment_context: dict[str, Any] = Field(default_factory=dict)
    timeline_events: list[TimelineEvent] = Field(default_factory=list)
    evidence_manifest: EvidenceManifest | None = None
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_json(data: Any) -> str:
    """Produce deterministic JSON for hash computation."""
    import json

    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
