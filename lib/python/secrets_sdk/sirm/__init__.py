"""SIRM — Security Incident Response Management framework.

Provides session lifecycle management, bootstrap protocol, context loading,
evidence chain tracking, timeline building, and report generation for
incident response operations with full chain of custody and audit trail.
"""

from __future__ import annotations

from secrets_sdk.sirm.bootstrap import SIRMBootstrap
from secrets_sdk.sirm.context import ContextLoader
from secrets_sdk.sirm.evidence import EvidenceChain, compute_sha256, compute_sha256_bytes
from secrets_sdk.sirm.models import (
    BootstrapReport,
    CertStatus,
    ClaimClassification,
    ConfidenceLevel,
    CustodyEntry,
    EvidenceItem,
    EvidenceManifest,
    Finding,
    GitState,
    IdentityInventory,
    PhaseReport,
    PhaseResult,
    PlatformInfo,
    Recommendation,
    ReportData,
    SessionContext,
    SessionLogEntry,
    SessionRecord,
    SessionState,
    SopsConfig,
    TimelineEvent,
    ToolCheck,
    VaultHealth,
)
from secrets_sdk.sirm.reporter import SessionReport
from secrets_sdk.sirm.session import SIRMSession, SIRMSessionError
from secrets_sdk.sirm.timeline import Timeline

__all__ = [
    # Core classes
    "SIRMSession",
    "SIRMSessionError",
    "SIRMBootstrap",
    "ContextLoader",
    "EvidenceChain",
    "Timeline",
    "SessionReport",
    # Utility functions
    "compute_sha256",
    "compute_sha256_bytes",
    # Models — Session
    "SessionState",
    "SessionLogEntry",
    "SessionRecord",
    # Models — Bootstrap
    "BootstrapReport",
    "PhaseReport",
    "PhaseResult",
    "ToolCheck",
    # Models — Context
    "SessionContext",
    "GitState",
    "VaultHealth",
    "SopsConfig",
    "IdentityInventory",
    "CertStatus",
    "PlatformInfo",
    # Models — Evidence
    "EvidenceItem",
    "EvidenceManifest",
    "CustodyEntry",
    # Models — Timeline
    "TimelineEvent",
    "ClaimClassification",
    # Models — Report
    "ReportData",
    "Finding",
    "Recommendation",
    "ConfidenceLevel",
]
