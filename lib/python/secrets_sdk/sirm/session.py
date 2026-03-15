"""SIRM session lifecycle management.

Provides create, load, suspend, resume, close, and seal operations
with full audit trail and tamper-evident sealing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secrets_sdk.sirm.models import (
    SessionLogEntry,
    SessionRecord,
    SessionState,
)

logger = logging.getLogger(__name__)

# Valid state transitions
_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.INITIALIZING: {SessionState.ACTIVE},
    SessionState.ACTIVE: {SessionState.SUSPENDED, SessionState.CLOSED},
    SessionState.SUSPENDED: {SessionState.ACTIVE, SessionState.CLOSED},
    SessionState.CLOSED: {SessionState.SEALED},
    SessionState.SEALED: set(),  # terminal
}


class SIRMSessionError(Exception):
    """Raised on invalid session operations."""


class SIRMSession:
    """Core session manager for SIRM incident response sessions.

    Manages the full session lifecycle: create -> activate -> suspend/resume
    -> close -> seal.  Every state transition is logged with timestamp,
    operator, and reason.  Sessions persist to JSON files in a configurable
    session directory.
    """

    def __init__(self, record: SessionRecord) -> None:
        self._record = record

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._record.session_id

    @property
    def state(self) -> SessionState:
        return self._record.state

    @property
    def operator(self) -> str:
        return self._record.operator

    @property
    def classification(self) -> str:
        return self._record.classification

    @property
    def record(self) -> SessionRecord:
        return self._record

    @property
    def log(self) -> list[SessionLogEntry]:
        return self._record.log

    @property
    def is_sealed(self) -> bool:
        return self._record.state == SessionState.SEALED

    @property
    def seal_hash(self) -> str:
        return self._record.seal_hash

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        operator: str,
        classification: str = "UNCLASSIFIED",
        session_dir: str | Path = ".",
        evidence_dir: str | Path | None = None,
    ) -> "SIRMSession":
        """Create a new SIRM session.

        Args:
            operator: Identity of the session operator.
            classification: Classification level for the session.
            session_dir: Directory for session persistence files.
            evidence_dir: Directory for evidence (defaults to session_dir/evidence).
        """
        session_dir = Path(session_dir)
        if evidence_dir is None:
            evidence_dir = session_dir / "evidence"
        else:
            evidence_dir = Path(evidence_dir)

        record = SessionRecord(
            operator=operator,
            classification=classification,
            session_dir=str(session_dir),
            evidence_dir=str(evidence_dir),
            state=SessionState.INITIALIZING,
        )

        session = cls(record)
        session._log_action("session_create", f"Session created by {operator}")
        logger.info("SIRM session %s created by %s", record.session_id, operator)
        return session

    @classmethod
    def load(cls, path: str | Path) -> "SIRMSession":
        """Load an existing session from a JSON file.

        Args:
            path: Path to the session JSON file.

        Returns:
            Loaded SIRMSession instance.

        Raises:
            SIRMSessionError: If the file cannot be loaded or parsed.
        """
        path = Path(path)
        if not path.exists():
            raise SIRMSessionError(f"Session file not found: {path}")

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            record = SessionRecord.model_validate(data)
        except Exception as exc:
            raise SIRMSessionError(f"Failed to load session from {path}: {exc}") from exc

        session = cls(record)
        session._log_action("session_load", f"Session loaded from {path}")
        logger.info("SIRM session %s loaded from %s", record.session_id, path)
        return session

    # ------------------------------------------------------------------
    # Lifecycle methods
    # ------------------------------------------------------------------

    def activate(self, reason: str = "") -> None:
        """Transition session to ACTIVE state (from INITIALIZING or SUSPENDED)."""
        self._transition(SessionState.ACTIVE, reason or "Session activated")

    def suspend(self, reason: str = "") -> None:
        """Suspend an active session."""
        self._transition(SessionState.SUSPENDED, reason or "Session suspended")

    def resume(self, reason: str = "") -> None:
        """Resume a suspended session."""
        self._transition(SessionState.ACTIVE, reason or "Session resumed")

    def close(self, reason: str = "") -> None:
        """Close a session (active or suspended)."""
        self._transition(SessionState.CLOSED, reason or "Session closed")

    def seal(self) -> str:
        """Seal a closed session with SHA-256 tamper-evidence hash.

        Returns:
            The seal hash string.

        Raises:
            SIRMSessionError: If session is not in CLOSED state.
        """
        self._transition(SessionState.SEALED, "Session sealed with integrity hash")
        seal_hash = self._record.compute_seal_hash()
        self._record.seal_hash = seal_hash
        self._save()
        logger.info("SIRM session %s sealed: %s", self.session_id, seal_hash)
        return seal_hash

    def verify_seal(self) -> bool:
        """Verify the integrity of a sealed session.

        Returns:
            True if the seal hash matches, False otherwise.

        Raises:
            SIRMSessionError: If session is not sealed.
        """
        if self._record.state != SessionState.SEALED:
            raise SIRMSessionError("Cannot verify seal: session is not sealed")
        if not self._record.seal_hash:
            raise SIRMSessionError("Cannot verify seal: no seal hash present")
        computed = self._record.compute_seal_hash()
        return computed == self._record.seal_hash

    # ------------------------------------------------------------------
    # Session logging
    # ------------------------------------------------------------------

    def log_action(self, action: str, detail: str = "") -> None:
        """Add an action entry to the session audit log.

        This is the public interface for logging arbitrary actions
        during the session lifecycle.
        """
        self._log_action(action, detail)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path | None = None) -> Path:
        """Save session record to a JSON file.

        Args:
            path: Explicit file path. If None, saves to session_dir/session-<id>.json.

        Returns:
            Path to the saved file.
        """
        return self._save(path)

    def to_dict(self) -> dict[str, Any]:
        """Export session record as a dictionary."""
        return self._record.model_dump(mode="json")

    # ------------------------------------------------------------------
    # Context attachment
    # ------------------------------------------------------------------

    def attach_context(self, context: dict[str, Any]) -> None:
        """Attach an environment context snapshot to the session."""
        self._record.context_snapshot = context
        self._record.updated_at = datetime.now(timezone.utc)
        self._log_action("context_attach", "Environment context snapshot attached")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _transition(self, target: SessionState, reason: str) -> None:
        """Execute a state transition with validation and logging."""
        current = self._record.state
        allowed = _TRANSITIONS.get(current, set())
        if target not in allowed:
            raise SIRMSessionError(
                f"Invalid state transition: {current.value} -> {target.value}"
            )
        self._log_action(
            f"state_transition",
            reason,
            state_before=current,
            state_after=target,
        )
        self._record.state = target
        self._record.updated_at = datetime.now(timezone.utc)

    def _log_action(
        self,
        action: str,
        detail: str = "",
        state_before: SessionState | None = None,
        state_after: SessionState | None = None,
    ) -> None:
        """Append an entry to the session audit log."""
        entry = SessionLogEntry(
            operator=self._record.operator,
            action=action,
            detail=detail,
            state_before=state_before,
            state_after=state_after,
        )
        self._record.log.append(entry)

    def _save(self, path: str | Path | None = None) -> Path:
        """Internal save implementation."""
        if path is None:
            session_dir = Path(self._record.session_dir)
            session_dir.mkdir(parents=True, exist_ok=True)
            path = session_dir / f"session-{self._record.session_id}.json"
        else:
            path = Path(path)

        path.parent.mkdir(parents=True, exist_ok=True)
        data = self._record.model_dump(mode="json")
        path.write_text(
            json.dumps(data, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        logger.debug("Session %s saved to %s", self.session_id, path)
        return path
