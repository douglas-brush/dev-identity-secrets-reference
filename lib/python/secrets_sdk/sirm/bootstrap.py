"""SIRM bootstrap protocol — initializes an IR session with full chain of custody.

Runs a five-phase bootstrap sequence:
  1. Environment validation (required tools)
  2. Identity verification (operator, Vault token, git config)
  3. Context gathering (git state, Vault health, SOPS config)
  4. Session initialization (create record, establish evidence dir, start audit)
  5. Dashboard generation (structured session-start output)
"""

from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from secrets_sdk.sirm.context import ContextLoader
from secrets_sdk.sirm.models import (
    BootstrapReport,
    PhaseReport,
    PhaseResult,
    ToolCheck,
)
from secrets_sdk.sirm.session import SIRMSession

logger = logging.getLogger(__name__)

# Tools required for full SIRM operation
REQUIRED_TOOLS = ["vault", "sops", "git", "openssl", "age"]


class SIRMBootstrap:
    """Runs the SIRM bootstrap sequence to initialize a session.

    Args:
        operator: Identity of the session operator.
        classification: Classification level for the session.
        session_dir: Directory for session files.
        repo_root: Repository root for context loading.
        required_tools: Override list of required tools.
    """

    def __init__(
        self,
        operator: str,
        classification: str = "UNCLASSIFIED",
        session_dir: str | Path = ".",
        repo_root: str | Path | None = None,
        required_tools: list[str] | None = None,
    ) -> None:
        self.operator = operator
        self.classification = classification
        self.session_dir = Path(session_dir)
        self.repo_root = Path(repo_root) if repo_root else Path.cwd()
        self.required_tools = required_tools or REQUIRED_TOOLS
        self._context_loader = ContextLoader(repo_root=self.repo_root)
        self._report = BootstrapReport()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def bootstrap(self) -> SIRMSession:
        """Run the full bootstrap sequence and return an active session.

        Returns:
            A fully initialized and activated SIRMSession.

        Raises:
            RuntimeError: If a critical phase fails.
        """
        phases: list[Callable[..., PhaseReport]] = [
            self._phase1_environment,
            self._phase2_identity,
            self._phase3_context,
            self._phase4_session_init,
            self._phase5_dashboard,
        ]

        session: SIRMSession | None = None
        context_data: dict[str, Any] = {}

        for phase_fn in phases:
            start = time.monotonic()
            report = phase_fn(session=session, context_data=context_data)
            report.duration_ms = (time.monotonic() - start) * 1000
            self._report.phases.append(report)

            if report.result == PhaseResult.FAIL:
                self._report.overall = PhaseResult.FAIL
                raise RuntimeError(
                    f"Bootstrap phase {report.phase} ({report.name}) failed: {report.detail}"
                )
            elif report.result == PhaseResult.WARN:
                if self._report.overall == PhaseResult.PASS:
                    self._report.overall = PhaseResult.WARN

            # Phase 4 creates the session
            if report.phase == 4 and "session" in report.data:
                session = report.data["session"]
                self._report.session_id = session.session_id

            # Phase 3 captures context
            if report.phase == 3 and "context" in report.data:
                context_data = report.data["context"]

        if session is None:
            raise RuntimeError("Bootstrap completed without creating a session")

        return session

    @property
    def report(self) -> BootstrapReport:
        """Access the bootstrap report after running."""
        return self._report

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------

    def _phase1_environment(self, **_: Any) -> PhaseReport:
        """Phase 1: Validate required tools are available."""
        checks: list[dict[str, Any]] = []
        missing: list[str] = []

        for tool in self.required_tools:
            path = shutil.which(tool)
            check = ToolCheck(
                tool=tool,
                found=path is not None,
                path=path or "",
            )
            checks.append(check.model_dump())
            if not path:
                missing.append(tool)

        result = PhaseResult.PASS
        detail = "All required tools found"
        if missing:
            # git is critical, others are warnings
            critical_missing = [t for t in missing if t in ("git",)]
            if critical_missing:
                result = PhaseResult.FAIL
                detail = f"Critical tools missing: {', '.join(critical_missing)}"
            else:
                result = PhaseResult.WARN
                detail = f"Optional tools missing: {', '.join(missing)}"

        return PhaseReport(
            phase=1,
            name="environment_validation",
            result=result,
            detail=detail,
            data={"tools": checks, "missing": missing},
        )

    def _phase2_identity(self, **_: Any) -> PhaseReport:
        """Phase 2: Verify operator identity."""
        identity = self._context_loader.load_identity_inventory()
        vault_health = self._context_loader.load_vault_health()

        issues: list[str] = []
        if not identity.git_user:
            issues.append("git user.name not configured")
        if not identity.git_email:
            issues.append("git user.email not configured")
        if not vault_health.token_valid:
            issues.append("Vault token not valid or not present")

        if any("git" in i for i in issues):
            result = PhaseResult.WARN
        elif issues:
            result = PhaseResult.WARN
        else:
            result = PhaseResult.PASS

        detail = "; ".join(issues) if issues else "Identity verified"

        return PhaseReport(
            phase=2,
            name="identity_verification",
            result=result,
            detail=detail,
            data={
                "identity": identity.model_dump(),
                "vault_token_valid": vault_health.token_valid,
            },
        )

    def _phase3_context(self, **_: Any) -> PhaseReport:
        """Phase 3: Gather full environment context."""
        try:
            context = self._context_loader.load_full_context()
            context_data = context.model_dump(mode="json")

            return PhaseReport(
                phase=3,
                name="context_gathering",
                result=PhaseResult.PASS,
                detail="Environment context captured",
                data={"context": context_data},
            )
        except Exception as exc:
            return PhaseReport(
                phase=3,
                name="context_gathering",
                result=PhaseResult.WARN,
                detail=f"Partial context gathered: {exc}",
                data={"context": {}},
            )

    def _phase4_session_init(
        self,
        context_data: dict[str, Any] | None = None,
        **_: Any,
    ) -> PhaseReport:
        """Phase 4: Initialize session record and evidence directory."""
        try:
            session = SIRMSession.create(
                operator=self.operator,
                classification=self.classification,
                session_dir=self.session_dir,
            )

            # Attach context
            if context_data:
                session.attach_context(context_data)

            # Create evidence directory
            evidence_dir = Path(session.record.evidence_dir)
            evidence_dir.mkdir(parents=True, exist_ok=True)

            # Activate the session
            session.activate("Bootstrap complete, session active")

            # Persist
            saved_path = session.save()

            return PhaseReport(
                phase=4,
                name="session_initialization",
                result=PhaseResult.PASS,
                detail=f"Session {session.session_id} initialized",
                data={
                    "session": session,
                    "session_id": session.session_id,
                    "saved_to": str(saved_path),
                    "evidence_dir": str(evidence_dir),
                },
            )
        except Exception as exc:
            return PhaseReport(
                phase=4,
                name="session_initialization",
                result=PhaseResult.FAIL,
                detail=f"Session initialization failed: {exc}",
            )

    def _phase5_dashboard(
        self,
        session: SIRMSession | None = None,
        context_data: dict[str, Any] | None = None,
        **_: Any,
    ) -> PhaseReport:
        """Phase 5: Generate structured session-start dashboard."""
        if session is None:
            return PhaseReport(
                phase=5,
                name="dashboard_generation",
                result=PhaseResult.FAIL,
                detail="No session available for dashboard",
            )

        dashboard = self._build_dashboard(session, context_data or {})

        return PhaseReport(
            phase=5,
            name="dashboard_generation",
            result=PhaseResult.PASS,
            detail="Dashboard generated",
            data={"dashboard": dashboard},
        )

    # ------------------------------------------------------------------
    # Dashboard builder
    # ------------------------------------------------------------------

    def _build_dashboard(
        self,
        session: SIRMSession,
        context_data: dict[str, Any],
    ) -> str:
        """Build a structured session-start dashboard."""
        git = context_data.get("git_state", {})
        vault = context_data.get("vault_health", {})
        sops = context_data.get("sops_config", {})

        branch = git.get("branch", "unknown")
        commit = git.get("commit_hash", "unknown")[:7]
        commit_msg = git.get("commit_message", "")
        is_dirty = git.get("is_dirty", False)

        vault_ok = vault.get("reachable", False) and not vault.get("sealed", True)
        sops_ok = sops.get("config_found", False)

        if vault_ok and sops_ok and not is_dirty:
            status_icon = "GREEN"
            status_reason = "clean"
        elif is_dirty or not vault_ok:
            status_icon = "YELLOW"
            reasons = []
            if is_dirty:
                reasons.append("dirty worktree")
            if not vault_ok:
                reasons.append("vault unreachable/sealed")
            status_reason = ", ".join(reasons)
        else:
            status_icon = "GREEN"
            status_reason = "operational"

        phases_summary = []
        for p in self._report.phases:
            phases_summary.append(f"  Phase {p.phase}: {p.name} [{p.result.value}] ({p.duration_ms:.0f}ms)")

        lines = [
            "+======================================================+",
            f"  SIRM Session — {session.session_id[:8]}",
            "+======================================================+",
            f"  Branch: {branch} | Commit: {commit} {commit_msg}",
            f"  Status: [{status_icon}] — {status_reason}",
            f"  Operator: {session.operator}",
            f"  Classification: {session.classification}",
            "+------------------------------------------------------+",
            "  BOOTSTRAP PHASES:",
            *phases_summary,
            "+------------------------------------------------------+",
            f"  Session State: {session.state.value}",
            f"  Evidence Dir: {session.record.evidence_dir}",
            f"  Vault: {'reachable' if vault_ok else 'unavailable'}",
            f"  SOPS: {'configured' if sops_ok else 'not found'}",
            "+======================================================+",
        ]

        return "\n".join(lines)
