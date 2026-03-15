"""Comprehensive tests for the SIRM (Security Incident Response Management) framework.

Covers session lifecycle, bootstrap, context loading, evidence chain integrity,
timeline operations, and report generation.
"""

from __future__ import annotations

import json
import os
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from secrets_sdk.sirm import (
    ClaimClassification,
    ConfidenceLevel,
    ContextLoader,
    EvidenceChain,
    PhaseResult,
    SessionReport,
    SessionState,
    SIRMBootstrap,
    SIRMSession,
    SIRMSessionError,
    Timeline,
    compute_sha256,
    compute_sha256_bytes,
)
from secrets_sdk.sirm.models import (
    BootstrapReport,
    CustodyEntry,
    EvidenceItem,
    EvidenceManifest,
    Finding,
    GitState,
    IdentityInventory,
    PhaseReport as PhaseReportModel,
    PlatformInfo,
    Recommendation,
    ReportData,
    SessionContext,
    SessionLogEntry,
    SessionRecord,
    SopsConfig,
    TimelineEvent,
    ToolCheck,
    VaultHealth,
)


# ======================================================================
# Session lifecycle tests
# ======================================================================


class TestSIRMSession:
    """Test session creation, state transitions, and persistence."""

    def test_create_session(self, tmp_path: Path) -> None:
        session = SIRMSession.create(
            operator="douglas_brush",
            classification="CONFIDENTIAL",
            session_dir=tmp_path,
        )
        assert session.state == SessionState.INITIALIZING
        assert session.operator == "douglas_brush"
        assert session.classification == "CONFIDENTIAL"
        assert len(session.session_id) == 36  # UUID format
        assert len(session.log) >= 1  # create log entry

    def test_full_lifecycle(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        assert session.state == SessionState.INITIALIZING

        session.activate("Starting investigation")
        assert session.state == SessionState.ACTIVE

        session.suspend("Lunch break")
        assert session.state == SessionState.SUSPENDED

        session.resume("Back from break")
        assert session.state == SessionState.ACTIVE

        session.close("Investigation complete")
        assert session.state == SessionState.CLOSED

        seal_hash = session.seal()
        assert session.state == SessionState.SEALED
        assert session.is_sealed
        assert len(seal_hash) == 64  # SHA-256 hex

    def test_invalid_transition_raises(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        # Cannot go directly from INITIALIZING to CLOSED
        with pytest.raises(SIRMSessionError, match="Invalid state transition"):
            session.close()

    def test_sealed_is_terminal(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        session.close()
        session.seal()
        with pytest.raises(SIRMSessionError, match="Invalid state transition"):
            session.activate()

    def test_seal_generates_tamper_evidence(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        session.close()
        seal_hash = session.seal()
        assert session.verify_seal()

    def test_verify_seal_detects_tamper(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        session.close()
        session.seal()
        # Tamper with the record
        session._record.operator = "tampered"
        assert not session.verify_seal()

    def test_verify_seal_fails_if_not_sealed(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        with pytest.raises(SIRMSessionError, match="not sealed"):
            session.verify_seal()

    def test_persist_and_load(self, tmp_path: Path) -> None:
        session = SIRMSession.create(
            operator="analyst",
            classification="SECRET",
            session_dir=tmp_path,
        )
        session.activate()
        session.log_action("test_action", "Testing persistence")
        saved = session.save()
        assert saved.exists()

        loaded = SIRMSession.load(saved)
        assert loaded.session_id == session.session_id
        assert loaded.state == SessionState.ACTIVE
        assert loaded.operator == "analyst"
        assert loaded.classification == "SECRET"

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(SIRMSessionError, match="not found"):
            SIRMSession.load("/nonexistent/path/session.json")

    def test_load_invalid_json_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json{{{")
        with pytest.raises(SIRMSessionError, match="Failed to load"):
            SIRMSession.load(bad_file)

    def test_session_log_records_all_transitions(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate("phase 1")
        session.suspend("pause")
        session.resume("continue")
        session.close("done")

        # Check log entries exist for each transition
        actions = [entry.action for entry in session.log]
        assert "session_create" in actions
        assert "state_transition" in actions
        log_with_transitions = [e for e in session.log if e.action == "state_transition"]
        assert len(log_with_transitions) == 4  # activate, suspend, resume, close

    def test_attach_context(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        ctx = {"git_state": {"branch": "main"}, "vault_health": {"reachable": True}}
        session.attach_context(ctx)
        assert session.record.context_snapshot == ctx

    def test_to_dict(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        data = session.to_dict()
        assert isinstance(data, dict)
        assert data["operator"] == "analyst"
        assert data["state"] == "INITIALIZING"


# ======================================================================
# Bootstrap tests
# ======================================================================


class TestSIRMBootstrap:
    """Test the bootstrap sequence with mocked external tools."""

    @patch("secrets_sdk.sirm.bootstrap.shutil.which")
    @patch("secrets_sdk.sirm.context.subprocess.run")
    @patch("secrets_sdk.sirm.context.shutil.which")
    def test_bootstrap_full_success(
        self,
        mock_ctx_which: MagicMock,
        mock_run: MagicMock,
        mock_boot_which: MagicMock,
        tmp_path: Path,
    ) -> None:
        # All tools found
        mock_boot_which.return_value = "/usr/bin/tool"
        mock_ctx_which.return_value = "/usr/bin/vault"

        # Mock subprocess calls
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="main",
            stderr="",
        )

        # Create a .sops.yaml for context loader
        sops_yaml = tmp_path / ".sops.yaml"
        sops_yaml.write_text("creation_rules:\n  - path_regex: '.*'\n    age: 'age1test'\n")

        bootstrap = SIRMBootstrap(
            operator="analyst",
            classification="UNCLASSIFIED",
            session_dir=str(tmp_path / "sessions"),
            repo_root=str(tmp_path),
        )

        session = bootstrap.bootstrap()
        assert session.state == SessionState.ACTIVE
        assert session.operator == "analyst"
        assert bootstrap.report.passed

    @patch("secrets_sdk.sirm.bootstrap.shutil.which")
    def test_bootstrap_missing_critical_tool(
        self,
        mock_which: MagicMock,
        tmp_path: Path,
    ) -> None:
        # git is missing (critical)
        def which_side_effect(tool: str) -> str | None:
            if tool == "git":
                return None
            return f"/usr/bin/{tool}"

        mock_which.side_effect = which_side_effect

        bootstrap = SIRMBootstrap(
            operator="analyst",
            session_dir=str(tmp_path),
            repo_root=str(tmp_path),
        )

        with pytest.raises(RuntimeError, match="Critical tools missing"):
            bootstrap.bootstrap()

    @patch("secrets_sdk.sirm.bootstrap.shutil.which")
    @patch("secrets_sdk.sirm.context.subprocess.run")
    @patch("secrets_sdk.sirm.context.shutil.which")
    def test_bootstrap_missing_optional_tool_warns(
        self,
        mock_ctx_which: MagicMock,
        mock_run: MagicMock,
        mock_boot_which: MagicMock,
        tmp_path: Path,
    ) -> None:
        # age is missing (optional)
        def which_side_effect(tool: str) -> str | None:
            if tool == "age":
                return None
            return f"/usr/bin/{tool}"

        mock_boot_which.side_effect = which_side_effect
        mock_ctx_which.return_value = "/usr/bin/vault"
        mock_run.return_value = MagicMock(returncode=0, stdout="main", stderr="")

        bootstrap = SIRMBootstrap(
            operator="analyst",
            session_dir=str(tmp_path / "sessions"),
            repo_root=str(tmp_path),
        )

        session = bootstrap.bootstrap()
        assert session.state == SessionState.ACTIVE
        assert bootstrap.report.overall == PhaseResult.WARN

    def test_bootstrap_report_has_all_phases(self, tmp_path: Path) -> None:
        with patch("secrets_sdk.sirm.bootstrap.shutil.which", return_value="/usr/bin/tool"), \
             patch("secrets_sdk.sirm.context.subprocess.run", return_value=MagicMock(returncode=0, stdout="main", stderr="")), \
             patch("secrets_sdk.sirm.context.shutil.which", return_value="/usr/bin/vault"):

            bootstrap = SIRMBootstrap(
                operator="analyst",
                session_dir=str(tmp_path / "sessions"),
                repo_root=str(tmp_path),
            )
            bootstrap.bootstrap()

            assert len(bootstrap.report.phases) == 5
            phase_names = [p.name for p in bootstrap.report.phases]
            assert "environment_validation" in phase_names
            assert "identity_verification" in phase_names
            assert "context_gathering" in phase_names
            assert "session_initialization" in phase_names
            assert "dashboard_generation" in phase_names


# ======================================================================
# Context loader tests
# ======================================================================


class TestContextLoader:
    """Test context loading with mocked external tools."""

    @patch("secrets_sdk.sirm.context.subprocess.run")
    def test_load_git_state(self, mock_run: MagicMock, tmp_path: Path) -> None:
        call_count = 0
        responses = [
            MagicMock(returncode=0, stdout="main"),  # branch
            MagicMock(returncode=0, stdout="abc123def456 feat: add feature"),  # commit
            MagicMock(returncode=0, stdout="M file.py\n?? new.txt"),  # status
            MagicMock(returncode=0, stdout="git@github.com:org/repo.git"),  # remote
            MagicMock(returncode=0, stdout="2\t1"),  # ahead/behind
        ]

        def run_side(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal call_count
            idx = min(call_count, len(responses) - 1)
            call_count += 1
            return responses[idx]

        mock_run.side_effect = run_side

        loader = ContextLoader(repo_root=tmp_path)
        git_state = loader.load_git_state()

        assert git_state.branch == "main"
        assert git_state.commit_hash == "abc123def456"
        assert git_state.commit_message == "feat: add feature"
        assert git_state.is_dirty
        assert git_state.untracked_count == 1

    def test_load_sops_config(self, tmp_path: Path) -> None:
        sops_yaml = tmp_path / ".sops.yaml"
        sops_yaml.write_text(textwrap.dedent("""\
            creation_rules:
              - path_regex: 'secrets/dev/.*'
                age: 'age1testkey'
              - path_regex: 'secrets/prod/.*'
                age: 'age1prodkey'
        """))

        loader = ContextLoader(repo_root=tmp_path)
        config = loader.load_sops_config()

        assert config.config_found
        assert config.creation_rules_count == 2
        assert "age" in config.key_types

    def test_load_sops_config_missing(self, tmp_path: Path) -> None:
        loader = ContextLoader(repo_root=tmp_path)
        config = loader.load_sops_config()
        assert not config.config_found

    def test_load_platform_info(self) -> None:
        loader = ContextLoader()
        info = loader.load_platform_info()
        assert info.os != ""
        assert info.python_version != ""
        assert info.arch != ""

    def test_load_environment_vars_redaction(self) -> None:
        with patch.dict(os.environ, {"VAULT_TOKEN": "s.SuperSecretTokenValue123", "VAULT_ADDR": "http://vault:8200"}):
            loader = ContextLoader()
            env_vars = loader.load_environment_vars()
            # Token should be redacted
            assert env_vars["VAULT_TOKEN"] == "****e123"
            # Addr should not be redacted
            assert env_vars["VAULT_ADDR"] == "http://vault:8200"

    @patch("secrets_sdk.sirm.context.subprocess.run")
    def test_load_full_context(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

        loader = ContextLoader(repo_root=tmp_path)
        ctx = loader.load_full_context()

        assert isinstance(ctx, SessionContext)
        assert ctx.platform_info.os != ""

    @patch("secrets_sdk.sirm.context.subprocess.run")
    def test_load_minimal_context(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

        loader = ContextLoader(repo_root=tmp_path)
        ctx = loader.load_minimal_context()

        assert isinstance(ctx, SessionContext)
        # Minimal context should have platform info
        assert ctx.platform_info.os != ""
        # SOPS and identity should be defaults
        assert not ctx.sops_config.config_found
        assert ctx.identity_inventory.git_user == ""

    def test_diff_context(self) -> None:
        before = SessionContext(
            git_state=GitState(branch="main", commit_hash="abc123"),
            vault_health=VaultHealth(reachable=True, sealed=False),
        )
        after = SessionContext(
            git_state=GitState(branch="feature", commit_hash="def456"),
            vault_health=VaultHealth(reachable=True, sealed=False),
        )

        diffs = ContextLoader.diff_context(before, after)
        assert "git_state" in diffs
        assert "branch" in diffs["git_state"]
        assert diffs["git_state"]["branch"]["before"] == "main"
        assert diffs["git_state"]["branch"]["after"] == "feature"
        # vault_health should not be in diffs (no changes)
        assert "vault_health" not in diffs

    def test_diff_context_env_vars(self) -> None:
        before = SessionContext(environment_vars={"VAULT_ADDR": "http://old:8200"})
        after = SessionContext(environment_vars={"VAULT_ADDR": "http://new:8200"})

        diffs = ContextLoader.diff_context(before, after)
        assert "environment_vars" in diffs


# ======================================================================
# Evidence chain tests
# ======================================================================


class TestEvidenceChain:
    """Test evidence registration, verification, and chain of custody."""

    def test_register_evidence(self, tmp_path: Path) -> None:
        evidence_file = tmp_path / "artifact.log"
        evidence_file.write_text("suspicious log entry here")

        chain = EvidenceChain(session_id="test-session")
        item = chain.register(
            source=evidence_file,
            collected_by="analyst",
            description="Suspicious log file",
            classification="CONFIDENTIAL",
        )

        assert item.sha256 != ""
        assert item.collected_by == "analyst"
        assert item.classification == "CONFIDENTIAL"
        assert len(item.chain_of_custody) == 1
        assert item.chain_of_custody[0].from_party == "source"
        assert chain.count == 1

    def test_verify_evidence_integrity(self, tmp_path: Path) -> None:
        evidence_file = tmp_path / "artifact.log"
        evidence_file.write_text("original content")

        chain = EvidenceChain()
        item = chain.register(source=evidence_file, collected_by="analyst")

        # Should verify OK
        assert chain.verify(item.id)

        # Tamper with the file
        evidence_file.write_text("tampered content")
        assert not chain.verify(item.id)

    def test_verify_missing_file(self, tmp_path: Path) -> None:
        evidence_file = tmp_path / "artifact.log"
        evidence_file.write_text("content")

        chain = EvidenceChain()
        item = chain.register(source=evidence_file, collected_by="analyst")

        evidence_file.unlink()
        assert not chain.verify(item.id)

    def test_verify_unknown_id_raises(self) -> None:
        chain = EvidenceChain()
        with pytest.raises(KeyError, match="not found"):
            chain.verify("nonexistent-id")

    def test_verify_all(self, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"
        f1.write_text("file 1 content")
        f2.write_text("file 2 content")

        chain = EvidenceChain()
        item1 = chain.register(source=f1, collected_by="analyst")
        item2 = chain.register(source=f2, collected_by="analyst")

        results = chain.verify_all()
        assert results[item1.id]
        assert results[item2.id]

        # Tamper with one
        f1.write_text("tampered")
        results = chain.verify_all()
        assert not results[item1.id]
        assert results[item2.id]

    def test_register_bytes(self) -> None:
        chain = EvidenceChain()
        data = b"API response body content"
        item = chain.register_bytes(
            data=data,
            source_label="api://vault/v1/sys/health",
            collected_by="analyst",
            description="Vault health API response",
        )
        assert item.sha256 == compute_sha256_bytes(data)
        assert chain.count == 1

    def test_custody_transfer(self, tmp_path: Path) -> None:
        evidence_file = tmp_path / "artifact.log"
        evidence_file.write_text("evidence content")

        chain = EvidenceChain()
        item = chain.register(source=evidence_file, collected_by="analyst_a")

        entry = chain.transfer(
            evidence_id=item.id,
            from_party="analyst_a",
            to_party="analyst_b",
            reason="Handoff for review",
        )

        assert len(item.chain_of_custody) == 2
        assert entry.from_party == "analyst_a"
        assert entry.to_party == "analyst_b"

    def test_custody_transfer_unknown_id(self) -> None:
        chain = EvidenceChain()
        with pytest.raises(KeyError):
            chain.transfer("bad-id", "a", "b")

    def test_export_manifest(self, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.txt"
        f1.write_text("evidence")

        chain = EvidenceChain(session_id="sess-001")
        chain.register(source=f1, collected_by="analyst")

        manifest = chain.export_manifest()
        assert manifest.session_id == "sess-001"
        assert len(manifest.items) == 1
        assert manifest.manifest_hash != ""

    def test_export_manifest_json(self, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.txt"
        f1.write_text("evidence")

        chain = EvidenceChain()
        chain.register(source=f1, collected_by="analyst")

        json_str = chain.export_manifest_json()
        data = json.loads(json_str)
        assert "items" in data
        assert "manifest_hash" in data

    def test_export_manifest_readable(self, tmp_path: Path) -> None:
        f1 = tmp_path / "file1.txt"
        f1.write_text("evidence")

        chain = EvidenceChain(session_id="sess-001")
        chain.register(
            source=f1,
            collected_by="analyst",
            description="Test evidence file",
        )

        readable = chain.export_manifest_readable()
        assert "EVIDENCE MANIFEST" in readable
        assert "sess-001" in readable
        assert "analyst" in readable

    def test_items_sorted_by_collection_time(self, tmp_path: Path) -> None:
        chain = EvidenceChain()
        for i in range(3):
            f = tmp_path / f"file{i}.txt"
            f.write_text(f"content {i}")
            chain.register(source=f, collected_by="analyst")

        items = chain.items
        for i in range(len(items) - 1):
            assert items[i].collected_at <= items[i + 1].collected_at


# ======================================================================
# SHA-256 utility tests
# ======================================================================


class TestSHA256:
    """Test SHA-256 computation utilities."""

    def test_compute_sha256_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h = compute_sha256(f)
        assert len(h) == 64
        # Known SHA-256 of "hello world" (with no trailing newline, but write_text adds none in this case)
        # Actually, "hello world" as text
        assert h == compute_sha256_bytes(b"hello world")

    def test_compute_sha256_bytes(self) -> None:
        h = compute_sha256_bytes(b"test data")
        assert len(h) == 64

    def test_compute_sha256_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            compute_sha256("/nonexistent/file.txt")


# ======================================================================
# Timeline tests
# ======================================================================


class TestTimeline:
    """Test timeline event management, filtering, and export."""

    def _make_timeline(self) -> Timeline:
        tl = Timeline()
        base = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        tl.add_event(base, "syslog", "info", "System startup")
        tl.add_event(base + timedelta(minutes=5), "vault", "auth", "Token authenticated")
        tl.add_event(base + timedelta(minutes=10), "syslog", "error", "Disk failure detected")
        tl.add_event(
            base + timedelta(minutes=15),
            "analyst",
            "observation",
            "Suspicious process found",
            confidence=ClaimClassification.OBSERVATION,
        )
        return tl

    def test_add_event(self) -> None:
        tl = Timeline()
        now = datetime.now(timezone.utc)
        event = tl.add_event(now, "test", "info", "Test event")
        assert event.source == "test"
        assert tl.count == 1

    def test_add_event_naive_timestamp(self) -> None:
        tl = Timeline()
        naive = datetime(2025, 1, 1, 12, 0, 0)
        event = tl.add_event(naive, "test", "info", "Naive TS")
        assert event.timestamp.tzinfo is not None

    def test_events_sorted(self) -> None:
        tl = self._make_timeline()
        events = tl.events
        for i in range(len(events) - 1):
            assert events[i].timestamp <= events[i + 1].timestamp

    def test_filter_by_time_range(self) -> None:
        tl = self._make_timeline()
        base = datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        filtered = tl.filter(
            start=base + timedelta(minutes=5),
            end=base + timedelta(minutes=10),
        )
        assert len(filtered) == 2

    def test_filter_by_source(self) -> None:
        tl = self._make_timeline()
        filtered = tl.filter(source="syslog")
        assert len(filtered) == 2

    def test_filter_by_event_type(self) -> None:
        tl = self._make_timeline()
        filtered = tl.filter(event_type="error")
        assert len(filtered) == 1

    def test_filter_by_confidence(self) -> None:
        tl = self._make_timeline()
        filtered = tl.filter(confidence=ClaimClassification.OBSERVATION)
        assert len(filtered) >= 1

    def test_add_from_log_iso(self) -> None:
        log_text = textwrap.dedent("""\
            2025-06-15T10:00:00Z INFO Application started
            2025-06-15T10:05:00Z ERROR Connection failed
            2025-06-15T10:10:00Z WARNING Disk space low
        """)
        tl = Timeline()
        events = tl.add_from_log(log_text, source="app.log")
        assert len(events) == 3
        assert tl.count == 3
        # Check event types were detected
        types = [e.event_type for e in events]
        assert "info" in types
        assert "error" in types
        assert "warning" in types

    def test_add_from_log_syslog(self) -> None:
        log_text = "Mar 15 14:30:00 host sshd[1234]: ERROR Failed login\n"
        tl = Timeline()
        events = tl.add_from_log(log_text, source="syslog")
        assert len(events) == 1

    @patch("secrets_sdk.sirm.timeline.subprocess.run")
    def test_add_from_git(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "2025-06-15T10:00:00+00:00|abc123def456789|Douglas Brush|feat: add SIRM\n"
                "2025-06-14T09:00:00+00:00|def456abc789012|Douglas Brush|fix: resolve auth bug\n"
            ),
        )

        tl = Timeline()
        events = tl.add_from_git()
        assert len(events) == 2
        assert events[0].event_type == "commit"
        assert events[0].confidence == ClaimClassification.FACT

    def test_export_json(self) -> None:
        tl = self._make_timeline()
        json_str = tl.export_json()
        data = json.loads(json_str)
        assert isinstance(data, list)
        assert len(data) == 4

    def test_export_csv(self) -> None:
        tl = self._make_timeline()
        csv_str = tl.export_csv()
        lines = csv_str.strip().splitlines()
        assert len(lines) == 5  # header + 4 events

    def test_export_markdown(self) -> None:
        tl = self._make_timeline()
        md = tl.export_markdown()
        assert "| Timestamp |" in md
        assert "System startup" in md

    def test_export_generic(self) -> None:
        tl = self._make_timeline()
        assert tl.export("json") == tl.export_json()
        assert tl.export("csv") == tl.export_csv()
        assert tl.export("markdown") == tl.export_markdown()
        assert tl.export("md") == tl.export_markdown()

    def test_export_unknown_format(self) -> None:
        tl = Timeline()
        with pytest.raises(ValueError, match="Unknown export format"):
            tl.export("xml")

    def test_merge_with_dedup(self) -> None:
        tl1 = Timeline()
        tl2 = Timeline()
        now = datetime.now(timezone.utc)

        # Same event in both
        tl1.add_event(now, "test", "info", "Shared event")
        tl2.add_event(now, "test", "info", "Shared event")

        # Unique events
        tl1.add_event(now + timedelta(minutes=1), "test", "info", "Only in tl1")
        tl2.add_event(now + timedelta(minutes=2), "test", "info", "Only in tl2")

        added = tl1.merge(tl2)
        assert added == 1  # Only "Only in tl2" should be added
        assert tl1.count == 3


# ======================================================================
# Report generator tests
# ======================================================================


class TestSessionReport:
    """Test report generation in all formats."""

    def _make_session_with_data(self, tmp_path: Path) -> tuple[SIRMSession, Timeline, EvidenceChain]:
        session = SIRMSession.create(
            operator="analyst",
            classification="CONFIDENTIAL",
            session_dir=tmp_path,
        )
        session.activate()
        session.attach_context({
            "git_state": {"branch": "main", "commit_hash": "abc123"},
            "vault_health": {"reachable": True, "sealed": False},
        })

        # Timeline
        tl = Timeline()
        now = datetime.now(timezone.utc)
        tl.add_event(now, "analyst", "init", "Session started")
        tl.add_event(now + timedelta(minutes=5), "vault", "query", "Vault queried")

        # Evidence
        ev_file = tmp_path / "evidence.txt"
        ev_file.write_text("evidence data")
        chain = EvidenceChain(session_id=session.session_id)
        chain.register(source=ev_file, collected_by="analyst", description="Test evidence")

        return session, tl, chain

    def test_generate_report_data(self, tmp_path: Path) -> None:
        session, tl, chain = self._make_session_with_data(tmp_path)
        report = SessionReport(session=session, timeline=tl, evidence_chain=chain)

        report.add_finding(
            title="Unauthorized access detected",
            description="Evidence of unauthorized access to vault secrets.",
            confidence=ConfidenceLevel.STRONG,
            classification="F",
        )
        report.add_recommendation(
            title="Rotate all tokens",
            description="Immediately rotate all Vault tokens.",
            priority="critical",
        )

        data = report.generate()
        assert isinstance(data, ReportData)
        assert data.session_id == session.session_id
        assert len(data.timeline_events) == 2
        assert data.evidence_manifest is not None
        assert len(data.findings) == 1
        assert len(data.recommendations) == 1
        assert "analyst" in data.executive_summary

    def test_to_json(self, tmp_path: Path) -> None:
        session, tl, chain = self._make_session_with_data(tmp_path)
        report = SessionReport(session=session, timeline=tl, evidence_chain=chain)
        json_str = report.to_json()
        data = json.loads(json_str)
        assert "session_id" in data
        assert "executive_summary" in data

    def test_to_markdown(self, tmp_path: Path) -> None:
        session, tl, chain = self._make_session_with_data(tmp_path)
        report = SessionReport(session=session, timeline=tl, evidence_chain=chain)

        report.add_finding(
            title="Token leak",
            description="Vault token found in log files.",
            confidence=ConfidenceLevel.DOMINANT,
            classification="F",
        )
        report.add_recommendation(
            title="Enable token revocation",
            description="Enable automatic token revocation on leak detection.",
            priority="high",
        )

        md = report.to_markdown()
        assert "# SIRM Session Report" in md
        assert "## Executive Summary" in md
        assert "## Session Metadata" in md
        assert "## Timeline of Actions" in md
        assert "## Evidence Manifest" in md
        assert "## Findings" in md
        assert "## Recommendations" in md
        assert "Token leak" in md
        assert "DOMINANT" in md or "dominant" in md

    def test_to_dict(self, tmp_path: Path) -> None:
        session, _, _ = self._make_session_with_data(tmp_path)
        report = SessionReport(session=session)
        data = report.to_dict()
        assert isinstance(data, dict)
        assert "executive_summary" in data

    def test_report_without_optional_components(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        report = SessionReport(session=session)
        md = report.to_markdown()
        assert "# SIRM Session Report" in md
        # Should not have timeline or evidence sections
        assert "## Timeline of Actions" not in md
        assert "## Evidence Manifest" not in md

    def test_add_finding_classification(self, tmp_path: Path) -> None:
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        report = SessionReport(session=session)

        for code in ["F", "O", "I", "H"]:
            finding = report.add_finding(
                title=f"Finding {code}",
                description=f"Test finding with classification {code}",
                classification=code,
            )
            assert finding.classification.value == code


# ======================================================================
# Model tests
# ======================================================================


class TestModels:
    """Test Pydantic model validation and serialization."""

    def test_session_record_seal_hash(self) -> None:
        record = SessionRecord(operator="analyst")
        hash1 = record.compute_seal_hash()
        assert len(hash1) == 64

        # Same record should produce same hash
        hash2 = record.compute_seal_hash()
        assert hash1 == hash2

        # Modified record should produce different hash
        record.operator = "different_analyst"
        hash3 = record.compute_seal_hash()
        assert hash3 != hash1

    def test_session_log_entry_defaults(self) -> None:
        entry = SessionLogEntry(action="test")
        assert entry.timestamp.tzinfo is not None
        assert entry.operator == ""

    def test_evidence_manifest_hash(self) -> None:
        manifest = EvidenceManifest(session_id="test")
        h = manifest.compute_hash()
        assert len(h) == 64

    def test_tool_check_model(self) -> None:
        check = ToolCheck(tool="vault", found=True, version="1.15.0", path="/usr/bin/vault")
        assert check.tool == "vault"
        assert check.found

    def test_timeline_event_model(self) -> None:
        event = TimelineEvent(
            timestamp=datetime.now(timezone.utc),
            source="test",
            event_type="info",
            description="Test event",
            confidence=ClaimClassification.FACT,
        )
        assert event.confidence == ClaimClassification.FACT

    def test_finding_model(self) -> None:
        finding = Finding(
            title="Test",
            description="Test finding",
            confidence=ConfidenceLevel.STRONG,
            classification=ClaimClassification.OBSERVATION,
        )
        assert finding.confidence == ConfidenceLevel.STRONG

    def test_recommendation_model(self) -> None:
        rec = Recommendation(
            title="Test",
            description="Test recommendation",
            priority="critical",
        )
        assert rec.priority == "critical"

    def test_session_context_serialization(self) -> None:
        ctx = SessionContext(
            git_state=GitState(branch="main"),
            vault_health=VaultHealth(reachable=True),
        )
        data = ctx.model_dump(mode="json")
        assert data["git_state"]["branch"] == "main"

        # Round-trip
        ctx2 = SessionContext.model_validate(data)
        assert ctx2.git_state.branch == "main"

    def test_claim_classification_enum(self) -> None:
        assert ClaimClassification.FACT.value == "F"
        assert ClaimClassification.OBSERVATION.value == "O"
        assert ClaimClassification.INFERENCE.value == "I"
        assert ClaimClassification.HYPOTHESIS.value == "H"

    def test_confidence_level_enum(self) -> None:
        assert ConfidenceLevel.WEAK.value == "weak"
        assert ConfidenceLevel.MODERATE.value == "moderate"
        assert ConfidenceLevel.STRONG.value == "strong"
        assert ConfidenceLevel.DOMINANT.value == "dominant"

    def test_session_state_enum(self) -> None:
        assert SessionState.INITIALIZING.value == "INITIALIZING"
        assert SessionState.ACTIVE.value == "ACTIVE"
        assert SessionState.SUSPENDED.value == "SUSPENDED"
        assert SessionState.CLOSED.value == "CLOSED"
        assert SessionState.SEALED.value == "SEALED"

    def test_phase_result_enum(self) -> None:
        assert PhaseResult.PASS.value == "pass"
        assert PhaseResult.WARN.value == "warn"
        assert PhaseResult.FAIL.value == "fail"


# ======================================================================
# CLI integration tests (smoke tests)
# ======================================================================


class TestSIRMCLI:
    """Smoke tests for SIRM CLI commands."""

    def test_sirm_init_json(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from secrets_sdk.cli import cli

        runner = CliRunner()

        with patch("secrets_sdk.sirm.bootstrap.shutil.which", return_value="/usr/bin/tool"), \
             patch("secrets_sdk.sirm.context.subprocess.run", return_value=MagicMock(returncode=0, stdout="main", stderr="")), \
             patch("secrets_sdk.sirm.context.shutil.which", return_value="/usr/bin/vault"):

            result = runner.invoke(cli, [
                "sirm-init",
                "--operator", "test_analyst",
                "--session-dir", str(tmp_path / "sessions"),
                "--repo-root", str(tmp_path),
                "--json-output",
            ])

            assert result.exit_code == 0, result.output
            data = json.loads(result.output)
            assert data["operator"] == "test_analyst"
            assert data["state"] == "ACTIVE"

    def test_sirm_status(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from secrets_sdk.cli import cli

        # Create a session file first
        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        runner = CliRunner()
        result = runner.invoke(cli, ["sirm-status", str(saved), "--json-output"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["state"] == "ACTIVE"
        assert data["operator"] == "analyst"

    def test_sirm_seal(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from secrets_sdk.cli import cli

        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        runner = CliRunner()
        result = runner.invoke(cli, [
            "sirm-seal", str(saved), "--json-output", "--reason", "Test seal",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["state"] == "SEALED"
        assert len(data["seal_hash"]) == 64

    def test_sirm_report_markdown(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from secrets_sdk.cli import cli

        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        runner = CliRunner()
        result = runner.invoke(cli, ["sirm-report", str(saved)])
        assert result.exit_code == 0, result.output
        assert "# SIRM Session Report" in result.output

    def test_sirm_report_json(self, tmp_path: Path) -> None:
        from click.testing import CliRunner
        from secrets_sdk.cli import cli

        session = SIRMSession.create(operator="analyst", session_dir=tmp_path)
        session.activate()
        saved = session.save()

        runner = CliRunner()
        result = runner.invoke(cli, ["sirm-report", str(saved), "--format", "json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "executive_summary" in data
