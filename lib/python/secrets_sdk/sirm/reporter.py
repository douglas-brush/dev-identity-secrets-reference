"""SIRM session report generator.

Produces structured reports following Douglas Mode output standards:
executive summary first, findings second, recommendations third.
Confidence ratings on all findings using correlation scale.
Tables over bullets for structured data.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from secrets_sdk.sirm.evidence import EvidenceChain
from secrets_sdk.sirm.models import (
    ConfidenceLevel,
    Finding,
    Recommendation,
    ReportData,
    TimelineEvent,
)
from secrets_sdk.sirm.session import SIRMSession
from secrets_sdk.sirm.timeline import Timeline

logger = logging.getLogger(__name__)


class SessionReport:
    """Generates structured SIRM session reports.

    Args:
        session: The SIRM session to report on.
        timeline: Optional timeline of events.
        evidence_chain: Optional evidence chain.
    """

    def __init__(
        self,
        session: SIRMSession,
        timeline: Timeline | None = None,
        evidence_chain: EvidenceChain | None = None,
    ) -> None:
        self._session = session
        self._timeline = timeline
        self._evidence = evidence_chain
        self._findings: list[Finding] = []
        self._recommendations: list[Recommendation] = []

    # ------------------------------------------------------------------
    # Findings and recommendations
    # ------------------------------------------------------------------

    def add_finding(
        self,
        title: str,
        description: str,
        confidence: ConfidenceLevel = ConfidenceLevel.MODERATE,
        evidence_refs: list[str] | None = None,
        classification: str = "O",
    ) -> Finding:
        """Add a finding to the report.

        Args:
            title: Short finding title.
            description: Detailed description.
            confidence: Confidence level (weak/moderate/strong/dominant).
            evidence_refs: List of evidence item IDs supporting this finding.
            classification: Claim classification code (F/O/I/H).

        Returns:
            The created Finding.
        """
        from secrets_sdk.sirm.models import ClaimClassification

        claim = ClaimClassification(classification)
        finding = Finding(
            title=title,
            description=description,
            confidence=confidence,
            evidence_refs=evidence_refs or [],
            classification=claim,
        )
        self._findings.append(finding)
        return finding

    def add_recommendation(
        self,
        title: str,
        description: str,
        priority: str = "medium",
        finding_refs: list[str] | None = None,
    ) -> Recommendation:
        """Add a recommendation to the report.

        Args:
            title: Short recommendation title.
            description: Detailed description.
            priority: Priority level (critical/high/medium/low).
            finding_refs: List of finding IDs this recommendation addresses.

        Returns:
            The created Recommendation.
        """
        rec = Recommendation(
            title=title,
            description=description,
            priority=priority,
            finding_refs=finding_refs or [],
        )
        self._recommendations.append(rec)
        return rec

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate(self) -> ReportData:
        """Generate the complete report data structure.

        Returns:
            ReportData with all sections populated.
        """
        record = self._session.record
        context = record.context_snapshot

        # Timeline events
        timeline_events: list[TimelineEvent] = []
        if self._timeline:
            timeline_events = self._timeline.events

        # Evidence manifest
        manifest = None
        if self._evidence:
            manifest = self._evidence.export_manifest()

        # Executive summary
        summary = self._build_executive_summary()

        # Session metadata
        session_metadata = {
            "session_id": record.session_id,
            "operator": record.operator,
            "classification": record.classification,
            "state": record.state.value,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "seal_hash": record.seal_hash or "N/A",
            "log_entries": len(record.log),
        }

        return ReportData(
            session_id=record.session_id,
            operator=record.operator,
            classification=record.classification,
            executive_summary=summary,
            session_metadata=session_metadata,
            environment_context=context,
            timeline_events=timeline_events,
            evidence_manifest=manifest,
            findings=self._findings,
            recommendations=self._recommendations,
        )

    def to_dict(self) -> dict[str, Any]:
        """Generate report as a dictionary."""
        return self.generate().model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        """Generate report as formatted JSON."""
        data = self.to_dict()
        return json.dumps(data, indent=indent, default=str)

    def to_markdown(self) -> str:
        """Generate report as structured Markdown.

        Follows Douglas Mode output standards:
        - Executive summary first
        - Findings second
        - Recommendations third
        - Tables over bullets for structured data
        """
        report = self.generate()
        sections: list[str] = []

        # Header
        sections.append(f"# SIRM Session Report")
        sections.append(f"\n**Report ID:** {report.report_id}")
        sections.append(f"**Generated:** {report.generated_at.isoformat()}")
        sections.append(f"**Classification:** {report.classification}")
        sections.append("")

        # Executive Summary
        sections.append("## Executive Summary")
        sections.append("")
        sections.append(report.executive_summary)
        sections.append("")

        # Session Metadata
        sections.append("## Session Metadata")
        sections.append("")
        sections.append("| Field | Value |")
        sections.append("|-------|-------|")
        for key, value in report.session_metadata.items():
            sections.append(f"| {key} | {value} |")
        sections.append("")

        # Environment Context
        if report.environment_context:
            sections.append("## Environment Context")
            sections.append("")
            self._render_context_section(sections, report.environment_context)
            sections.append("")

        # Timeline
        if report.timeline_events:
            sections.append("## Timeline of Actions")
            sections.append("")
            sections.append("| Timestamp | Source | Type | Description | Confidence |")
            sections.append("|-----------|--------|------|-------------|------------|")
            for event in report.timeline_events:
                ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                desc = event.description.replace("|", "\\|")
                if len(desc) > 60:
                    desc = desc[:57] + "..."
                sections.append(
                    f"| {ts} | {event.source} | {event.event_type} | {desc} | {event.confidence.value} |"
                )
            sections.append("")

        # Evidence Manifest
        if report.evidence_manifest and report.evidence_manifest.items:
            sections.append("## Evidence Manifest")
            sections.append("")
            sections.append(f"**Manifest Hash:** {report.evidence_manifest.manifest_hash}")
            sections.append("")
            sections.append("| ID | Source | SHA-256 | Collected By | Classification |")
            sections.append("|----|--------|---------|--------------|----------------|")
            for item in report.evidence_manifest.items:
                sha_short = item.sha256[:16] + "..."
                src = item.source.replace("|", "\\|")
                if len(src) > 40:
                    src = "..." + src[-37:]
                sections.append(
                    f"| {item.id[:8]}... | {src} | {sha_short} | {item.collected_by} | {item.classification} |"
                )
            sections.append("")

        # Findings
        if report.findings:
            sections.append("## Findings")
            sections.append("")
            sections.append("| # | Title | Confidence | Classification | Evidence |")
            sections.append("|---|-------|------------|----------------|----------|")
            for i, finding in enumerate(report.findings, 1):
                ev_count = len(finding.evidence_refs)
                sections.append(
                    f"| {i} | {finding.title} | {finding.confidence.value} | "
                    f"{finding.classification.value} | {ev_count} item(s) |"
                )
            sections.append("")

            # Finding details
            for i, finding in enumerate(report.findings, 1):
                sections.append(f"### Finding {i}: {finding.title}")
                sections.append("")
                sections.append(f"**Confidence:** {finding.confidence.value}")
                sections.append(f"**Classification:** {finding.classification.value}")
                sections.append("")
                sections.append(finding.description)
                sections.append("")

        # Recommendations
        if report.recommendations:
            sections.append("## Recommendations")
            sections.append("")
            sections.append("| # | Priority | Title | Addresses |")
            sections.append("|---|----------|-------|-----------|")
            for i, rec in enumerate(report.recommendations, 1):
                finding_count = len(rec.finding_refs)
                sections.append(
                    f"| {i} | {rec.priority.upper()} | {rec.title} | {finding_count} finding(s) |"
                )
            sections.append("")

            for i, rec in enumerate(report.recommendations, 1):
                sections.append(f"### Recommendation {i}: {rec.title}")
                sections.append("")
                sections.append(f"**Priority:** {rec.priority.upper()}")
                sections.append("")
                sections.append(rec.description)
                sections.append("")

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_executive_summary(self) -> str:
        """Build the executive summary paragraph."""
        record = self._session.record
        parts: list[str] = []

        parts.append(
            f"SIRM session {record.session_id[:8]} was initiated by {record.operator} "
            f"on {record.created_at.strftime('%Y-%m-%d at %H:%M UTC')} "
            f"with classification level {record.classification}."
        )

        if self._timeline:
            parts.append(f"The session timeline contains {self._timeline.count} events.")

        if self._evidence:
            parts.append(
                f"{self._evidence.count} evidence items were registered and tracked."
            )

        if self._findings:
            by_confidence: dict[str, int] = {}
            for f in self._findings:
                level = f.confidence.value
                by_confidence[level] = by_confidence.get(level, 0) + 1
            conf_parts = [f"{count} {level}" for level, count in by_confidence.items()]
            parts.append(
                f"{len(self._findings)} findings were documented ({', '.join(conf_parts)})."
            )

        if self._recommendations:
            parts.append(f"{len(self._recommendations)} recommendations were issued.")

        parts.append(f"Session state at report time: {record.state.value}.")

        return " ".join(parts)

    def _render_context_section(
        self, sections: list[str], context: dict[str, Any]
    ) -> None:
        """Render environment context as nested tables."""
        for section_name, section_data in context.items():
            if not section_data:
                continue
            if isinstance(section_data, dict):
                sections.append(f"### {section_name.replace('_', ' ').title()}")
                sections.append("")
                sections.append("| Key | Value |")
                sections.append("|-----|-------|")
                for k, v in section_data.items():
                    val_str = str(v).replace("|", "\\|")
                    if len(val_str) > 60:
                        val_str = val_str[:57] + "..."
                    sections.append(f"| {k} | {val_str} |")
                sections.append("")
