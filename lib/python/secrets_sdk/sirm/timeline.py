"""SIRM timeline builder — ordered event tracking with multi-source ingestion.

Supports manual event addition, log parsing, git log import, filtering,
export (JSON, CSV, Markdown), and timeline merging with dedup.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from secrets_sdk.sirm.models import ClaimClassification, TimelineEvent

logger = logging.getLogger(__name__)

# Common syslog-style timestamp pattern: "Mar 15 14:30:00"
_SYSLOG_TS_RE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# ISO 8601 timestamp pattern
_ISO_TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# Common log levels
_LOG_LEVEL_RE = re.compile(
    r"\b(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG|NOTICE|ALERT|EMERG)\b", re.IGNORECASE
)


class Timeline:
    """Ordered collection of timeline events with filtering and export.

    Events are stored sorted by timestamp.  Duplicate detection is based
    on (timestamp, source, event_type, description) tuple.
    """

    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []

    @property
    def events(self) -> list[TimelineEvent]:
        """All events, sorted by timestamp."""
        return sorted(self._events, key=lambda e: e.timestamp)

    @property
    def count(self) -> int:
        return len(self._events)

    # ------------------------------------------------------------------
    # Event addition
    # ------------------------------------------------------------------

    def add_event(
        self,
        timestamp: datetime,
        source: str,
        event_type: str,
        description: str,
        evidence_refs: list[str] | None = None,
        confidence: ClaimClassification = ClaimClassification.OBSERVATION,
    ) -> TimelineEvent:
        """Add a single event to the timeline.

        Args:
            timestamp: When the event occurred (should be UTC).
            source: Source of the event (log file, tool, operator).
            event_type: Category of event.
            description: Human-readable description.
            evidence_refs: Optional list of evidence item IDs.
            confidence: Claim classification per Douglas Mode.

        Returns:
            The created TimelineEvent.
        """
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        event = TimelineEvent(
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            description=description,
            evidence_refs=evidence_refs or [],
            confidence=confidence,
        )
        self._events.append(event)
        return event

    def add_from_log(
        self,
        log_text: str,
        source: str = "log",
        default_event_type: str = "log_entry",
        confidence: ClaimClassification = ClaimClassification.OBSERVATION,
    ) -> list[TimelineEvent]:
        """Parse common log formats and add events.

        Supports ISO 8601 and syslog-style timestamps.  Falls back to
        current time if no timestamp can be parsed.

        Args:
            log_text: Raw log text (multi-line).
            source: Source label for all parsed events.
            default_event_type: Default event type if none detected.
            confidence: Claim classification for parsed events.

        Returns:
            List of created TimelineEvents.
        """
        created: list[TimelineEvent] = []

        for line in log_text.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            timestamp = self._parse_timestamp(line)
            event_type = self._detect_event_type(line, default_event_type)

            event = self.add_event(
                timestamp=timestamp,
                source=source,
                event_type=event_type,
                description=line,
                confidence=confidence,
            )
            created.append(event)

        return created

    def add_from_git(
        self,
        repo_path: str | Path | None = None,
        max_count: int = 50,
        confidence: ClaimClassification = ClaimClassification.FACT,
    ) -> list[TimelineEvent]:
        """Import git log entries as timeline events.

        Args:
            repo_path: Path to git repository (default: cwd).
            max_count: Maximum number of commits to import.
            confidence: Claim classification (git commits are Facts).

        Returns:
            List of created TimelineEvents.
        """
        cmd = ["git", "log", f"--max-count={max_count}", "--format=%aI|%H|%an|%s"]
        if repo_path:
            cmd = ["git", "-C", str(repo_path)] + cmd[1:]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning("git log failed: %s", result.stderr)
                return []
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("git log failed: %s", exc)
            return []

        created: list[TimelineEvent] = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue

            try:
                ts = datetime.fromisoformat(parts[0])
            except ValueError:
                continue

            commit_hash = parts[1][:12]
            author = parts[2]
            message = parts[3]

            event = self.add_event(
                timestamp=ts,
                source=f"git:{author}",
                event_type="commit",
                description=f"[{commit_hash}] {message}",
                confidence=confidence,
            )
            created.append(event)

        return created

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        source: str | None = None,
        event_type: str | None = None,
        confidence: ClaimClassification | None = None,
    ) -> list[TimelineEvent]:
        """Filter events by criteria.

        Args:
            start: Include events at or after this time.
            end: Include events at or before this time.
            source: Filter by source (substring match).
            event_type: Filter by event type (exact match).
            confidence: Filter by claim classification.

        Returns:
            Filtered list of TimelineEvents, sorted by timestamp.
        """
        result: list[TimelineEvent] = []

        for event in self.events:
            if start and event.timestamp < start:
                continue
            if end and event.timestamp > end:
                continue
            if source and source.lower() not in event.source.lower():
                continue
            if event_type and event.event_type != event_type:
                continue
            if confidence and event.confidence != confidence:
                continue
            result.append(event)

        return result

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self, indent: int = 2) -> str:
        """Export timeline as JSON."""
        data = [e.model_dump(mode="json") for e in self.events]
        return json.dumps(data, indent=indent, default=str)

    def export_csv(self) -> str:
        """Export timeline as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "source", "event_type", "description", "confidence", "evidence_refs"])

        for event in self.events:
            writer.writerow([
                event.timestamp.isoformat(),
                event.source,
                event.event_type,
                event.description,
                event.confidence.value,
                ";".join(event.evidence_refs),
            ])

        return output.getvalue()

    def export_markdown(self) -> str:
        """Export timeline as a structured Markdown table."""
        lines: list[str] = [
            "| Timestamp | Source | Type | Description | Confidence |",
            "|-----------|--------|------|-------------|------------|",
        ]

        for event in self.events:
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            desc = event.description.replace("|", "\\|")
            if len(desc) > 80:
                desc = desc[:77] + "..."
            lines.append(
                f"| {ts} | {event.source} | {event.event_type} | {desc} | {event.confidence.value} |"
            )

        return "\n".join(lines)

    def export(self, fmt: str = "json") -> str:
        """Export timeline in the specified format.

        Args:
            fmt: One of "json", "csv", "markdown".

        Returns:
            Formatted timeline string.

        Raises:
            ValueError: If format is not recognized.
        """
        exporters: dict[str, Callable[[], str]] = {
            "json": self.export_json,
            "csv": self.export_csv,
            "markdown": self.export_markdown,
            "md": self.export_markdown,
        }
        exporter = exporters.get(fmt.lower())
        if exporter is None:
            raise ValueError(f"Unknown export format: {fmt}. Use: {', '.join(exporters)}")
        return exporter()

    # ------------------------------------------------------------------
    # Merge
    # ------------------------------------------------------------------

    def merge(self, other: "Timeline") -> int:
        """Merge another timeline into this one, deduplicating events.

        Dedup key: (timestamp, source, event_type, description).

        Args:
            other: Timeline to merge from.

        Returns:
            Number of new events added.
        """
        existing = {self._dedup_key(e) for e in self._events}
        added = 0

        for event in other._events:
            key = self._dedup_key(event)
            if key not in existing:
                self._events.append(event)
                existing.add(key)
                added += 1

        return added

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(line: str) -> datetime:
        """Extract timestamp from a log line."""
        # Try ISO 8601 first
        iso_match = _ISO_TS_RE.search(line)
        if iso_match:
            ts_str = iso_match.group(1)
            try:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                pass

        # Try syslog format
        syslog_match = _SYSLOG_TS_RE.match(line)
        if syslog_match:
            ts_str = syslog_match.group(1)
            try:
                # Assume current year
                year = datetime.now(timezone.utc).year
                dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # Fallback to now
        return datetime.now(timezone.utc)

    @staticmethod
    def _detect_event_type(line: str, default: str) -> str:
        """Detect event type from log level keywords."""
        match = _LOG_LEVEL_RE.search(line)
        if match:
            level = match.group(1).upper()
            return {
                "CRITICAL": "critical",
                "ERROR": "error",
                "WARNING": "warning",
                "WARN": "warning",
                "INFO": "info",
                "DEBUG": "debug",
                "NOTICE": "notice",
                "ALERT": "alert",
                "EMERG": "emergency",
            }.get(level, default)
        return default

    @staticmethod
    def _dedup_key(event: TimelineEvent) -> tuple[str, str, str, str]:
        """Generate a dedup key for an event."""
        return (
            event.timestamp.isoformat(),
            event.source,
            event.event_type,
            event.description,
        )
