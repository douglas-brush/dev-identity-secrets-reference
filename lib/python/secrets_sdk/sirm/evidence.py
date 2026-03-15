"""SIRM evidence chain tracking — hash-and-record integrity management.

Provides registration, verification, custody transfer, and manifest export
for evidence items.  NEVER modifies evidence files — read-only access,
hash-and-record only.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secrets_sdk.sirm.models import (
    CustodyEntry,
    EvidenceItem,
    EvidenceManifest,
)

logger = logging.getLogger(__name__)

# Buffer size for file hashing (64KB)
_HASH_BUFFER_SIZE = 65536


def compute_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        path: Path to the file to hash.

    Returns:
        Hex-encoded SHA-256 hash string.

    Raises:
        FileNotFoundError: If the file does not exist.
        OSError: If the file cannot be read.
    """
    path = Path(path)
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(_HASH_BUFFER_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes.

    Args:
        data: Bytes to hash.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    return hashlib.sha256(data).hexdigest()


class EvidenceChain:
    """Manages a collection of evidence items with chain-of-custody tracking.

    This class never writes to or modifies evidence files.  It only reads
    files to compute hashes and maintains its own registry of items and
    custody records.
    """

    def __init__(self, session_id: str = "") -> None:
        self.session_id = session_id
        self._items: dict[str, EvidenceItem] = {}

    @property
    def items(self) -> list[EvidenceItem]:
        """All registered evidence items, ordered by collection time."""
        return sorted(self._items.values(), key=lambda i: i.collected_at)

    @property
    def count(self) -> int:
        return len(self._items)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        source: str | Path,
        collected_by: str,
        description: str = "",
        classification: str = "UNCLASSIFIED",
        evidence_id: str | None = None,
    ) -> EvidenceItem:
        """Register a new evidence item with automatic hash computation.

        Args:
            source: Path to the evidence file.
            collected_by: Identity of the collector.
            description: Human-readable description of the evidence.
            classification: Classification level.
            evidence_id: Optional explicit ID (auto-generated if not provided).

        Returns:
            The registered EvidenceItem.

        Raises:
            FileNotFoundError: If the source file does not exist.
        """
        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"Evidence source not found: {source}")

        sha256 = compute_sha256(source)

        item = EvidenceItem(
            source=str(source.resolve()),
            sha256=sha256,
            collected_by=collected_by,
            description=description,
            classification=classification,
        )
        if evidence_id:
            item.id = evidence_id

        # Initial custody entry
        item.chain_of_custody.append(
            CustodyEntry(
                from_party="source",
                to_party=collected_by,
                reason="Initial collection",
            )
        )

        self._items[item.id] = item
        logger.info(
            "Evidence registered: id=%s source=%s sha256=%s",
            item.id,
            source,
            sha256[:16] + "...",
        )
        return item

    def register_bytes(
        self,
        data: bytes,
        source_label: str,
        collected_by: str,
        description: str = "",
        classification: str = "UNCLASSIFIED",
        evidence_id: str | None = None,
    ) -> EvidenceItem:
        """Register evidence from raw bytes (e.g., API response, memory dump).

        Args:
            data: Raw bytes to register.
            source_label: Label describing the source (not a file path).
            collected_by: Identity of the collector.
            description: Human-readable description.
            classification: Classification level.
            evidence_id: Optional explicit ID.

        Returns:
            The registered EvidenceItem.
        """
        sha256 = compute_sha256_bytes(data)

        item = EvidenceItem(
            source=source_label,
            sha256=sha256,
            collected_by=collected_by,
            description=description,
            classification=classification,
        )
        if evidence_id:
            item.id = evidence_id

        item.chain_of_custody.append(
            CustodyEntry(
                from_party="source",
                to_party=collected_by,
                reason="Initial collection (in-memory)",
            )
        )

        self._items[item.id] = item
        logger.info(
            "Evidence registered (bytes): id=%s source=%s sha256=%s",
            item.id,
            source_label,
            sha256[:16] + "...",
        )
        return item

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, evidence_id: str) -> bool:
        """Verify hash integrity of a registered evidence item.

        Re-computes the SHA-256 hash of the source file and compares
        it to the registered hash.

        Args:
            evidence_id: ID of the evidence item to verify.

        Returns:
            True if hash matches, False if tampered or file missing.

        Raises:
            KeyError: If evidence_id is not registered.
        """
        item = self._get_item(evidence_id)
        source = Path(item.source)

        if not source.exists():
            logger.warning("Evidence file missing: %s (id=%s)", source, evidence_id)
            return False

        current_hash = compute_sha256(source)
        matches = current_hash == item.sha256

        if not matches:
            logger.warning(
                "Evidence integrity FAILED: id=%s expected=%s got=%s",
                evidence_id,
                item.sha256[:16] + "...",
                current_hash[:16] + "...",
            )
        else:
            logger.debug("Evidence integrity verified: id=%s", evidence_id)

        return matches

    def verify_all(self) -> dict[str, bool]:
        """Verify all registered evidence items.

        Returns:
            Dict mapping evidence_id -> verification result.
        """
        return {eid: self.verify(eid) for eid in self._items}

    # ------------------------------------------------------------------
    # Custody transfer
    # ------------------------------------------------------------------

    def transfer(
        self,
        evidence_id: str,
        from_party: str,
        to_party: str,
        reason: str = "",
    ) -> CustodyEntry:
        """Log a custody transfer for an evidence item.

        Args:
            evidence_id: ID of the evidence item.
            from_party: Party transferring custody.
            to_party: Party receiving custody.
            reason: Reason for transfer.

        Returns:
            The created CustodyEntry.

        Raises:
            KeyError: If evidence_id is not registered.
        """
        item = self._get_item(evidence_id)
        entry = CustodyEntry(
            from_party=from_party,
            to_party=to_party,
            reason=reason,
        )
        item.chain_of_custody.append(entry)
        logger.info(
            "Custody transfer: id=%s from=%s to=%s reason=%s",
            evidence_id,
            from_party,
            to_party,
            reason,
        )
        return entry

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_manifest(self) -> EvidenceManifest:
        """Generate an evidence manifest.

        Returns:
            EvidenceManifest with all items and integrity hash.
        """
        manifest = EvidenceManifest(
            session_id=self.session_id,
            items=self.items,
        )
        manifest.manifest_hash = manifest.compute_hash()
        return manifest

    def export_manifest_json(self, indent: int = 2) -> str:
        """Export manifest as formatted JSON string."""
        manifest = self.export_manifest()
        return json.dumps(manifest.model_dump(mode="json"), indent=indent, default=str)

    def export_manifest_readable(self) -> str:
        """Export manifest as a human-readable text report."""
        manifest = self.export_manifest()
        lines: list[str] = [
            "=" * 72,
            "EVIDENCE MANIFEST",
            "=" * 72,
            f"Session: {manifest.session_id or 'N/A'}",
            f"Generated: {manifest.generated_at.isoformat()}",
            f"Total Items: {len(manifest.items)}",
            f"Manifest Hash: {manifest.manifest_hash}",
            "-" * 72,
        ]

        for item in manifest.items:
            lines.extend([
                f"\nEvidence ID: {item.id}",
                f"  Source: {item.source}",
                f"  SHA-256: {item.sha256}",
                f"  Collected: {item.collected_at.isoformat()}",
                f"  Collected By: {item.collected_by}",
                f"  Description: {item.description}",
                f"  Classification: {item.classification}",
                f"  Custody Chain ({len(item.chain_of_custody)} entries):",
            ])
            for entry in item.chain_of_custody:
                lines.append(
                    f"    [{entry.timestamp.isoformat()}] "
                    f"{entry.from_party} -> {entry.to_party}: {entry.reason}"
                )

        lines.append("=" * 72)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, evidence_id: str) -> EvidenceItem:
        """Get an evidence item by ID.

        Raises:
            KeyError: If not found.
        """
        return self._get_item(evidence_id)

    def _get_item(self, evidence_id: str) -> EvidenceItem:
        """Internal item lookup with KeyError on miss."""
        if evidence_id not in self._items:
            raise KeyError(f"Evidence item not found: {evidence_id}")
        return self._items[evidence_id]
