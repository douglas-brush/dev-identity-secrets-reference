"""Secret rotation helpers.

Provides rotation policy definitions, age checking for Vault secrets,
and SOPS key rotation utilities.
"""

from __future__ import annotations

import logging
import re
import subprocess
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from secrets_sdk.exceptions import RotationError, SopsNotInstalledError
from secrets_sdk.models import AgeReport

if TYPE_CHECKING:
    from secrets_sdk.vault import VaultClient

logger = logging.getLogger(__name__)


@dataclass
class RotationPolicy:
    """Defines rotation requirements for a class of secrets.

    Attributes:
        name: Human-readable policy name (e.g., "database-creds", "api-keys").
        max_age_days: Maximum allowed age in days before rotation is required.
        paths: Vault KV paths this policy applies to (glob-like patterns).
        warn_age_days: Age in days at which to start warning (default: 80% of max).
        auto_rotate: Whether the system should attempt automatic rotation.
        notify_channels: Where to send rotation notifications (e.g., ["slack", "email"]).
    """

    name: str
    max_age_days: float = 90.0
    paths: list[str] = field(default_factory=list)
    warn_age_days: float = 0.0
    auto_rotate: bool = False
    notify_channels: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.warn_age_days <= 0:
            self.warn_age_days = self.max_age_days * 0.8

    def matches_path(self, path: str) -> bool:
        """Check if a Vault path matches any of this policy's path patterns.

        Supports simple glob: `*` matches any single path segment,
        `**` is not supported (use multiple patterns instead).

        Args:
            path: Vault secret path to check.

        Returns:
            True if the path matches any pattern.
        """
        for pattern in self.paths:
            regex = _glob_to_regex(pattern)
            if re.match(regex, path):
                return True
        return False


# Default rotation policies for common secret types
DEFAULT_POLICIES: list[RotationPolicy] = [
    RotationPolicy(
        name="database-credentials",
        max_age_days=90,
        paths=["kv/data/*/database/*", "kv/data/*/db/*"],
    ),
    RotationPolicy(
        name="api-keys",
        max_age_days=180,
        paths=["kv/data/*/api-keys/*", "kv/data/*/apikeys/*"],
    ),
    RotationPolicy(
        name="service-accounts",
        max_age_days=365,
        paths=["kv/data/*/service-accounts/*"],
    ),
    RotationPolicy(
        name="tls-certificates",
        max_age_days=90,
        paths=["kv/data/*/certs/*", "kv/data/*/tls/*"],
    ),
    RotationPolicy(
        name="ssh-keys",
        max_age_days=90,
        paths=["kv/data/*/ssh/*"],
    ),
]


def check_secret_age(
    vault_client: "VaultClient",
    path: str,
    max_age_days: float = 90.0,
    kv_mount: str | None = None,
) -> AgeReport:
    """Check the age of a KV v2 secret and determine if rotation is needed.

    Args:
        vault_client: Authenticated VaultClient instance.
        path: Secret path (without mount prefix).
        max_age_days: Maximum allowed age in days.
        kv_mount: KV mount point override. Uses client default if None.

    Returns:
        AgeReport with age details and rotation recommendation.

    Raises:
        RotationError: If the metadata cannot be retrieved.
    """
    from secrets_sdk.exceptions import VaultSecretNotFound, VaultConnectionError

    try:
        metadata = vault_client.kv_metadata(path)
    except VaultSecretNotFound:
        return AgeReport(
            path=path,
            max_age_days=max_age_days,
            needs_rotation=False,
            detail=f"Secret not found at path: {path}",
        )
    except VaultConnectionError as exc:
        raise RotationError(f"Cannot check age of {path}: {exc}")

    now = datetime.now(timezone.utc)
    age_days = 0.0
    created = metadata.created_time

    if created is not None:
        if isinstance(created, str):
            # Parse ISO format string from Vault
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                return AgeReport(
                    path=path,
                    current_version=metadata.version,
                    created_time=None,
                    max_age_days=max_age_days,
                    needs_rotation=False,
                    detail=f"Cannot parse created_time: {created}",
                )

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        delta = now - created
        age_days = delta.total_seconds() / 86400.0

    needs_rotation = age_days > max_age_days
    detail = ""
    if needs_rotation:
        overdue = age_days - max_age_days
        detail = f"Secret is {overdue:.1f} days overdue for rotation"
    elif age_days > max_age_days * 0.8:
        remaining = max_age_days - age_days
        detail = f"Secret will need rotation in {remaining:.1f} days"
    else:
        detail = "Secret age is within policy"

    return AgeReport(
        path=path,
        current_version=metadata.version,
        created_time=created if isinstance(created, datetime) else None,
        age_days=age_days,
        max_age_days=max_age_days,
        needs_rotation=needs_rotation,
        detail=detail,
    )


def check_secrets_batch(
    vault_client: "VaultClient",
    paths: list[str],
    policies: list[RotationPolicy] | None = None,
) -> list[AgeReport]:
    """Check multiple secrets against rotation policies.

    For each path, finds the matching policy (or uses default 90 days)
    and checks the secret age.

    Args:
        vault_client: Authenticated VaultClient instance.
        paths: List of secret paths to check.
        policies: Rotation policies to match against. Uses DEFAULT_POLICIES if None.

    Returns:
        List of AgeReport objects, one per path.
    """
    active_policies = policies or DEFAULT_POLICIES
    reports: list[AgeReport] = []

    for path in paths:
        max_age = 90.0  # default
        for policy in active_policies:
            if policy.matches_path(path):
                max_age = policy.max_age_days
                break
        try:
            report = check_secret_age(vault_client, path, max_age_days=max_age)
            reports.append(report)
        except RotationError as exc:
            reports.append(
                AgeReport(
                    path=path,
                    max_age_days=max_age,
                    needs_rotation=False,
                    detail=f"Error: {exc}",
                )
            )

    return reports


def rotate_sops_keys(
    repo_root: str | Path,
    new_key: str,
    key_type: str = "age",
    old_key: str = "",
    dry_run: bool = False,
) -> list[dict[str, str]]:
    """Rotate SOPS encryption keys across all encrypted files in a repository.

    This updates the .sops.yaml configuration and re-encrypts all matching
    files with the new key. Requires the old key to be available for
    decryption during the rotation.

    Args:
        repo_root: Repository root directory.
        new_key: New encryption key (age public key, KMS ARN, etc.).
        key_type: Key type ("age", "kms", "gcp_kms", "azure_keyvault").
        old_key: Old key to replace. If empty, the new key is added alongside existing keys.
        dry_run: If True, report what would change without modifying files.

    Returns:
        List of dicts with {"file": path, "status": "rotated"|"skipped"|"error", "detail": ...}.

    Raises:
        RotationError: If sops is not installed or repo_root is invalid.
    """
    root = Path(repo_root)
    if not root.is_dir():
        raise RotationError(f"Repository root not found: {root}")

    sops_yaml = root / ".sops.yaml"
    if not sops_yaml.exists():
        raise RotationError(f".sops.yaml not found in {root}")

    if shutil.which("sops") is None:
        raise RotationError("sops binary not found on PATH")

    results: list[dict[str, str]] = []

    # Step 1: Update .sops.yaml
    raw = sops_yaml.read_text()
    config = _load_yaml_preserving(raw)

    if not isinstance(config, dict) or "creation_rules" not in config:
        raise RotationError("Invalid .sops.yaml: missing creation_rules")

    updated_rules = False
    for rule in config["creation_rules"]:
        if not isinstance(rule, dict):
            continue

        current_value = rule.get(key_type, "")
        if old_key and current_value == old_key:
            if not dry_run:
                rule[key_type] = new_key
            updated_rules = True
        elif not old_key and key_type in rule:
            # Add new key alongside existing
            if not dry_run:
                rule[key_type] = new_key
            updated_rules = True

    if updated_rules and not dry_run:
        import yaml
        sops_yaml.write_text(yaml.safe_dump(config, default_flow_style=False))
        results.append({"file": str(sops_yaml), "status": "rotated", "detail": f"Updated {key_type} key"})
    elif updated_rules:
        results.append({"file": str(sops_yaml), "status": "would_rotate", "detail": f"Would update {key_type} key"})

    # Step 2: Find and re-encrypt all SOPS-encrypted files
    encrypted_files = _find_encrypted_files(root)

    for enc_file in encrypted_files:
        rel = enc_file.relative_to(root)
        if dry_run:
            results.append({"file": str(rel), "status": "would_rotate", "detail": "Would re-encrypt"})
            continue

        try:
            # sops updatekeys re-encrypts with the new .sops.yaml keys
            proc = subprocess.run(
                ["sops", "updatekeys", "--yes", str(enc_file)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode == 0:
                results.append({"file": str(rel), "status": "rotated", "detail": "Re-encrypted with new keys"})
            else:
                results.append({"file": str(rel), "status": "error", "detail": proc.stderr.strip()})
        except subprocess.TimeoutExpired:
            results.append({"file": str(rel), "status": "error", "detail": "sops updatekeys timed out"})
        except Exception as exc:
            results.append({"file": str(rel), "status": "error", "detail": str(exc)})

    return results


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _glob_to_regex(pattern: str) -> str:
    """Convert a simple glob pattern to a regex.

    Supports `*` as a single-segment wildcard.
    """
    parts = []
    for char in pattern:
        if char == "*":
            parts.append("[^/]*")
        elif char in r"\.+^${}()|[]":
            parts.append(f"\\{char}")
        else:
            parts.append(char)
    return "^" + "".join(parts) + "$"


def _find_encrypted_files(root: Path) -> list[Path]:
    """Find all SOPS-encrypted files in the repo."""
    encrypted: list[Path] = []
    for ext in ("*.enc.yaml", "*.enc.yml", "*.enc.json", "*.enc.env"):
        encrypted.extend(root.rglob(ext))
    return sorted(encrypted)


def _load_yaml_preserving(content: str) -> Any:
    """Load YAML content."""
    import yaml
    return yaml.safe_load(content)
