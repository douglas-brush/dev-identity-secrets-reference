"""SOPS helpers for encrypting and decrypting secrets files.

Wraps the `sops` CLI binary. Requires sops to be installed and on PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from secrets_sdk.exceptions import (
    SopsDecryptError,
    SopsEncryptError,
    SopsNotInstalledError,
)
from secrets_sdk.models import AuditEvent, AuditEventType


def _find_sops() -> str:
    """Locate the sops binary on PATH.

    Returns:
        Absolute path to sops binary.

    Raises:
        SopsNotInstalledError: If sops is not found.
    """
    path = shutil.which("sops")
    if path is None:
        raise SopsNotInstalledError()
    return path


def _run_sops(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run sops with the given arguments.

    Args:
        args: Arguments to pass to sops (after the binary name).
        env: Optional environment variables to merge with os.environ.

    Returns:
        CompletedProcess with stdout/stderr.
    """
    sops = _find_sops()
    run_env = dict(os.environ)
    if env:
        run_env.update(env)
    return subprocess.run(
        [sops, *args],
        capture_output=True,
        text=True,
        env=run_env,
        timeout=120,
    )


def decrypt_file(path: str | Path, output_format: str = "") -> dict[str, Any]:
    """Decrypt a SOPS-encrypted file and return its contents as a dict.

    Args:
        path: Path to the encrypted file.
        output_format: Force output format ("json", "yaml", "dotenv").
            If empty, sops auto-detects from file extension.

    Returns:
        Decrypted data as a dictionary.

    Raises:
        SopsDecryptError: If decryption fails.
        SopsNotInstalledError: If sops binary is not found.
        FileNotFoundError: If the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    args = ["--decrypt"]
    if output_format:
        args.extend(["--output-type", output_format])
    args.append(str(p))

    result = _run_sops(args)
    if result.returncode != 0:
        raise SopsDecryptError(str(p), result.stderr.strip())

    stdout = result.stdout
    # Parse based on detected or specified format
    fmt = output_format or _detect_format(p)
    try:
        if fmt == "json":
            return dict(json.loads(stdout))
        elif fmt in ("yaml", "yml"):
            loaded = yaml.safe_load(stdout)
            return dict(loaded) if isinstance(loaded, dict) else {"data": loaded}
        elif fmt == "dotenv":
            return _parse_dotenv(stdout)
        else:
            # Try JSON first, fall back to YAML
            try:
                return dict(json.loads(stdout))
            except (json.JSONDecodeError, ValueError):
                loaded = yaml.safe_load(stdout)
                return dict(loaded) if isinstance(loaded, dict) else {"data": loaded}
    except Exception as exc:
        raise SopsDecryptError(str(p), f"Failed to parse decrypted output: {exc}")


def encrypt_file(
    path: str | Path,
    data: dict[str, Any],
    output_path: str | Path | None = None,
    config_path: str | Path | None = None,
) -> Path:
    """Encrypt data and write to a SOPS-encrypted file.

    Args:
        path: Template path that determines the encryption rules
            (matching .sops.yaml path_regex). Used for format detection.
        data: Data to encrypt.
        output_path: Where to write the encrypted file. Defaults to `path`.
        config_path: Explicit .sops.yaml config path. If None, sops searches
            parent directories.

    Returns:
        Path to the written encrypted file.

    Raises:
        SopsEncryptError: If encryption fails.
        SopsNotInstalledError: If sops binary is not found.
    """
    p = Path(path)
    out = Path(output_path) if output_path else p
    fmt = _detect_format(p)

    # Write plaintext to a temp file, then encrypt in place
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=f".{fmt}",
        delete=False,
    ) as tmp:
        tmp_path = Path(tmp.name)
        if fmt == "json":
            json.dump(data, tmp, indent=2)
        elif fmt in ("yaml", "yml"):
            yaml.safe_dump(data, tmp, default_flow_style=False)
        elif fmt == "dotenv":
            for k, v in data.items():
                tmp.write(f"{k}={v}\n")
        else:
            json.dump(data, tmp, indent=2)

    try:
        args = ["--encrypt"]
        if config_path:
            args.extend(["--config", str(config_path)])
        # Use --input-type and --output-type to match the desired format
        if fmt in ("yaml", "yml"):
            args.extend(["--input-type", "yaml", "--output-type", "yaml"])
        elif fmt == "json":
            args.extend(["--input-type", "json", "--output-type", "json"])
        args.append(str(tmp_path))

        result = _run_sops(args)
        if result.returncode != 0:
            raise SopsEncryptError(str(p), result.stderr.strip())

        # Write encrypted output to destination
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.stdout)
        return out
    finally:
        tmp_path.unlink(missing_ok=True)


def decrypt_value(encrypted_string: str, key: str = "value") -> str:
    """Decrypt a single SOPS-encrypted value.

    Wraps the value in a minimal JSON document, decrypts it, and
    returns the plaintext string.

    Args:
        encrypted_string: The SOPS-encrypted string (e.g., "ENC[AES256_GCM,...]").
        key: The key name to use in the wrapper document.

    Returns:
        Decrypted plaintext string.

    Raises:
        SopsDecryptError: If decryption fails.
    """
    doc = json.dumps({key: encrypted_string, "sops": {}})
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tmp:
        tmp.write(doc)
        tmp_path = Path(tmp.name)

    try:
        result = _run_sops(["--decrypt", "--input-type", "json", "--output-type", "json", str(tmp_path)])
        if result.returncode != 0:
            raise SopsDecryptError("<inline>", result.stderr.strip())
        parsed = json.loads(result.stdout)
        return str(parsed.get(key, ""))
    finally:
        tmp_path.unlink(missing_ok=True)


@dataclass
class SopsCreationRule:
    """A single SOPS creation rule from .sops.yaml."""

    path_regex: str = ""
    kms: str = ""
    azure_keyvault: str = ""
    gcp_kms: str = ""
    age: str = ""
    pgp: str = ""
    encrypted_regex: str = ""


@dataclass
class SopsConfig:
    """Parsed .sops.yaml configuration."""

    path: Path
    creation_rules: list[SopsCreationRule] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> SopsConfig:
        """Parse a .sops.yaml file.

        Args:
            path: Path to .sops.yaml.

        Returns:
            Parsed SopsConfig.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is malformed.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f".sops.yaml not found: {p}")

        raw = yaml.safe_load(p.read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"Invalid .sops.yaml: expected a YAML mapping, got {type(raw).__name__}")

        rules_raw = raw.get("creation_rules", [])
        if not isinstance(rules_raw, list):
            raise ValueError("Invalid .sops.yaml: creation_rules must be a list")

        rules: list[SopsCreationRule] = []
        for entry in rules_raw:
            if not isinstance(entry, dict):
                continue
            rules.append(
                SopsCreationRule(
                    path_regex=entry.get("path_regex", ""),
                    kms=entry.get("kms", ""),
                    azure_keyvault=entry.get("azure_keyvault", ""),
                    gcp_kms=entry.get("gcp_kms", ""),
                    age=entry.get("age", ""),
                    pgp=entry.get("pgp", ""),
                    encrypted_regex=entry.get("encrypted_regex", ""),
                )
            )

        return cls(path=p, creation_rules=rules)

    def has_cloud_kms(self, rule_index: int | None = None) -> bool:
        """Check if a rule (or any rule) uses cloud KMS.

        Args:
            rule_index: Specific rule index to check. None checks all rules.

        Returns:
            True if cloud KMS is configured.
        """
        targets = [self.creation_rules[rule_index]] if rule_index is not None else self.creation_rules
        return any(
            bool(r.kms or r.azure_keyvault or r.gcp_kms)
            for r in targets
        )

    def rules_for_path(self, file_path: str) -> list[SopsCreationRule]:
        """Find creation rules whose path_regex matches the given path.

        Args:
            file_path: Relative file path to match.

        Returns:
            List of matching rules (first match wins in sops, but we
            return all matches for validation purposes).
        """
        import re

        matches: list[SopsCreationRule] = []
        for rule in self.creation_rules:
            if rule.path_regex:
                try:
                    if re.search(rule.path_regex, file_path):
                        matches.append(rule)
                except re.error:
                    continue
        return matches


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _detect_format(path: Path) -> str:
    """Detect file format from extension."""
    name = path.name.lower()
    # Strip .enc prefix if present (e.g., secrets.enc.yaml -> yaml)
    if ".enc." in name:
        suffix = name.split(".enc.")[-1]
    else:
        suffix = path.suffix.lstrip(".")

    if suffix in ("yaml", "yml"):
        return "yaml"
    elif suffix == "json":
        return "json"
    elif suffix in ("env", "dotenv"):
        return "dotenv"
    return "json"


def _parse_dotenv(content: str) -> dict[str, Any]:
    """Parse dotenv-formatted content into a dict."""
    result: dict[str, Any] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Strip optional quotes
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key.strip()] = value
    return result
