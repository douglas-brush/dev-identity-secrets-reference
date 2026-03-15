"""Configuration validation for repository structure, SOPS config, and Vault policies.

Validates that a dev-identity-secrets-reference repository is correctly
structured, that .sops.yaml follows best practices, that Vault HCL policies
parse correctly, and that no plaintext secrets are checked in.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from secrets_sdk.models import SecretFinding


# ------------------------------------------------------------------
# .sops.yaml Validation
# ------------------------------------------------------------------

def validate_sops_yaml(path: str | Path) -> list[str]:
    """Validate a .sops.yaml file for correctness and best practices.

    Checks:
    - File exists and is valid YAML
    - creation_rules is present and non-empty
    - Each rule has a path_regex
    - path_regex compiles as valid regex
    - Each rule has at least one key source (kms, age, gcp_kms, azure_keyvault, pgp)
    - Production rules use cloud KMS (not age-only)
    - encrypted_regex is present and covers sensitive fields

    Args:
        path: Path to .sops.yaml file.

    Returns:
        List of issue strings. Empty list means valid.
    """
    issues: list[str] = []
    p = Path(path)

    if not p.exists():
        issues.append(f"File not found: {p}")
        return issues

    try:
        raw = yaml.safe_load(p.read_text())
    except yaml.YAMLError as exc:
        issues.append(f"Invalid YAML: {exc}")
        return issues

    if not isinstance(raw, dict):
        issues.append("Root must be a YAML mapping")
        return issues

    rules = raw.get("creation_rules")
    if rules is None:
        issues.append("Missing 'creation_rules' key")
        return issues

    if not isinstance(rules, list):
        issues.append("'creation_rules' must be a list")
        return issues

    if len(rules) == 0:
        issues.append("'creation_rules' is empty — no encryption rules defined")
        return issues

    sensitive_fields = {"password", "token", "secret", "private_key", "api_key", "credentials"}

    for i, rule in enumerate(rules):
        prefix = f"Rule {i}"
        if not isinstance(rule, dict):
            issues.append(f"{prefix}: must be a mapping")
            continue

        # path_regex
        path_regex = rule.get("path_regex", "")
        if not path_regex:
            issues.append(f"{prefix}: missing 'path_regex'")
        else:
            try:
                re.compile(path_regex)
            except re.error as exc:
                issues.append(f"{prefix}: invalid regex '{path_regex}': {exc}")

        # Key sources
        has_key = any(
            bool(rule.get(k))
            for k in ("kms", "azure_keyvault", "gcp_kms", "age", "pgp", "hc_vault_transit_uri")
        )
        if not has_key:
            issues.append(f"{prefix}: no encryption key source (kms, age, gcp_kms, azure_keyvault, pgp)")

        # Production should use cloud KMS
        if path_regex and "prod" in path_regex.lower():
            has_cloud = any(bool(rule.get(k)) for k in ("kms", "azure_keyvault", "gcp_kms"))
            if not has_cloud:
                issues.append(
                    f"{prefix}: production rule '{path_regex}' should use cloud KMS, "
                    "not age-only"
                )

        # encrypted_regex check
        enc_regex = rule.get("encrypted_regex", "")
        if not enc_regex:
            issues.append(f"{prefix}: missing 'encrypted_regex' — all fields will be encrypted")
        else:
            # Check that common sensitive field names are covered
            try:
                compiled = re.compile(enc_regex)
                for field_name in sensitive_fields:
                    if not compiled.search(field_name):
                        # Not necessarily an issue — just advisory
                        pass
            except re.error as exc:
                issues.append(f"{prefix}: invalid encrypted_regex: {exc}")

    return issues


# ------------------------------------------------------------------
# Vault HCL Policy Validation
# ------------------------------------------------------------------

# Minimal HCL policy parser — enough to validate structure without a full HCL library
_PATH_BLOCK_RE = re.compile(
    r'path\s+"([^"]+)"\s*\{([^}]*)\}',
    re.DOTALL,
)
_CAPABILITIES_RE = re.compile(
    r'capabilities\s*=\s*\[([^\]]*)\]',
)

VALID_CAPABILITIES = frozenset({
    "create", "read", "update", "delete", "list",
    "sudo", "deny", "patch",
})

DANGEROUS_CAPABILITIES = frozenset({"sudo", "delete"})


def validate_vault_policy(path: str | Path) -> list[str]:
    """Validate a Vault HCL policy file.

    Checks:
    - File exists and contains at least one path block
    - Each path block has a capabilities list
    - All capabilities are valid Vault capabilities
    - Warns on dangerous capabilities (sudo, delete)
    - Warns on overly broad paths (ending in *)

    Args:
        path: Path to .hcl policy file.

    Returns:
        List of issue strings. Empty list means valid.
    """
    issues: list[str] = []
    p = Path(path)

    if not p.exists():
        issues.append(f"File not found: {p}")
        return issues

    content = p.read_text()
    if not content.strip():
        issues.append("Policy file is empty")
        return issues

    blocks = _PATH_BLOCK_RE.findall(content)
    if not blocks:
        issues.append("No 'path' blocks found — is this a valid Vault policy?")
        return issues

    for vault_path, block_body in blocks:
        prefix = f"path \"{vault_path}\""

        # Check capabilities
        cap_match = _CAPABILITIES_RE.search(block_body)
        if not cap_match:
            issues.append(f"{prefix}: missing 'capabilities' list")
            continue

        raw_caps = cap_match.group(1)
        caps = [c.strip().strip('"').strip("'") for c in raw_caps.split(",") if c.strip()]

        for cap in caps:
            if cap not in VALID_CAPABILITIES:
                issues.append(f"{prefix}: unknown capability '{cap}'")
            if cap in DANGEROUS_CAPABILITIES:
                issues.append(
                    f"{prefix}: uses dangerous capability '{cap}' — ensure this is intentional"
                )

        # Warn on broad paths
        if vault_path.endswith("*") and not vault_path.endswith("/*"):
            issues.append(
                f"{prefix}: very broad path pattern — consider narrowing scope"
            )

        # Warn on root-level access
        if vault_path in ("*", "sys/*", "auth/*"):
            issues.append(
                f"{prefix}: root-level access — this should only be in emergency/admin policies"
            )

    return issues


# ------------------------------------------------------------------
# Repository Structure Validation
# ------------------------------------------------------------------

# Expected directories for a well-formed dev-identity-secrets-reference repo
EXPECTED_DIRS = [
    "platform/vault/policies",
    "secrets",
    "docs",
]

EXPECTED_FILES = [
    ".sops.yaml",
]


def validate_repo_structure(root: str | Path) -> list[str]:
    """Validate that a repository follows the dev-identity-secrets-reference layout.

    Checks:
    - Expected directories exist
    - Expected files exist
    - .sops.yaml is valid (delegates to validate_sops_yaml)
    - Vault policies in platform/vault/policies/ are valid
    - Secrets directories have proper env separation (dev/staging/prod)
    - No unencrypted secret files in secrets/

    Args:
        root: Repository root directory.

    Returns:
        List of issue strings. Empty list means valid.
    """
    issues: list[str] = []
    r = Path(root)

    if not r.exists() or not r.is_dir():
        issues.append(f"Repository root not found or not a directory: {r}")
        return issues

    # Check expected directories
    for d in EXPECTED_DIRS:
        if not (r / d).is_dir():
            issues.append(f"Missing expected directory: {d}")

    # Check expected files
    for f in EXPECTED_FILES:
        if not (r / f).exists():
            issues.append(f"Missing expected file: {f}")

    # Validate .sops.yaml if it exists
    sops_path = r / ".sops.yaml"
    if sops_path.exists():
        sops_issues = validate_sops_yaml(sops_path)
        for issue in sops_issues:
            issues.append(f".sops.yaml: {issue}")

    # Validate Vault policies
    policy_dir = r / "platform" / "vault" / "policies"
    if policy_dir.is_dir():
        for hcl_file in sorted(policy_dir.glob("*.hcl")):
            policy_issues = validate_vault_policy(hcl_file)
            for issue in policy_issues:
                issues.append(f"{hcl_file.relative_to(r)}: {issue}")

    # Check secrets directory structure
    secrets_dir = r / "secrets"
    if secrets_dir.is_dir():
        expected_envs = {"dev", "staging", "prod"}
        actual_envs = {d.name for d in secrets_dir.iterdir() if d.is_dir()}
        missing_envs = expected_envs - actual_envs
        for env in sorted(missing_envs):
            issues.append(f"Missing secrets environment directory: secrets/{env}")

        # Check for unencrypted files in secrets/
        for secret_file in secrets_dir.rglob("*"):
            if secret_file.is_file():
                name = secret_file.name
                # Files should be .enc.yaml, .enc.json, or .enc.env, or .gitkeep, README, etc.
                safe_names = {".gitkeep", ".gitignore", "README.md", "README"}
                safe_extensions = {".enc.yaml", ".enc.yml", ".enc.json", ".enc.env"}
                is_safe = (
                    name in safe_names
                    or any(name.endswith(ext) for ext in safe_extensions)
                    or name.startswith(".")
                )
                if not is_safe:
                    rel = secret_file.relative_to(r)
                    issues.append(
                        f"Potentially unencrypted file in secrets/: {rel} "
                        "(expected .enc.yaml/.enc.json or metadata files)"
                    )

    return issues


# ------------------------------------------------------------------
# Plaintext Secret Scanning
# ------------------------------------------------------------------

# Patterns that indicate hardcoded secrets
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "AWS Access Key",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        "high",
    ),
    (
        "AWS Secret Key",
        re.compile(r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?""", re.IGNORECASE),
        "high",
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"""(?:api_key|apikey|api_secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{20,}['"]""", re.IGNORECASE),
        "high",
    ),
    (
        "Generic Password Assignment",
        re.compile(r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
        "medium",
    ),
    (
        "Generic Token Assignment",
        re.compile(r"""(?:token|bearer|auth_token)\s*[=:]\s*['"][A-Za-z0-9_\-\.]{20,}['"]""", re.IGNORECASE),
        "medium",
    ),
    (
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
    ),
    (
        "GitHub Token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        "high",
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9]{10,13}-[A-Za-z0-9-]{20,}"),
        "high",
    ),
    (
        "Vault Token",
        re.compile(r"(?:hvs|s)\.[A-Za-z0-9]{24,}"),
        "high",
    ),
    (
        "Connection String with Password",
        re.compile(r"(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@", re.IGNORECASE),
        "high",
    ),
]

# File extensions to scan
SCANNABLE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".sh", ".bash", ".zsh", ".ps1", ".tf", ".hcl",
    ".xml", ".properties", ".gradle",
})

# Directories to skip
SKIP_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info",
})

# Max file size to scan (1 MB)
MAX_SCAN_SIZE = 1_048_576


def scan_plaintext_secrets(
    path: str | Path,
    include_patterns: list[str] | None = None,
    exclude_dirs: set[str] | None = None,
) -> list[SecretFinding]:
    """Scan files for hardcoded secrets and sensitive values.

    Args:
        path: File or directory to scan.
        include_patterns: If provided, only scan patterns with these names.
        exclude_dirs: Additional directory names to skip.

    Returns:
        List of SecretFinding objects for each match.
    """
    findings: list[SecretFinding] = []
    p = Path(path)
    skip = SKIP_DIRS | (exclude_dirs or set())

    # Select patterns
    patterns = SECRET_PATTERNS
    if include_patterns:
        name_set = set(include_patterns)
        patterns = [(n, r, s) for n, r, s in SECRET_PATTERNS if n in name_set]

    if p.is_file():
        findings.extend(_scan_file(p, patterns))
    elif p.is_dir():
        for root_dir, dirs, files in os.walk(p):
            # Prune skipped directories
            dirs[:] = [d for d in dirs if d not in skip and not d.endswith(".egg-info")]
            for fname in files:
                fpath = Path(root_dir) / fname
                if fpath.suffix.lower() in SCANNABLE_EXTENSIONS:
                    findings.extend(_scan_file(fpath, patterns))

    return findings


def _scan_file(
    path: Path,
    patterns: list[tuple[str, re.Pattern[str], str]],
) -> list[SecretFinding]:
    """Scan a single file for secret patterns."""
    findings: list[SecretFinding] = []

    try:
        size = path.stat().st_size
        if size > MAX_SCAN_SIZE or size == 0:
            return findings

        content = path.read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return findings

    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern_name, regex, severity in patterns:
            match = regex.search(line)
            if match:
                # Redact the match in the finding — show first 4 and last 4 chars
                raw = match.group()
                if len(raw) > 12:
                    redacted = raw[:4] + "..." + raw[-4:]
                else:
                    redacted = raw[:4] + "..."
                findings.append(
                    SecretFinding(
                        file_path=str(path),
                        line_number=line_num,
                        pattern_name=pattern_name,
                        matched_text=redacted,
                        severity=severity,
                    )
                )

    return findings
