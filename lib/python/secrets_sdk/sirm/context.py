"""SIRM context loader — gathers environment state for session initialization.

Collects git state, Vault health, SOPS configuration, identity inventory,
certificate status, and platform information.  All sensitive values are
automatically redacted (tokens masked to last 4 chars).
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secrets_sdk.sirm.models import (
    CertStatus,
    GitState,
    IdentityInventory,
    PlatformInfo,
    SessionContext,
    SopsConfig,
    VaultHealth,
)

logger = logging.getLogger(__name__)

# Environment variables to capture (values redacted)
_ENV_VARS_OF_INTEREST = [
    "VAULT_ADDR",
    "VAULT_TOKEN",
    "VAULT_NAMESPACE",
    "VAULT_CACERT",
    "SOPS_AGE_KEY_FILE",
    "SOPS_AGE_RECIPIENTS",
    "SOPS_PGP_FP",
    "GNUPGHOME",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "KUBECONFIG",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "PATH",
]

# Patterns that indicate sensitive values
_SENSITIVE_PATTERNS = re.compile(
    r"(token|secret|password|key|credential|api_key)", re.IGNORECASE
)


def _redact(value: str, var_name: str = "") -> str:
    """Redact sensitive values, showing only last 4 chars."""
    if not value:
        return ""
    is_sensitive = bool(_SENSITIVE_PATTERNS.search(var_name)) or var_name in {
        "VAULT_TOKEN",
        "SOPS_AGE_KEY_FILE",
    }
    if is_sensitive and len(value) > 4:
        return f"****{value[-4:]}"
    # PATH and similar are not sensitive
    return value


def _run_cmd(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Run a command and return (success, stdout)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode == 0, result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Command %s failed: %s", cmd, exc)
        return False, ""


class ContextLoader:
    """Gathers environment context for SIRM sessions.

    Each method can be called independently or via ``load_full_context()``
    / ``load_minimal_context()`` aggregators.
    """

    def __init__(self, repo_root: str | Path | None = None) -> None:
        self.repo_root = Path(repo_root) if repo_root else Path.cwd()

    # ------------------------------------------------------------------
    # Individual loaders
    # ------------------------------------------------------------------

    def load_git_state(self) -> GitState:
        """Gather current git repository state."""
        state = GitState()

        ok, branch = _run_cmd(["git", "-C", str(self.repo_root), "rev-parse", "--abbrev-ref", "HEAD"])
        if ok:
            state.branch = branch

        ok, commit = _run_cmd(["git", "-C", str(self.repo_root), "log", "-1", "--format=%H %s"])
        if ok and " " in commit:
            parts = commit.split(" ", 1)
            state.commit_hash = parts[0][:12]
            state.commit_message = parts[1]

        ok, status = _run_cmd(["git", "-C", str(self.repo_root), "status", "--porcelain"])
        if ok:
            lines = [l for l in status.splitlines() if l.strip()]
            state.is_dirty = len(lines) > 0
            state.untracked_count = sum(1 for l in lines if l.startswith("??"))

        ok, remote = _run_cmd(["git", "-C", str(self.repo_root), "remote", "get-url", "origin"])
        if ok:
            state.remote_url = remote

        ok, ahead_behind = _run_cmd(
            ["git", "-C", str(self.repo_root), "rev-list", "--left-right", "--count", "HEAD...@{upstream}"]
        )
        if ok and "\t" in ahead_behind:
            parts = ahead_behind.split("\t")
            try:
                state.ahead = int(parts[0])
                state.behind = int(parts[1])
            except (ValueError, IndexError):
                pass

        return state

    def load_vault_health(self) -> VaultHealth:
        """Check Vault server health and token validity."""
        health = VaultHealth()
        health.addr = os.environ.get("VAULT_ADDR", "")

        if not shutil.which("vault"):
            return health

        ok, output = _run_cmd(["vault", "status", "-format=json"])
        if ok:
            try:
                import json
                data = json.loads(output)
                health.reachable = True
                health.initialized = data.get("initialized", False)
                health.sealed = data.get("sealed", True)
                health.version = data.get("version", "")
            except (json.JSONDecodeError, KeyError):
                health.reachable = True

        ok, output = _run_cmd(["vault", "token", "lookup", "-format=json"])
        if ok:
            try:
                import json
                data = json.loads(output)
                token_data = data.get("data", {})
                health.token_valid = True
                health.token_ttl = token_data.get("ttl", 0)
            except (json.JSONDecodeError, KeyError):
                pass

        return health

    def load_sops_config(self) -> SopsConfig:
        """Parse SOPS configuration from .sops.yaml."""
        config = SopsConfig()

        sops_path = self.repo_root / ".sops.yaml"
        if not sops_path.exists():
            return config

        config.config_found = True
        config.config_path = str(sops_path)

        try:
            import yaml
            data = yaml.safe_load(sops_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                rules = data.get("creation_rules", [])
                config.creation_rules_count = len(rules) if isinstance(rules, list) else 0
                key_types: set[str] = set()
                for rule in (rules if isinstance(rules, list) else []):
                    if isinstance(rule, dict):
                        if rule.get("age"):
                            key_types.add("age")
                        if rule.get("pgp") or rule.get("gcp_kms") or rule.get("azure_kv"):
                            key_types.add("kms")
                        if rule.get("hc_vault_transit_uri"):
                            key_types.add("vault_transit")
                config.key_types = sorted(key_types)
        except Exception as exc:
            logger.debug("Failed to parse .sops.yaml: %s", exc)

        return config

    def load_identity_inventory(self) -> IdentityInventory:
        """Gather operator identity information."""
        identity = IdentityInventory()

        ok, user = _run_cmd(["git", "config", "user.name"])
        if ok:
            identity.git_user = user

        ok, email = _run_cmd(["git", "config", "user.email"])
        if ok:
            identity.git_email = email

        # SSH keys
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir.is_dir():
            identity.ssh_keys = sorted(
                str(p.name)
                for p in ssh_dir.iterdir()
                if p.suffix == ".pub" and p.is_file()
            )

        # GPG keys
        ok, gpg_out = _run_cmd(["gpg", "--list-keys", "--keyid-format", "short", "--with-colons"])
        if ok:
            for line in gpg_out.splitlines():
                if line.startswith("pub:"):
                    fields = line.split(":")
                    if len(fields) > 4:
                        identity.gpg_keys.append(fields[4])

        return identity

    def load_cert_status(self) -> CertStatus:
        """Scan for certificates and check expiry status."""
        status = CertStatus()

        # Check common cert locations
        cert_dirs = [
            self.repo_root / "certs",
            self.repo_root / "tls",
            self.repo_root / "platform" / "tls",
            Path.home() / ".local" / "share" / "mkcert",
        ]

        for cert_dir in cert_dirs:
            if not cert_dir.is_dir():
                continue
            for cert_file in cert_dir.glob("*.pem"):
                if "ca" in cert_file.name.lower():
                    status.ca_certs_found += 1
                else:
                    status.client_certs_found += 1

                # Try to check expiry with openssl
                ok, output = _run_cmd([
                    "openssl", "x509", "-in", str(cert_file),
                    "-noout", "-enddate",
                ])
                if ok and "notAfter=" in output:
                    try:
                        date_str = output.split("notAfter=")[1].strip()
                        # openssl date format: "Mar 15 12:00:00 2026 GMT"
                        from email.utils import parsedate_to_datetime
                        expiry = parsedate_to_datetime(date_str.replace("GMT", "+0000"))
                        now = datetime.now(timezone.utc)
                        days_left = (expiry - now).days
                        if days_left < 0:
                            status.expired_certs += 1
                        elif days_left < 30:
                            status.expiring_soon += 1
                    except Exception:
                        pass

        return status

    def load_environment_vars(self) -> dict[str, str]:
        """Capture relevant environment variables with redaction."""
        result: dict[str, str] = {}
        for var in _ENV_VARS_OF_INTEREST:
            value = os.environ.get(var, "")
            if value:
                result[var] = _redact(value, var)
        return result

    def load_platform_info(self) -> PlatformInfo:
        """Gather host platform information."""
        return PlatformInfo(
            os=platform.system(),
            os_version=platform.release(),
            hostname=platform.node(),
            python_version=platform.python_version(),
            arch=platform.machine(),
        )

    # ------------------------------------------------------------------
    # Aggregators
    # ------------------------------------------------------------------

    def load_full_context(self) -> SessionContext:
        """Load complete environment context."""
        return SessionContext(
            git_state=self.load_git_state(),
            vault_health=self.load_vault_health(),
            sops_config=self.load_sops_config(),
            identity_inventory=self.load_identity_inventory(),
            cert_status=self.load_cert_status(),
            environment_vars=self.load_environment_vars(),
            platform_info=self.load_platform_info(),
        )

    def load_minimal_context(self) -> SessionContext:
        """Load minimal context (git + vault health only) for quick sessions."""
        return SessionContext(
            git_state=self.load_git_state(),
            vault_health=self.load_vault_health(),
            platform_info=self.load_platform_info(),
        )

    # ------------------------------------------------------------------
    # Context comparison
    # ------------------------------------------------------------------

    @staticmethod
    def diff_context(before: SessionContext, after: SessionContext) -> dict[str, Any]:
        """Compare two context snapshots and return differences.

        Returns a dict keyed by section name, each value being a dict of
        field_name -> {"before": old_value, "after": new_value}.
        """
        diffs: dict[str, Any] = {}

        sections = [
            ("git_state", before.git_state, after.git_state),
            ("vault_health", before.vault_health, after.vault_health),
            ("sops_config", before.sops_config, after.sops_config),
            ("identity_inventory", before.identity_inventory, after.identity_inventory),
            ("cert_status", before.cert_status, after.cert_status),
            ("platform_info", before.platform_info, after.platform_info),
        ]

        for name, b, a in sections:
            b_dict = b.model_dump()
            a_dict = a.model_dump()
            section_diffs: dict[str, dict[str, Any]] = {}
            for key in b_dict:
                if b_dict[key] != a_dict.get(key):
                    section_diffs[key] = {
                        "before": b_dict[key],
                        "after": a_dict.get(key),
                    }
            if section_diffs:
                diffs[name] = section_diffs

        # Environment vars
        env_diffs: dict[str, dict[str, str]] = {}
        all_keys = set(before.environment_vars) | set(after.environment_vars)
        for key in all_keys:
            bv = before.environment_vars.get(key, "")
            av = after.environment_vars.get(key, "")
            if bv != av:
                env_diffs[key] = {"before": bv, "after": av}
        if env_diffs:
            diffs["environment_vars"] = env_diffs

        return diffs
