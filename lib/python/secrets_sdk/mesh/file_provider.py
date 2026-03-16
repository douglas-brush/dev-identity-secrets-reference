"""File-based secret provider using SOPS-encrypted files.

Reads secrets from SOPS-encrypted YAML/JSON files on disk, leveraging
the existing sops module. Supports a directory of encrypted files where
each file name (minus extension) maps to a secret key, or a single file
where top-level keys are secret keys.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

from secrets_sdk.mesh.provider import (
    ProviderHealth,
    ProviderStatus,
    SecretProvider,
    SecretValue,
)

logger = logging.getLogger(__name__)


class FileProvider(SecretProvider):
    """Secret provider backed by SOPS-encrypted files.

    Operates in two modes:
    1. **Directory mode** (path is a directory): Each encrypted file is a
       secret. The file stem is the key, the decrypted content is the value.
    2. **Single-file mode** (path is a file): The decrypted file is a dict
       of key-value pairs.

    Args:
        path: Path to a SOPS-encrypted file or directory of encrypted files.
        value_key: When in directory mode, the key within each file's
            decrypted dict to extract as the secret value. Defaults to "value".
        use_sops: If True (default), decrypt via sops. If False, read
            files as plaintext (for testing or unencrypted fallback).
    """

    def __init__(
        self,
        path: str | Path,
        value_key: str = "value",
        use_sops: bool = True,
    ) -> None:
        self._path = Path(path)
        self._value_key = value_key
        self._use_sops = use_sops
        # Cache decrypted single-file contents
        self._single_file_cache: dict[str, Any] | None = None

    @property
    def name(self) -> str:
        return "file"

    @property
    def is_directory_mode(self) -> bool:
        """True if operating on a directory of encrypted files."""
        return self._path.is_dir()

    def _read_file(self, file_path: Path) -> dict[str, Any]:
        """Read and optionally decrypt a file."""
        if self._use_sops:
            from secrets_sdk.sops import decrypt_file

            return decrypt_file(file_path)
        else:
            # Plaintext mode — parse JSON or YAML
            import json

            import yaml

            content = file_path.read_text()
            try:
                return dict(json.loads(content))
            except (json.JSONDecodeError, ValueError):
                loaded = yaml.safe_load(content)
                if isinstance(loaded, dict):
                    return loaded
                return {"data": loaded}

    def _load_single_file(self) -> dict[str, Any]:
        """Load and cache the single-file contents."""
        if self._single_file_cache is None:
            self._single_file_cache = self._read_file(self._path)
        return self._single_file_cache

    def _find_secret_file(self, key: str) -> Path | None:
        """Find an encrypted file matching the given key in directory mode."""
        # Try common extensions
        for ext in (".enc.yaml", ".enc.yml", ".enc.json", ".yaml", ".yml", ".json"):
            candidate = self._path / f"{key}{ext}"
            if candidate.exists():
                return candidate
        return None

    def get_secret(self, key: str) -> SecretValue:
        """Read a secret from SOPS-encrypted file(s).

        Raises:
            KeyError: If the secret key is not found.
            ConnectionError: If decryption fails.
        """
        try:
            if self.is_directory_mode:
                return self._get_from_directory(key)
            else:
                return self._get_from_single_file(key)
        except KeyError:
            raise
        except FileNotFoundError as exc:
            raise KeyError(f"Secret file not found: {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"Failed to read secret '{key}': {exc}") from exc

    def _get_from_directory(self, key: str) -> SecretValue:
        """Read a secret from a file in the directory."""
        file_path = self._find_secret_file(key)
        if file_path is None:
            raise KeyError(f"No encrypted file found for key: {key}")

        data = self._read_file(file_path)
        if self._value_key in data:
            value = str(data[self._value_key])
        else:
            import json

            value = json.dumps(data)

        return SecretValue(
            key=key,
            value=value,
            provider=self.name,
            metadata={"file": str(file_path), "keys": list(data.keys())},
        )

    def _get_from_single_file(self, key: str) -> SecretValue:
        """Read a secret key from the single decrypted file."""
        data = self._load_single_file()
        if key not in data:
            raise KeyError(f"Key '{key}' not found in {self._path}")

        raw_value = data[key]
        if isinstance(raw_value, dict):
            if self._value_key in raw_value:
                value = str(raw_value[self._value_key])
            else:
                import json

                value = json.dumps(raw_value)
        else:
            value = str(raw_value)

        return SecretValue(
            key=key,
            value=value,
            provider=self.name,
            metadata={"file": str(self._path)},
        )

    def put_secret(self, key: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        """File provider is read-only — writing encrypted files is not supported.

        Raises:
            PermissionError: Always, as this provider is read-only.
        """
        raise PermissionError("FileProvider is read-only. Use sops CLI to encrypt files.")

    def delete_secret(self, key: str) -> bool:
        """File provider is read-only — deletion is not supported.

        Raises:
            PermissionError: Always, as this provider is read-only.
        """
        raise PermissionError("FileProvider is read-only. Delete encrypted files manually.")

    def list_secrets(self, prefix: str = "") -> list[str]:
        """List available secret keys.

        In directory mode, returns file stems. In single-file mode,
        returns top-level keys from the decrypted data.
        """
        try:
            if self.is_directory_mode:
                return self._list_directory(prefix)
            else:
                return self._list_single_file(prefix)
        except Exception as exc:
            logger.warning("Failed to list secrets from file provider: %s", exc)
            return []

    def _list_directory(self, prefix: str) -> list[str]:
        """List encrypted files in the directory."""
        keys: list[str] = []
        enc_extensions = {".yaml", ".yml", ".json"}
        for entry in sorted(self._path.iterdir()):
            if not entry.is_file():
                continue
            stem = entry.stem
            # Handle .enc.yaml etc
            if ".enc" in entry.name:
                stem = entry.name.split(".enc")[0]
            elif entry.suffix in enc_extensions:
                stem = entry.stem
            else:
                continue
            if prefix and not stem.startswith(prefix):
                continue
            keys.append(stem)
        return keys

    def _list_single_file(self, prefix: str) -> list[str]:
        """List keys in the single decrypted file."""
        data = self._load_single_file()
        keys = sorted(data.keys())
        if prefix:
            keys = [k for k in keys if k.startswith(prefix)]
        return keys

    def invalidate_cache(self) -> None:
        """Clear the cached single-file contents, forcing re-decryption."""
        self._single_file_cache = None

    def health_check(self) -> ProviderHealth:
        """Check if the configured path exists and is readable."""
        t0 = time.monotonic()
        try:
            if not self._path.exists():
                latency = (time.monotonic() - t0) * 1000
                return ProviderHealth(
                    provider_name=self.name,
                    status=ProviderStatus.UNHEALTHY,
                    latency_ms=latency,
                    detail=f"Path does not exist: {self._path}",
                )

            if self._path.is_dir():
                enc_files = list(self._path.glob("*.enc.*")) + list(self._path.glob("*.yaml")) + list(self._path.glob("*.json"))
                latency = (time.monotonic() - t0) * 1000
                return ProviderHealth(
                    provider_name=self.name,
                    status=ProviderStatus.HEALTHY,
                    latency_ms=latency,
                    detail=f"Directory with {len(enc_files)} secret file(s)",
                )
            else:
                readable = os.access(self._path, os.R_OK)
                latency = (time.monotonic() - t0) * 1000
                status = ProviderStatus.HEALTHY if readable else ProviderStatus.UNHEALTHY
                detail = f"File readable: {readable}" if readable else f"File not readable: {self._path}"
                return ProviderHealth(
                    provider_name=self.name,
                    status=status,
                    latency_ms=latency,
                    detail=detail,
                )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ProviderHealth(
                provider_name=self.name,
                status=ProviderStatus.UNHEALTHY,
                latency_ms=latency,
                detail=str(exc),
            )
