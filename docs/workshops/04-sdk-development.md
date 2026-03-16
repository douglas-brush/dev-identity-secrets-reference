# Workshop 04: SDK Development

**Duration:** 2 hours
**Level:** Intermediate
**Audience:** Application developers, SDK contributors, security engineers building tooling

---

## Objectives

By the end of this workshop, participants will be able to:

1. Install and configure the Python SDK for Vault operations
2. Use the SOPS integration module for encrypted config file handling
3. Define and check secret rotation policies programmatically
4. Build a custom CLI tool using the SDK
5. Contribute code back to the repository following project conventions

---

## Prerequisites

| Requirement | Check |
|-------------|-------|
| Completed Workshop 01 or equivalent Vault familiarity | -- |
| Docker 24.0+ and Docker Compose 2.20+ | `docker --version` |
| Python 3.10+ | `python3 --version` |
| pip | `pip --version` |
| `sops` 3.8+ (Lab 2) | `sops --version` |
| `age` 1.1+ (Lab 2) | `age --version` |
| Vault CLI | `vault version` |
| Familiarity with Python (or Go/TypeScript for alternate labs) | -- |

### Environment Setup

```bash
cd dev-identity-secrets-reference

# Start the dev environment
make dev-up && make dev-setup

export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token

# Seed demo data for the SDK labs
cd dev && make seed-demo-data 2>/dev/null; cd ..
```

---

## Lab 1: Python SDK Setup and Basic Vault Operations (25 minutes)

### Concept

The SDKs (`lib/python/`, `lib/go/`, `lib/typescript/`) provide language-idiomatic interfaces to Vault, SOPS, config validation, and rotation checking. All three SDKs implement the same logical surface (see `docs/23-sdk-design-guide.md`).

This workshop focuses on the Python SDK. The patterns translate directly to Go and TypeScript.

### 1.1 Install the Python SDK

```bash
# Create a virtual environment for the workshop
python3 -m venv /tmp/workshop-sdk-venv
source /tmp/workshop-sdk-venv/bin/activate

# Install the SDK in development mode
pip install -e lib/python/

# Verify installation
python3 -c "from secrets_sdk import VaultClient; print('SDK installed successfully')"
```

### 1.2 Connect to Vault

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient

# The SDK reads VAULT_ADDR and VAULT_TOKEN from environment by default
client = VaultClient()

# Check Vault health
health = client.health()
print(f"Vault version: {health.get('version', 'unknown')}")
print(f"Sealed: {health.get('sealed', 'unknown')}")
print(f"Initialized: {health.get('initialized', 'unknown')}")
PYEOF
```

Expected: Vault version, sealed=False, initialized=True.

### 1.3 KV Operations

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient

client = VaultClient()

# Write a secret
client.kv_write("workshop/sdk-demo", {
    "api_key": "sk-workshop-sdk-12345",
    "api_url": "https://api.example.com",
    "environment": "development",
})
print("Secret written to workshop/sdk-demo")

# Read the secret
secret = client.kv_read("workshop/sdk-demo")
print(f"Read back: {secret}")

# Read a specific version
secret_v1 = client.kv_read("workshop/sdk-demo", version=1)
print(f"Version 1: {secret_v1}")

# Update the secret (creates version 2)
client.kv_write("workshop/sdk-demo", {
    "api_key": "sk-workshop-sdk-67890-rotated",
    "api_url": "https://api.example.com",
    "environment": "staging",
})
print("Secret updated (version 2)")

# Read version 2
secret_v2 = client.kv_read("workshop/sdk-demo")
print(f"Version 2: {secret_v2}")

# Delete the secret
client.kv_delete("workshop/sdk-demo")
print("Secret deleted")
PYEOF
```

### 1.4 Dynamic Credentials

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient

client = VaultClient()

# Request dynamic database credentials
creds = client.dynamic_creds("database", "demo-readonly")
print(f"Username: {creds['username']}")
print(f"Password: {creds['password'][:8]}...")
print(f"Lease ID: {creds['lease_id']}")
print(f"Lease duration: {creds['lease_duration']}s")

# In production, you would use these credentials to connect to the database
# When done, the lease expires automatically or you can revoke it
PYEOF
```

### 1.5 Transit Encryption

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient

client = VaultClient()

# Create a key (if not exists)
try:
    import requests
    requests.post(
        f"{client.addr}/v1/transit/keys/sdk-workshop-key",
        headers={"X-Vault-Token": client.token},
    )
except Exception:
    pass

# Encrypt
ciphertext = client.transit_encrypt("transit", "sdk-workshop-key", "sensitive-data-to-protect")
print(f"Ciphertext: {ciphertext[:50]}...")

# Decrypt
plaintext = client.transit_decrypt("transit", "sdk-workshop-key", ciphertext)
print(f"Plaintext: {plaintext}")

assert plaintext == "sensitive-data-to-protect", "Decryption mismatch!"
print("Transit encrypt/decrypt roundtrip successful")
PYEOF
```

### 1.6 Error Handling

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient
from secrets_sdk.exceptions import (
    VaultSecretNotFound,
    VaultAuthError,
    VaultConnectionError,
    SecretsSDKError,
)

client = VaultClient()

# Handle "not found"
try:
    client.kv_read("nonexistent/path/that/does/not/exist")
except VaultSecretNotFound as e:
    print(f"Expected error: {e}")
except SecretsSDKError as e:
    print(f"SDK error (may vary by Vault state): {e}")

# Handle connection errors
try:
    bad_client = VaultClient(addr="http://localhost:9999")
    bad_client.health()
except VaultConnectionError as e:
    print(f"Connection error: {e}")
except SecretsSDKError as e:
    print(f"SDK error: {e}")

print("Error handling works correctly")
PYEOF
```

**Verification:**
- [ ] SDK installed in a virtual environment
- [ ] Connected to Vault and read health status
- [ ] Performed KV write, read (with versioning), and delete
- [ ] Generated dynamic database credentials
- [ ] Encrypted and decrypted data with Transit
- [ ] Error handling catches expected exceptions

---

## Lab 2: SOPS Integration and Config Validation (25 minutes)

### Concept

The SDK includes a SOPS module for programmatic encryption/decryption and a config validation module that checks repository structure, `.sops.yaml` rules, and Vault policy files.

### 2.1 SOPS Decrypt with the SDK

```bash
# First, create an encrypted file to work with
mkdir -p /tmp/workshop-sdk-sops
age-keygen -o /tmp/workshop-sdk-sops/key.txt 2>/dev/null
AGE_RECIPIENT=$(grep "^# public key:" /tmp/workshop-sdk-sops/key.txt | cut -d' ' -f4)
export SOPS_AGE_KEY_FILE=/tmp/workshop-sdk-sops/key.txt

cat > /tmp/workshop-sdk-sops/config.yaml <<EOF
app_name: workshop-demo
secrets:
  api_key: "sk-live-secret-value"
  db_password: "super-secret"
EOF

sops --encrypt \
  --age "$AGE_RECIPIENT" \
  --encrypted-regex '^(api_key|db_password)$' \
  /tmp/workshop-sdk-sops/config.yaml > /tmp/workshop-sdk-sops/config.enc.yaml
```

Now use the SDK to decrypt:

```bash
python3 <<'PYEOF'
from secrets_sdk.sops import decrypt_file

# Decrypt the SOPS-encrypted file
result = decrypt_file("/tmp/workshop-sdk-sops/config.enc.yaml")
print(f"Decrypted config: {result}")
print(f"App name: {result.get('app_name', 'unknown')}")
print(f"API key: {result.get('secrets', {}).get('api_key', 'not found')}")
PYEOF
```

### 2.2 Validate `.sops.yaml` Configuration

```bash
python3 <<'PYEOF'
from secrets_sdk.config import validate_sops_yaml

# Validate the repository's .sops.yaml
issues = validate_sops_yaml(".sops.yaml")

if issues:
    print(f"Found {len(issues)} issues:")
    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")
else:
    print("No issues found -- .sops.yaml is valid")
PYEOF
```

### 2.3 Validate Repository Structure

```bash
python3 <<'PYEOF'
from secrets_sdk.config import validate_sops_yaml
from pathlib import Path

# Check for common structural issues
repo_root = Path(".")

checks = {
    ".sops.yaml exists": (repo_root / ".sops.yaml").exists(),
    ".pre-commit-config.yaml exists": (repo_root / ".pre-commit-config.yaml").exists(),
    "platform/vault/policies/ exists": (repo_root / "platform" / "vault" / "policies").is_dir(),
    "secrets/ directory exists": (repo_root / "secrets").is_dir(),
    "tools/ directory exists": (repo_root / "tools").is_dir(),
}

print("Repository structure validation:")
for check, passed in checks.items():
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {check}")

# Validate SOPS config
sops_issues = validate_sops_yaml(".sops.yaml")
print(f"\n.sops.yaml validation: {len(sops_issues)} issues")
for issue in sops_issues:
    print(f"  - {issue}")
PYEOF
```

### 2.4 Scan for Plaintext Secrets

```bash
python3 <<'PYEOF'
from secrets_sdk.config import validate_sops_yaml
from pathlib import Path
import re

# Simple secret pattern scanner using the SDK patterns
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'sk-[a-zA-Z0-9]{20,}', "Generic API Key (sk- prefix)"),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
]

def scan_file(filepath: Path) -> list[dict]:
    findings = []
    try:
        content = filepath.read_text(errors="ignore")
        for pattern, description in SECRET_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    "file": str(filepath),
                    "pattern": description,
                    "line": content[:match.start()].count("\n") + 1,
                })
    except Exception:
        pass
    return findings

# Scan example files (limited scope for workshop)
scan_dirs = [Path("examples"), Path("dev")]
all_findings = []

for scan_dir in scan_dirs:
    if not scan_dir.exists():
        continue
    for f in scan_dir.rglob("*"):
        if f.is_file() and f.suffix in (".py", ".sh", ".yaml", ".yml", ".json", ".env", ".txt"):
            findings = scan_file(f)
            all_findings.extend(findings)

print(f"Scanned directories: {[str(d) for d in scan_dirs]}")
print(f"Total findings: {len(all_findings)}")
for finding in all_findings[:10]:
    print(f"  [{finding['pattern']}] {finding['file']}:{finding['line']}")
PYEOF
```

**Verification:**
- [ ] Decrypted a SOPS-encrypted file using the SDK
- [ ] Validated `.sops.yaml` and identified issues
- [ ] Validated repository structure
- [ ] Ran a simple secret pattern scan using SDK patterns

---

## Lab 3: Secret Rotation Policies (20 minutes)

### Concept

The SDK's rotation module lets you define policies (max age, warning thresholds, paths) and check Vault secrets against them. This enables automated rotation compliance monitoring.

### 3.1 Define Rotation Policies

```bash
python3 <<'PYEOF'
from secrets_sdk.rotation import RotationPolicy

# Define policies for different secret types
policies = [
    RotationPolicy(
        name="database-credentials",
        max_age_days=30,
        paths=["secret/data/*/database", "secret/data/*/db-*"],
        warn_age_days=25,
        auto_rotate=True,
        notify_channels=["slack"],
    ),
    RotationPolicy(
        name="api-keys",
        max_age_days=90,
        paths=["secret/data/*/api-keys", "secret/data/*/api-*"],
        warn_age_days=75,
        auto_rotate=False,
        notify_channels=["email", "slack"],
    ),
    RotationPolicy(
        name="signing-keys",
        max_age_days=365,
        paths=["transit/keys/*"],
        warn_age_days=330,
        auto_rotate=False,
        notify_channels=["email", "slack", "pagerduty"],
    ),
]

for policy in policies:
    print(f"Policy: {policy.name}")
    print(f"  Max age: {policy.max_age_days} days")
    print(f"  Warning at: {policy.warn_age_days} days")
    print(f"  Auto-rotate: {policy.auto_rotate}")
    print(f"  Paths: {policy.paths}")
    print()
PYEOF
```

### 3.2 Check Secret Ages Against Policies

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient
from secrets_sdk.rotation import RotationPolicy
from datetime import datetime, timezone

client = VaultClient()

# Write a test secret to check age against
client.kv_write("workshop/rotation-test", {
    "api_key": "test-key-value",
    "created_by": "workshop",
})

# Read the secret metadata to get creation time
import requests
resp = requests.get(
    f"{client.addr}/v1/secret/metadata/workshop/rotation-test",
    headers={"X-Vault-Token": client.token},
)

if resp.ok:
    metadata = resp.json().get("data", {})
    versions = metadata.get("versions", {})
    for ver_num, ver_data in versions.items():
        created = ver_data.get("created_time", "unknown")
        destroyed = ver_data.get("destroyed", False)
        print(f"Version {ver_num}: created={created}, destroyed={destroyed}")

# Define a policy and check compliance
policy = RotationPolicy(
    name="workshop-api-keys",
    max_age_days=90,
    paths=["secret/data/workshop/*"],
    warn_age_days=75,
)

# Since we just created it, it should be compliant
print(f"\nPolicy: {policy.name} (max age: {policy.max_age_days} days)")
print(f"Secret age: < 1 day")
print(f"Status: COMPLIANT (within {policy.max_age_days}-day window)")

# Simulate an aged secret check
from datetime import timedelta
simulated_age = 85
if simulated_age >= policy.max_age_days:
    status = "EXPIRED -- rotation required"
elif simulated_age >= policy.warn_age_days:
    status = f"WARNING -- {policy.max_age_days - simulated_age} days until rotation required"
else:
    status = "COMPLIANT"
print(f"\nSimulated age: {simulated_age} days")
print(f"Status: {status}")

# Cleanup
client.kv_delete("workshop/rotation-test")
PYEOF
```

### 3.3 Build a Rotation Report

```bash
python3 <<'PYEOF'
from secrets_sdk import VaultClient
from datetime import datetime, timezone, timedelta
import json

client = VaultClient()

# List all secrets under a path and check their ages
def check_rotation_compliance(client, base_path, max_age_days):
    """Check all secrets under a path for rotation compliance."""
    report = {"path": base_path, "max_age_days": max_age_days, "secrets": []}

    try:
        import requests
        resp = requests.request(
            "LIST",
            f"{client.addr}/v1/secret/metadata/{base_path}",
            headers={"X-Vault-Token": client.token},
        )
        if not resp.ok:
            report["error"] = f"Cannot list path: {resp.status_code}"
            return report

        keys = resp.json().get("data", {}).get("keys", [])
        for key in keys:
            if key.endswith("/"):
                continue  # Skip subdirectories
            secret_path = f"{base_path}/{key}" if base_path else key

            meta_resp = requests.get(
                f"{client.addr}/v1/secret/metadata/{secret_path}",
                headers={"X-Vault-Token": client.token},
            )
            if not meta_resp.ok:
                continue

            versions = meta_resp.json().get("data", {}).get("versions", {})
            latest = max(versions.keys(), key=int) if versions else None
            if latest:
                created = versions[latest].get("created_time", "")
                report["secrets"].append({
                    "path": secret_path,
                    "version": int(latest),
                    "created": created,
                })

    except Exception as e:
        report["error"] = str(e)

    return report

# Generate report for demo secrets
report = check_rotation_compliance(client, "demo", max_age_days=90)
print(json.dumps(report, indent=2))
PYEOF
```

**Verification:**
- [ ] Defined rotation policies with max age, warning threshold, and notification channels
- [ ] Checked a secret's age against a rotation policy
- [ ] Built a rotation compliance report for a Vault path

---

## Lab 4: Building a Custom Tool with the SDK (25 minutes)

### Concept

The SDK is designed to be the foundation for custom security tools. In this lab, we build a complete CLI tool that checks a team's secrets for rotation compliance, validates their SOPS configuration, and produces a structured report.

### 4.1 Create the Tool

```bash
mkdir -p /tmp/workshop-tool

cat > /tmp/workshop-tool/team_health_check.py <<'PYEOF'
#!/usr/bin/env python3
"""team-health-check — Validate a team's secrets management posture.

Checks:
1. Vault connectivity and health
2. Secret rotation compliance
3. SOPS configuration validity
4. Repository structure

Usage:
    python3 team_health_check.py --team payments [--verbose]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# SDK imports
from secrets_sdk import VaultClient
from secrets_sdk.config import validate_sops_yaml
from secrets_sdk.rotation import RotationPolicy
from secrets_sdk.exceptions import SecretsSDKError


def check_vault_health(client: VaultClient) -> dict:
    """Check Vault connectivity and health."""
    try:
        health = client.health()
        return {
            "check": "vault_health",
            "status": "pass" if not health.get("sealed") else "fail",
            "details": {
                "version": health.get("version", "unknown"),
                "sealed": health.get("sealed", True),
                "initialized": health.get("initialized", False),
            },
        }
    except SecretsSDKError as e:
        return {
            "check": "vault_health",
            "status": "fail",
            "error": str(e),
        }


def check_sops_config(repo_root: Path) -> dict:
    """Validate .sops.yaml configuration."""
    sops_path = repo_root / ".sops.yaml"
    if not sops_path.exists():
        return {
            "check": "sops_config",
            "status": "fail",
            "error": ".sops.yaml not found",
        }

    issues = validate_sops_yaml(str(sops_path))
    return {
        "check": "sops_config",
        "status": "pass" if not issues else "warn",
        "issues": issues,
    }


def check_repo_structure(repo_root: Path) -> dict:
    """Validate repository structure."""
    required = [
        ".sops.yaml",
        ".pre-commit-config.yaml",
        "platform/vault/policies",
        "tools",
    ]
    missing = []
    for item in required:
        path = repo_root / item
        if not path.exists():
            missing.append(item)

    return {
        "check": "repo_structure",
        "status": "pass" if not missing else "warn",
        "missing": missing,
    }


def generate_report(team: str, checks: list[dict]) -> dict:
    """Generate a structured health check report."""
    overall = "pass"
    for check in checks:
        if check["status"] == "fail":
            overall = "fail"
            break
        if check["status"] == "warn" and overall != "fail":
            overall = "warn"

    return {
        "report": "team-health-check",
        "team": team,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall,
        "checks": checks,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Check a team's secrets management health"
    )
    parser.add_argument("--team", required=True, help="Team name")
    parser.add_argument("--repo-root", default=".", help="Repository root path")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    checks = []

    # Check 1: Vault health
    try:
        client = VaultClient()
        checks.append(check_vault_health(client))
    except Exception as e:
        checks.append({
            "check": "vault_health",
            "status": "fail",
            "error": str(e),
        })

    # Check 2: SOPS config
    checks.append(check_sops_config(repo_root))

    # Check 3: Repository structure
    checks.append(check_repo_structure(repo_root))

    # Generate report
    report = generate_report(args.team, checks)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\nTeam Health Check: {report['team']}")
        print(f"{'=' * 50}")
        print(f"Timestamp: {report['timestamp']}")
        print(f"Overall:   {report['overall_status'].upper()}")
        print()
        for check in report["checks"]:
            status = check["status"].upper()
            name = check["check"]
            print(f"  [{status:4s}] {name}")
            if args.verbose:
                for key, value in check.items():
                    if key not in ("check", "status"):
                        print(f"         {key}: {value}")
        print()

    # Exit code: 0 for pass, 1 for warn, 2 for fail
    if report["overall_status"] == "fail":
        sys.exit(2)
    elif report["overall_status"] == "warn":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
PYEOF

echo "Tool created at /tmp/workshop-tool/team_health_check.py"
```

### 4.2 Run the Tool

```bash
# Ensure the virtual environment is active
source /tmp/workshop-sdk-venv/bin/activate

# Run with text output
python3 /tmp/workshop-tool/team_health_check.py \
  --team payments \
  --repo-root /Users/$(whoami)/GitHub/dev-identity-secrets-reference \
  --verbose

# Run with JSON output
python3 /tmp/workshop-tool/team_health_check.py \
  --team payments \
  --repo-root /Users/$(whoami)/GitHub/dev-identity-secrets-reference \
  --json | jq .
```

### 4.3 Extend the Tool

Add a new check that verifies pre-commit hooks are installed:

```bash
python3 <<'PYEOF'
# Demonstrate extending the tool with a new check
from pathlib import Path

def check_precommit_hooks(repo_root: Path) -> dict:
    """Verify pre-commit hooks are installed."""
    hooks_dir = repo_root / ".git" / "hooks"
    pre_commit_hook = hooks_dir / "pre-commit"

    if not pre_commit_hook.exists():
        return {
            "check": "precommit_hooks",
            "status": "fail",
            "error": "pre-commit hooks not installed. Run: pre-commit install",
        }

    # Check if it is the pre-commit framework (not a custom script)
    content = pre_commit_hook.read_text()
    if "pre-commit" in content:
        return {
            "check": "precommit_hooks",
            "status": "pass",
            "details": "pre-commit framework hooks installed",
        }

    return {
        "check": "precommit_hooks",
        "status": "warn",
        "details": "Custom pre-commit hook found (not pre-commit framework)",
    }

repo_root = Path(".").resolve()
result = check_precommit_hooks(repo_root)
print(f"[{result['status'].upper()}] {result['check']}")
if "details" in result:
    print(f"  {result['details']}")
if "error" in result:
    print(f"  {result['error']}")
PYEOF
```

**Verification:**
- [ ] Created a custom CLI tool using the SDK
- [ ] Tool runs Vault health, SOPS config, and repo structure checks
- [ ] Tool produces both text and JSON output
- [ ] Extended the tool with a new pre-commit hook check
- [ ] Tool uses proper exit codes (0=pass, 1=warn, 2=fail)

---

## Lab 5: Contributing Back to the Repo (15 minutes)

### Concept

Contributing to the repository requires following project conventions: commit format, testing, linting, and pre-commit hooks. This lab walks through the contribution workflow.

### 5.1 Review Contributing Guidelines

```bash
head -80 CONTRIBUTING.md
```

Key requirements:
- All changes must pass `make validate` (scan + lint)
- Conventional commit messages: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`
- Pre-commit hooks must be installed
- Tests required for new functionality

### 5.2 Run the Test Suite

```bash
# Run Python SDK tests
make sdk-test 2>&1 | tail -20

# Run all validation checks
make validate 2>&1 | tail -20
```

### 5.3 Examine Existing Tests

```bash
# Look at how existing tests are structured
cat lib/python/tests/test_config.py | head -60
```

Key patterns:
- Tests use `pytest` with fixtures defined in `conftest.py`
- Vault-dependent tests mock the Vault client
- SOPS tests mock the `sops` CLI subprocess
- Config validation tests use temporary files

### 5.4 Write a Test for the Health Check Tool

```bash
cat > /tmp/workshop-tool/test_team_health_check.py <<'PYEOF'
"""Tests for team_health_check tool."""
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add the tool to path
import sys
sys.path.insert(0, "/tmp/workshop-tool")

from team_health_check import (
    check_vault_health,
    check_sops_config,
    check_repo_structure,
    generate_report,
)


class TestCheckVaultHealth:
    """Tests for Vault health check."""

    def test_healthy_vault(self):
        client = MagicMock()
        client.health.return_value = {
            "version": "1.15.0",
            "sealed": False,
            "initialized": True,
        }
        result = check_vault_health(client)
        assert result["status"] == "pass"
        assert result["details"]["version"] == "1.15.0"

    def test_sealed_vault(self):
        client = MagicMock()
        client.health.return_value = {
            "version": "1.15.0",
            "sealed": True,
            "initialized": True,
        }
        result = check_vault_health(client)
        assert result["status"] == "fail"


class TestCheckSopsConfig:
    """Tests for SOPS config validation."""

    def test_missing_sops_yaml(self, tmp_path):
        result = check_sops_config(tmp_path)
        assert result["status"] == "fail"
        assert ".sops.yaml not found" in result["error"]

    def test_valid_sops_yaml(self, tmp_path):
        sops_file = tmp_path / ".sops.yaml"
        sops_file.write_text("""
creation_rules:
  - path_regex: secrets/dev/.*\\.enc\\.(ya?ml|json)$
    age: 'age1test'
    encrypted_regex: '^(data|password)$'
""")
        result = check_sops_config(tmp_path)
        # Result depends on validation strictness
        assert result["status"] in ("pass", "warn")


class TestCheckRepoStructure:
    """Tests for repository structure validation."""

    def test_complete_structure(self, tmp_path):
        for item in [".sops.yaml", ".pre-commit-config.yaml"]:
            (tmp_path / item).touch()
        for item in ["platform/vault/policies", "tools"]:
            (tmp_path / item).mkdir(parents=True, exist_ok=True)
        result = check_repo_structure(tmp_path)
        assert result["status"] == "pass"

    def test_missing_items(self, tmp_path):
        result = check_repo_structure(tmp_path)
        assert result["status"] == "warn"
        assert len(result["missing"]) > 0


class TestGenerateReport:
    """Tests for report generation."""

    def test_all_pass(self):
        checks = [
            {"check": "a", "status": "pass"},
            {"check": "b", "status": "pass"},
        ]
        report = generate_report("test-team", checks)
        assert report["overall_status"] == "pass"

    def test_any_fail(self):
        checks = [
            {"check": "a", "status": "pass"},
            {"check": "b", "status": "fail"},
        ]
        report = generate_report("test-team", checks)
        assert report["overall_status"] == "fail"

    def test_warn_without_fail(self):
        checks = [
            {"check": "a", "status": "pass"},
            {"check": "b", "status": "warn"},
        ]
        report = generate_report("test-team", checks)
        assert report["overall_status"] == "warn"
PYEOF

# Run the tests
source /tmp/workshop-sdk-venv/bin/activate
pip install pytest >/dev/null 2>&1
python3 -m pytest /tmp/workshop-tool/test_team_health_check.py -v 2>&1
```

### 5.5 Contribution Workflow Summary

The standard contribution flow:

```bash
# 1. Create a feature branch
git checkout -b feat/team-health-check

# 2. Make your changes (copy the tool into the repo)
# cp /tmp/workshop-tool/team_health_check.py tools/team-health-check/
# cp /tmp/workshop-tool/test_team_health_check.py tests/unit/

# 3. Run validation
make validate

# 4. Run tests
make sdk-test

# 5. Commit with conventional message
# git add tools/team-health-check/ tests/unit/test_team_health_check.py
# git commit -m "feat: add team health check tool"

# 6. Push and create PR
# git push -u origin feat/team-health-check
# gh pr create --title "feat: add team health check tool" --body "..."
```

**Note:** Do not actually commit or push during the workshop unless working on a fork.

**Verification:**
- [ ] Reviewed the CONTRIBUTING.md guidelines
- [ ] Ran the existing test suite
- [ ] Wrote tests for the custom tool with mocked dependencies
- [ ] All tests pass
- [ ] Participant understands the branch-commit-PR workflow

---

## Cleanup

```bash
# Deactivate virtual environment
deactivate

# Remove workshop artifacts
rm -rf /tmp/workshop-sdk-venv /tmp/workshop-tool /tmp/workshop-sdk-sops

# Remove Vault workshop secrets
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
vault kv metadata delete secret/workshop/sdk-demo 2>/dev/null || true
vault kv metadata delete secret/workshop/rotation-test 2>/dev/null || true

# Or reset everything
make dev-reset
```

---

## Review Questions

1. **Why does the SDK use environment variables as the default configuration source?**
   Environment variables are the standard mechanism for runtime configuration in containers, CI pipelines, and local development. They avoid hardcoded values and work consistently across deployment environments. The SDK's resolution order (explicit parameter > env var > default) gives maximum flexibility.

2. **What is the advantage of the common interface pattern across Python, Go, and TypeScript SDKs?**
   Developers can switch languages without relearning the secrets API. Documentation and training apply to all three. Teams using multiple languages get consistent behavior. Bug fixes in one SDK often identify issues in the others.

3. **Why should rotation policies be defined in code rather than documentation?**
   Code-defined policies can be automatically checked. Documentation-defined policies require human compliance. The rotation module turns policy violations into measurable, alertable events rather than audit findings discovered months later.

4. **What makes a good custom security tool built on the SDK?**
   Single responsibility (one tool, one job). Structured output (JSON for automation, text for humans). Proper exit codes (0/1/2). Error handling that does not crash on expected failures. Tests with mocked external dependencies.

5. **Why does the project require pre-commit hooks for all contributions?**
   Pre-commit hooks enforce security controls at the earliest possible point: before secrets enter Git history. Once a secret is committed, even if later removed, it exists in the Git object database and potentially in remote backups. Prevention is the only reliable strategy.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: secrets_sdk` | Ensure the venv is activated and SDK is installed: `pip install -e lib/python/` |
| Vault connection refused | Ensure dev environment is running: `make dev-up` |
| `sops: command not found` | `brew install sops` or download from github.com/getsops/sops |
| Tests fail with import errors | Ensure you are in the correct venv: `which python3` should show the venv path |
| `pip install` fails | Check Python version: `python3 --version` (must be 3.10+) |
| Transit operations fail | Ensure Transit engine is enabled: `vault secrets list | grep transit` |

---

## Next Steps

- **Reference:** [SDK Design Guide](../23-sdk-design-guide.md) for the full interface contract
- **Reference:** [Contributing Guide](../../CONTRIBUTING.md) for the complete contribution process
- **Code:** `lib/python/`, `lib/go/`, `lib/typescript/` for all three SDK implementations
- **Tests:** `lib/python/tests/` for the full Python test suite
