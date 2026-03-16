# Runbook Automation Engine

Generic YAML-driven runbook executor with sequential step execution, validation, rollback, and structured logging.

## Quick Start

```bash
# Dry run a runbook (shows what would execute)
./tools/runbooks/runbook-runner.sh runbooks/secret-rotation.yaml --dry-run

# Execute a runbook
./tools/runbooks/runbook-runner.sh runbooks/vault-unseal.yaml --verbose

# Start from a specific step
./tools/runbooks/runbook-runner.sh runbooks/cert-renewal.yaml --step 3

# No color output (for CI/logging)
./tools/runbooks/runbook-runner.sh runbooks/onboard-service.yaml --no-color
```

## Runbook Format

Runbooks are YAML files with the following structure:

```yaml
name: "Runbook Name"
description: "What this runbook does"
version: "1.0.0"
requires:       # optional — CLI tools that must be available
  - vault
  - jq
env:            # optional — environment variables that must be set
  - VAULT_ADDR
  - VAULT_TOKEN

steps:
  - name: "Step description"
    command: "shell command to execute"
    validate: "command returning 0 on success"    # optional
    rollback: "command to undo this step"          # optional
    continue_on_fail: false                        # optional (default: false)
    timeout: 30                                    # optional (default: 300s)
```

### Step Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Human-readable step description |
| `command` | yes | Shell command to execute |
| `validate` | no | Post-execution validation (exit 0 = pass) |
| `rollback` | no | Undo command, run in reverse on failure |
| `continue_on_fail` | no | If `true`, proceed despite step failure |
| `timeout` | no | Max execution time in seconds (default: 300) |

## Available Runbooks

| Runbook | Description | Required Env |
|---------|-------------|--------------|
| `secret-rotation.yaml` | Full secret rotation — detect, rotate, verify, notify | `VAULT_ADDR`, `VAULT_TOKEN` |
| `vault-unseal.yaml` | Emergency Vault unseal procedure | `VAULT_ADDR` |
| `cert-renewal.yaml` | Certificate renewal — scan, issue, deploy, verify | `VAULT_ADDR`, `VAULT_TOKEN` |
| `incident-response.yaml` | IR kickoff — SIRM init, evidence, timeline | (none) |
| `onboard-service.yaml` | New service onboarding with Vault | `VAULT_ADDR`, `VAULT_TOKEN`, `SERVICE_NAME` |

## Execution Behavior

1. **Dependency check** — verifies all `requires` tools are installed
2. **Environment check** — verifies all `env` variables are set
3. **Sequential execution** — steps run in order from `--step N` (default: 1)
4. **Validation** — post-execution validation runs after each step
5. **Failure handling** — on failure, completed steps are rolled back in reverse order
6. **Logging** — all output written to `logs/runbooks/<runbook>-<run-id>.log`
7. **JSON summary** — structured output written to `logs/runbooks/<runbook>-<run-id>.json`

## CLI Options

```
--dry-run       Show commands without executing
--step N        Start from step N (1-indexed, skips earlier steps)
--verbose       Show detailed execution output and debug logs
--no-color      Disable colored terminal output
-h, --help      Show usage help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All steps passed |
| 1 | One or more steps failed |
| 2 | Usage error or missing dependencies |

## Environment Overrides

| Variable | Description |
|----------|-------------|
| `RUNBOOK_LOG_DIR` | Override default log directory (`logs/runbooks/`) |
| `NO_COLOR` | Disable colored output |

## Writing Custom Runbooks

Create a new YAML file in `runbooks/` following the format above. Tips:

- Use `continue_on_fail: true` for non-critical steps (notifications, cleanup)
- Always define `rollback` for steps that mutate state
- Use `validate` to confirm step success beyond exit code
- Set `timeout` for commands that may hang (network calls, key generation)
- Commands run in `bash -c`, so pipes and subshells work

## Output

Each run produces two artifacts in `logs/runbooks/`:

- **Log file** (`<runbook>-<run-id>.log`) — timestamped execution log
- **JSON summary** (`<runbook>-<run-id>.json`) — structured results:

```json
{
  "run_id": "20260316-143022-12345",
  "runbook": "Secret Rotation",
  "status": "success",
  "total_steps": 8,
  "passed": 8,
  "failed": 0,
  "skipped": 0,
  "steps": [...]
}
```
