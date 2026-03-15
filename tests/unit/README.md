# Unit Tests

BATS (Bash Automated Testing System) test suite for shell scripts in this repository.

## Prerequisites

Install BATS:

```bash
# macOS
brew install bats-core

# Linux (apt)
sudo apt-get install bats

# From source
git clone https://github.com/bats-core/bats-core.git
cd bats-core && sudo ./install.sh /usr/local
```

## Running Tests

Run all tests:

```bash
bats tests/unit/
```

Run a specific test file:

```bash
bats tests/unit/test_doctor.bats
bats tests/unit/test_onboard.bats
bats tests/unit/test_plaintext_scan.bats
```

Run with verbose output (TAP format):

```bash
bats --tap tests/unit/
```

## Test Files

| File | Tests |
|------|-------|
| `test_doctor.bats` | secrets-doctor CLI: help, flags, check modules, JSON output, skip mechanism |
| `test_onboard.bats` | onboard_app.sh: help, platform validation, policy generation, manifest output |
| `test_plaintext_scan.bats` | Secret scanner: AWS/GitHub/JWT/PEM detection, exclusions, JSON output |
| `helpers.bash` | Shared setup/teardown, assertion functions, temp directory management |

## Writing New Tests

Source the helpers file in your `.bats` file:

```bash
load helpers

setup() {
  common_setup
}

teardown() {
  common_teardown
}

@test "description of test" {
  run some_command --flag
  assert_success
  assert_output_contains "expected string"
}
```

Available helpers: `assert_success`, `assert_failure`, `assert_output_contains`,
`assert_output_not_contains`, `assert_file_exists`, `assert_file_contains`,
`require_command` (skips test if command missing).
