#!/usr/bin/env bash
set -euo pipefail

# run_all.sh — Run all integration tests sequentially.
# Usage: ./run_all.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

PASS=0
FAIL=0

for test_script in "$SCRIPT_DIR"/test_*.sh; do
  [[ -f "$test_script" ]] || continue
  name="$(basename "$test_script")"
  printf '%b[*] Running %s...%b\n' "$GREEN" "$name" "$NC"
  if bash "$test_script"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    printf '%b[!] FAILED: %s%b\n' "$RED" "$name" "$NC"
  fi
done

echo ""
printf '%b[*] Integration tests complete: %d passed, %d failed%b\n' \
  "$GREEN" "$PASS" "$FAIL" "$NC"

[[ $FAIL -eq 0 ]] || exit 1
