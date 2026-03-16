#!/usr/bin/env bash
set -euo pipefail

# setup-dev.sh — One-command developer environment setup
# Usage: ./scripts/setup-dev.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

pass=0
warn=0
fail=0

ok()   { echo -e "  ${GREEN}[ok]${NC} $1"; ((pass++)); }
skip() { echo -e "  ${YELLOW}[skip]${NC} $1"; ((warn++)); }
err()  { echo -e "  ${RED}[miss]${NC} $1"; ((fail++)); }

check_cmd() {
    if command -v "$1" &>/dev/null; then
        ok "$1 $(command -v "$1")"
        return 0
    else
        err "$1 — not found"
        return 1
    fi
}

echo "=== Dev Identity & Secrets Reference — Dev Setup ==="
echo ""

# -------------------------------------------------------
# 1. Pre-commit hooks
# -------------------------------------------------------
echo "--- Pre-commit hooks ---"
if check_cmd pre-commit; then
    pre-commit install --install-hooks 2>/dev/null && ok "hooks installed" || skip "hook install failed (run manually)"
else
    skip "pre-commit not installed — run: pip install pre-commit"
fi
echo ""

# -------------------------------------------------------
# 2. Python venv + deps
# -------------------------------------------------------
echo "--- Python (lib/python) ---"
if check_cmd python3; then
    PYTHON_DIR="$REPO_ROOT/lib/python"
    VENV_DIR="$PYTHON_DIR/.venv"

    if [[ ! -d "$VENV_DIR" ]]; then
        echo "  Creating venv at $VENV_DIR..."
        python3 -m venv "$VENV_DIR"
        ok "venv created"
    else
        ok "venv exists"
    fi

    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    pip install --quiet --upgrade pip
    pip install --quiet -e "$PYTHON_DIR[dev]" && ok "python deps installed" || err "python dep install failed"
    deactivate
else
    err "python3 required for lib/python"
fi
echo ""

# -------------------------------------------------------
# 3. Go modules
# -------------------------------------------------------
echo "--- Go (lib/go) ---"
if check_cmd go; then
    (cd "$REPO_ROOT/lib/go" && go mod download) && ok "go mod download complete" || err "go mod download failed"
else
    err "go required for lib/go"
fi
echo ""

# -------------------------------------------------------
# 4. TypeScript / Node
# -------------------------------------------------------
echo "--- TypeScript (lib/typescript) ---"
if check_cmd node; then
    ok "node $(node --version)"
    if check_cmd npm; then
        (cd "$REPO_ROOT/lib/typescript" && npm ci --silent 2>/dev/null || npm install --silent) && ok "npm deps installed" || err "npm install failed"
    fi
else
    err "node required for lib/typescript"
fi
echo ""

# -------------------------------------------------------
# 5. Tool dependency checks
# -------------------------------------------------------
echo "--- Required tools ---"
check_cmd shellcheck || true
check_cmd bats      || true
check_cmd opa       || true
check_cmd sops      || true
check_cmd vault     || true
check_cmd jq        || true
check_cmd yq        || true
check_cmd age       || true
check_cmd gitleaks  || true
echo ""

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo "=== Setup Summary ==="
echo -e "  ${GREEN}Ready:${NC}   $pass"
echo -e "  ${YELLOW}Skipped:${NC} $warn"
echo -e "  ${RED}Missing:${NC} $fail"
echo ""

if [[ $fail -gt 0 ]]; then
    echo -e "${YELLOW}Some tools are missing. Install them to enable all pre-commit hooks and tests.${NC}"
    echo "  macOS:  brew install shellcheck bats-core opa sops age gitleaks hashicorp/tap/vault jq yq"
    echo "  Linux:  see project docs or install via package manager"
    exit 0
else
    echo -e "${GREEN}All tools ready. Run 'pre-commit run --all-files' to verify.${NC}"
fi
