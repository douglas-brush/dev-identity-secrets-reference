#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# vault-dev-proxy.sh — Local Vault agent proxy with auto-renewing tokens
#
# Starts a Vault agent in dev mode that:
#   - Auto-authenticates and renews tokens
#   - Templates secrets to a memory-backed tmpfs (Linux) or ramdisk (macOS)
#   - Cleans up all resources on exit
#
# Usage:
#   ./vault-dev-proxy.sh
#   ./vault-dev-proxy.sh --vault-addr http://127.0.0.1:8200
#   ./vault-dev-proxy.sh --template-dir ./templates
# =============================================================================

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

# --- Logging ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# --- Defaults ---
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
TEMPLATE_DIR=""
RAMDISK_PATH=""
RAMDISK_DEVICE=""
AGENT_PID=""
AGENT_CONFIG=""

usage() {
  cat >&2 <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Start a Vault agent in dev mode that auto-renews tokens and templates secrets
to a memory-backed filesystem. All secrets stay in RAM — nothing on disk.

Options:
  --vault-addr URL       Vault server address (default: \$VAULT_ADDR or http://127.0.0.1:8200)
  --template-dir DIR     Directory containing Vault agent template files (*.ctmpl)
                         If not set, a default template that exports KV secrets is used.
  --help                 Show this help message

Prerequisites:
  - vault CLI installed
  - Valid Vault token (run 'vault login' first)
  - jq installed

The agent runs in the foreground. Press Ctrl+C to stop.
All temporary files and ramdisks are cleaned up automatically on exit.
EOF
  exit "${1:-0}"
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-addr)
      VAULT_ADDR="$2"
      shift 2
      ;;
    --template-dir)
      TEMPLATE_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage 0
      ;;
    *)
      die "Unknown option: $1 (see --help)"
      ;;
  esac
done

export VAULT_ADDR

# --- Validation ---
for cmd in vault jq; do
  command -v "$cmd" &>/dev/null || die "$cmd is required but not found"
done

vault token lookup &>/dev/null 2>&1 || die "No valid Vault token. Run 'vault login' first."
ok "Vault connectivity verified ($VAULT_ADDR)"

# --- Cleanup Trap ---
# Ensures ramdisk is unmounted, agent is stopped, and temp files are removed
# regardless of how the script exits.
cleanup() {
  local exit_code=$?
  info "Cleaning up..."

  # Stop Vault agent
  if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    ok "Vault agent stopped (PID $AGENT_PID)"
  fi

  # Unmount and remove ramdisk
  if [[ -n "$RAMDISK_PATH" && -d "$RAMDISK_PATH" ]]; then
    case "$(uname -s)" in
      Darwin)
        if [[ -n "$RAMDISK_DEVICE" ]]; then
          umount "$RAMDISK_PATH" 2>/dev/null || true
          hdiutil detach "$RAMDISK_DEVICE" -quiet 2>/dev/null || true
          ok "macOS ramdisk detached ($RAMDISK_DEVICE)"
        fi
        rmdir "$RAMDISK_PATH" 2>/dev/null || true
        ;;
      Linux)
        umount "$RAMDISK_PATH" 2>/dev/null || true
        rmdir "$RAMDISK_PATH" 2>/dev/null || true
        ok "tmpfs unmounted ($RAMDISK_PATH)"
        ;;
    esac
  fi

  # Remove agent config
  if [[ -n "$AGENT_CONFIG" && -f "$AGENT_CONFIG" ]]; then
    rm -f "$AGENT_CONFIG"
  fi

  exit "$exit_code"
}
trap cleanup EXIT INT TERM HUP

# --- Create Memory-Backed Filesystem ---
# Secrets are templated here — they exist only in RAM.
create_ramdisk() {
  local size_mb=16

  case "$(uname -s)" in
    Darwin)
      # macOS: create a RAM disk using hdiutil
      RAMDISK_PATH=$(mktemp -d /tmp/vault-proxy-XXXXXX)
      local sectors=$((size_mb * 2048))  # 512-byte sectors
      RAMDISK_DEVICE=$(hdiutil attach -nomount "ram://${sectors}" 2>/dev/null)
      RAMDISK_DEVICE=$(echo "$RAMDISK_DEVICE" | xargs)  # trim whitespace
      newfs_hfs -M 700 "$RAMDISK_DEVICE" &>/dev/null || die "Failed to format ramdisk"
      mount -t hfs -o nobrowse "$RAMDISK_DEVICE" "$RAMDISK_PATH" || die "Failed to mount ramdisk"
      chmod 700 "$RAMDISK_PATH"
      ok "macOS ramdisk created at $RAMDISK_PATH (${size_mb}MB)"
      ;;
    Linux)
      # Linux: use tmpfs
      RAMDISK_PATH=$(mktemp -d /tmp/vault-proxy-XXXXXX)
      mount -t tmpfs -o size=${size_mb}m,mode=0700 tmpfs "$RAMDISK_PATH" 2>/dev/null || {
        # Fallback if not root: use regular tmpdir with restrictive permissions
        warn "Cannot mount tmpfs (not root) — using restricted temp directory"
        chmod 700 "$RAMDISK_PATH"
      }
      ok "Memory-backed directory at $RAMDISK_PATH"
      ;;
    *)
      die "Unsupported OS: $(uname -s)"
      ;;
  esac
}

create_ramdisk

# --- Generate Agent Configuration ---
generate_agent_config() {
  AGENT_CONFIG=$(mktemp /tmp/vault-agent-config-XXXXXX.hcl)

  # Build template stanzas
  local template_block=""
  if [[ -n "$TEMPLATE_DIR" && -d "$TEMPLATE_DIR" ]]; then
    for tmpl in "$TEMPLATE_DIR"/*.ctmpl; do
      [[ -f "$tmpl" ]] || continue
      local dest_name
      dest_name=$(basename "$tmpl" .ctmpl)
      template_block+="
template {
  source      = \"$tmpl\"
  destination = \"${RAMDISK_PATH}/${dest_name}\"
  perms       = \"0600\"
}
"
    done
  fi

  # Default template: export all KV secrets as env file
  if [[ -z "$template_block" ]]; then
    local default_tmpl="${RAMDISK_PATH}/_default.ctmpl"
    cat > "$default_tmpl" <<'TMPL'
{{ with secret "kv/data/dev/apps/default/config" }}
{{ range $k, $v := .Data.data }}
export {{ $k | toUpper }}={{ $v | toJSON }}
{{ end }}
{{ end }}
TMPL
    chmod 600 "$default_tmpl"

    template_block="
template {
  source      = \"${default_tmpl}\"
  destination = \"${RAMDISK_PATH}/secrets.env\"
  perms       = \"0600\"
}
"
  fi

  cat > "$AGENT_CONFIG" <<HCL
pid_file = "${RAMDISK_PATH}/agent.pid"

vault {
  address = "${VAULT_ADDR}"
}

auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/dev/stdin"
    }
  }

  sink "file" {
    config = {
      path = "${RAMDISK_PATH}/.vault-token"
      mode = 0600
    }
  }
}

cache {
  use_auto_auth_token = true
}

${template_block}
HCL

  chmod 600 "$AGENT_CONFIG"
  ok "Agent config written to $AGENT_CONFIG"
}

generate_agent_config

# --- Start Vault Agent ---
info "Starting Vault agent..."
info "  Vault:     $VAULT_ADDR"
info "  Secrets:   $RAMDISK_PATH/"
info "  Templates: ${TEMPLATE_DIR:-<default>}"
echo ""
info "Press Ctrl+C to stop. All secrets will be wiped from memory."
echo ""

# Run agent — feed token via environment, not file
vault agent -config="$AGENT_CONFIG" -log-level=info &
AGENT_PID=$!

ok "Vault agent started (PID $AGENT_PID)"
info "Secret files available at: $RAMDISK_PATH/"
info "  source ${RAMDISK_PATH}/secrets.env  # to load into shell"

# Wait for agent — cleanup trap handles shutdown
wait "$AGENT_PID" 2>/dev/null || true
