#!/usr/bin/env bash
# basic-session.sh — End-to-end example of a basic SIRM session
#
# Demonstrates the full session lifecycle:
#   Bootstrap → Register evidence → Add timeline events → Generate report → Seal
#
# This is a routine session (scheduled audit, health check review).
# For incident response sessions, see incident-response-session.sh.
#
# Prerequisites:
#   - tools/sirm/sirm.sh must be available
#   - Required tools: openssl, jq, sha256sum (or shasum on macOS)
#
# Usage:
#   ./examples/sirm/basic-session.sh
#
# Environment:
#   SIRM_CASE_ID          - Case identifier (default: auto-generated)
#   SIRM_CLASSIFICATION   - Session classification (default: routine)
#   VAULT_ADDR            - Vault server URL (optional, for Vault health checks)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIRM="${REPO_ROOT}/tools/sirm/sirm.sh"

# ── Configuration ────────────────────────────────────────────────────────────

# Case ID: use provided value or generate one with today's date
CASE_ID="${SIRM_CASE_ID:-CASE-$(date -u +%Y)-$(date -u +%s | tail -c 4)}"
CLASSIFICATION="${SIRM_CLASSIFICATION:-routine}"
OPERATOR="$(whoami)"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  SIRM Basic Session Example                             ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Case ID:        ${CASE_ID}"
echo "║  Classification: ${CLASSIFICATION}"
echo "║  Operator:       ${OPERATOR}"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Phase 1: Bootstrap ──────────────────────────────────────────────────────
# Bootstrap validates the environment, captures context, and transitions
# the session from NOT_STARTED → BOOTSTRAPPING → ACTIVE.
# All 5 phases must pass: operator auth, env validation, repo state,
# infrastructure health, and context snapshot.

echo "[1/5] Bootstrapping session..."
export SIRM_CASE_ID="${CASE_ID}"
export SIRM_CLASSIFICATION="${CLASSIFICATION}"
export SIRM_OPERATOR="${OPERATOR}"

${SIRM} bootstrap
echo "      Session bootstrapped — state is now ACTIVE"
echo ""

# ── Phase 2: Register Evidence ──────────────────────────────────────────────
# Run tools and register their output as evidence artifacts.
# Each registration captures the output, computes SHA-256, copies to the
# session evidence directory, and appends to the evidence manifest.

echo "[2/5] Registering evidence..."

# Run secrets-doctor and capture output as evidence
# This checks SOPS config, Vault connectivity, git hooks, dependencies
${SIRM} run secrets-doctor
echo "      Registered: secrets-doctor output"

# Run identity inventory to catalog non-human identities
# Captures service accounts, API keys, bot accounts
${SIRM} run identity-inventory
echo "      Registered: identity inventory"

echo ""

# ── Phase 3: Add Timeline Events ───────────────────────────────────────────
# Add classified findings to the timeline. Each entry carries:
#   - Classification: F (fact), O (observation), I (inference), H (hypothesis)
#   - Confidence: weak, moderate, strong, dominant
# Only F and O entries with strong/dominant confidence become report findings.

echo "[3/5] Adding timeline events..."

# Record a factual finding (something directly verified)
${SIRM} add-finding \
  --classification F \
  --confidence dominant \
  --summary "All SOPS-encrypted files pass decryption test" \
  --detail "secrets-doctor verified 12 encrypted files across dev/staging/prod environments. All decrypt successfully with current KMS keys." \
  --evidence-refs "001" \
  --tags "sops,encryption,healthy"

# Record an observation (something noted but not yet fully investigated)
${SIRM} add-finding \
  --classification O \
  --confidence strong \
  --summary "3 service accounts created >365 days ago with no rotation record" \
  --detail "Identity inventory shows 3 NHIs with creation dates older than 1 year. No rotation events found in audit logs." \
  --evidence-refs "002" \
  --tags "nhi,rotation,review-needed"

echo "      Added 2 timeline entries"
echo ""

# ── Phase 4: Generate Report ───────────────────────────────────────────────
# Report generation aggregates all findings, evidence, and timeline entries
# into the standard format: executive summary → findings → recommendations.
# The report is written to session/<case-id>/report.md.

echo "[4/5] Generating report..."
${SIRM} report
echo "      Report generated"
echo ""

# ── Phase 5: Seal Session ──────────────────────────────────────────────────
# Sealing is irreversible. It:
#   1. Re-verifies all evidence hashes
#   2. Checks timeline integrity
#   3. Generates a Merkle-style root hash
#   4. Writes seal.json
# After sealing, any modification to any session file is detectable.

echo "[5/5] Sealing session..."
${SIRM} seal
echo "      Session sealed — tamper-evident package complete"
echo ""

# ── Verify ──────────────────────────────────────────────────────────────────
# Demonstrate independent verification of the sealed session.

echo "Verifying seal..."
${SIRM} verify-seal "sessions/${CASE_ID}/"
echo ""

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Session Complete                                       ║"
echo "║  Case:   ${CASE_ID}"
echo "║  State:  SEALED                                         ║"
echo "║  Report: sessions/${CASE_ID}/report.md"
echo "║  Seal:   sessions/${CASE_ID}/seal.json"
echo "╚══════════════════════════════════════════════════════════╝"
