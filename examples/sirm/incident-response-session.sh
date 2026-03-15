#!/usr/bin/env bash
# incident-response-session.sh — Full incident response SIRM session
#
# Demonstrates a comprehensive IR session with:
#   - Bootstrap with case ID and elevated classification
#   - Git log import to timeline for commit-level analysis
#   - Tool execution with output registered as evidence
#   - Manual findings with confidence ratings (F/O/I/H)
#   - Context snapshots at key investigation milestones
#   - Comprehensive report generation
#   - Session close and seal with tamper-evident packaging
#
# Scenario: Suspected credential exposure in CI pipeline.
# A GitHub Actions workflow log showed a Vault token in plaintext output.
# This session investigates scope of exposure and captures evidence.
#
# Prerequisites:
#   - tools/sirm/sirm.sh must be available
#   - Required tools: openssl, jq, sha256sum, vault (for Vault checks)
#   - VAULT_ADDR set if Vault health checks are desired
#
# Usage:
#   SIRM_CASE_ID="CASE-2026-042" ./examples/sirm/incident-response-session.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIRM="${REPO_ROOT}/tools/sirm/sirm.sh"

# ── Configuration ────────────────────────────────────────────────────────────

CASE_ID="${SIRM_CASE_ID:-CASE-2026-042}"
CLASSIFICATION="${SIRM_CLASSIFICATION:-critical}"
OPERATOR="$(whoami)"
INCIDENT_DATE="${SIRM_INCIDENT_DATE:-$(date -u +%Y-%m-%d)}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SIRM Incident Response Session                             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Case ID:        ${CASE_ID}"
echo "║  Classification: ${CLASSIFICATION}"
echo "║  Operator:       ${OPERATOR}"
echo "║  Incident Date:  ${INCIDENT_DATE}"
echo "║  Scenario:       Suspected credential exposure in CI        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: BOOTSTRAP
# ═══════════════════════════════════════════════════════════════════════════
# Bootstrap with critical classification triggers full ceremony:
# all 5 phases validated, escalation notification logged.

echo "━━━ Phase 1: Bootstrap ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

export SIRM_CASE_ID="${CASE_ID}"
export SIRM_CLASSIFICATION="${CLASSIFICATION}"
export SIRM_OPERATOR="${OPERATOR}"

${SIRM} bootstrap
echo "[OK] Session bootstrapped — ACTIVE"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: IMPORT GIT HISTORY
# ═══════════════════════════════════════════════════════════════════════════
# Import recent git commits to the session timeline. This provides a
# commit-level audit trail showing what code changes occurred around
# the time of the incident. Each commit becomes a timeline event.

echo "━━━ Phase 2: Git History Import ━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Import commits from the past 30 days into the timeline
# Each commit is recorded with hash, author, timestamp, and message
${SIRM} import-git-log --since="30 days ago"
echo "[OK] Git history imported to timeline"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: AUTOMATED TOOL SCANS
# ═══════════════════════════════════════════════════════════════════════════
# Run the repository's diagnostic and scanning tools. Each tool's output
# is captured, hashed, and registered as a numbered evidence artifact.

echo "━━━ Phase 3: Automated Scans ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Full secrets-doctor diagnostic — checks SOPS, Vault, git hooks, deps
echo "[*] Running secrets-doctor..."
${SIRM} run secrets-doctor
echo "    Evidence registered: secrets-doctor output"

# Identity inventory — catalogs all non-human identities
# Critical for understanding blast radius of exposed credentials
echo "[*] Running identity inventory..."
${SIRM} run identity-inventory
echo "    Evidence registered: identity inventory"

# Credential age report — identifies stale or unrotated credentials
echo "[*] Running credential age report..."
${SIRM} run credential-age-report
echo "    Evidence registered: credential age report"

# Enhanced secret scanner — deep scan for exposed secrets in codebase
echo "[*] Running enhanced secret scan..."
${SIRM} run enhanced-scan
echo "    Evidence registered: enhanced scan results"

# Entropy analysis — detect high-entropy strings that may be secrets
echo "[*] Running entropy analysis..."
${SIRM} run entropy-check
echo "    Evidence registered: entropy analysis"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: MANUAL FINDINGS
# ═══════════════════════════════════════════════════════════════════════════
# Analyst records findings from manual investigation. Each finding is
# classified (F/O/I/H) with a confidence level.
#
# Classification:
#   F = Fact       — directly verified, increases evidentiary weight
#   O = Observation — noted from data, increases evidentiary weight
#   I = Inference   — logical deduction, conditional weight
#   H = Hypothesis  — theory to test, no weight until supported
#
# Confidence scale:
#   weak     (< 0.35)  — preliminary
#   moderate (0.35-0.65) — supported but alternatives exist
#   strong   (0.65-0.85) — dominant, tested against alternatives
#   dominant (> 0.85)   — corroborated across independent evidence

echo "━━━ Phase 4: Manual Findings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# FACT: Directly verified — the token was in the CI output
${SIRM} add-finding \
  --classification F \
  --confidence dominant \
  --summary "Vault root token exposed in GitHub Actions workflow log" \
  --detail "Workflow run #4271 in deploy-production.yml printed VAULT_TOKEN to stdout at step 'Configure Vault'. Token prefix: hvs.CAESIJx... Token type: root (confirmed via vault token lookup). Log is publicly accessible to repository collaborators." \
  --evidence-refs "001" \
  --tags "vault,ci,token-exposure,critical"
echo "    Finding: Vault root token in CI log [F/dominant]"

# FACT: Verified by checking the token's policy
${SIRM} add-finding \
  --classification F \
  --confidence dominant \
  --summary "Exposed token has full root policy — unlimited Vault access" \
  --detail "vault token lookup confirms the exposed token has root policy with no TTL. Token was created 2025-11-03T08:15:00Z. No accessor restrictions. Grants full read/write/delete/sudo across all Vault paths." \
  --evidence-refs "001,003" \
  --tags "vault,root-token,unlimited-access,critical"
echo "    Finding: Root token has unlimited access [F/dominant]"

# OBSERVATION: Noted from identity inventory data
${SIRM} add-finding \
  --classification O \
  --confidence strong \
  --summary "14 non-human identities share the same Vault auth method as the exposed token" \
  --detail "Identity inventory shows 14 service accounts using AppRole auth with the same mount point. If the root token was used to create these AppRole credentials, they may be compromised by extension." \
  --evidence-refs "002" \
  --tags "nhi,blast-radius,approle"
echo "    Finding: 14 NHIs potentially in blast radius [O/strong]"

# OBSERVATION: Credential age data reveals a pattern
${SIRM} add-finding \
  --classification O \
  --confidence strong \
  --summary "Root token has not been rotated in 498 days" \
  --detail "Credential age report shows the root token was created 2025-11-03 and never rotated. This exceeds the 90-day rotation policy by 408 days." \
  --evidence-refs "003" \
  --tags "rotation,policy-violation,root-token"
echo "    Finding: Token 498 days old, 408 days past policy [O/strong]"

# INFERENCE: Logical deduction from timeline correlation
${SIRM} add-finding \
  --classification I \
  --confidence moderate \
  --summary "Token likely first exposed during CI pipeline refactor on 2026-02-20" \
  --detail "Git log shows deploy-production.yml was modified on 2026-02-20 (commit a3f8c21) adding a debug step that echoes environment variables. The workflow has run 47 times since that commit. Each run potentially exposed the token." \
  --evidence-refs "001" \
  --tags "timeline,root-cause,ci-refactor"
echo "    Finding: Exposure likely started 2026-02-20 [I/moderate]"

# HYPOTHESIS: Theory requiring further investigation
${SIRM} add-finding \
  --classification H \
  --confidence weak \
  --summary "Potential unauthorized access to production secrets via exposed root token" \
  --detail "If an adversary obtained the root token from the workflow logs (accessible to all 23 repository collaborators), they could have read production secrets from Vault. Vault audit logs need to be examined for anomalous access patterns during the exposure window." \
  --tags "unauthorized-access,production,investigation-needed"
echo "    Finding: Possible unauthorized production access [H/weak]"

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: MID-SESSION CONTEXT SNAPSHOT
# ═══════════════════════════════════════════════════════════════════════════
# Capture the environment state at this point in the investigation.
# This provides a comparison point if remediation actions are taken.

echo "━━━ Phase 5: Context Snapshot ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

${SIRM} snapshot --reason "Pre-remediation state capture — all findings recorded"
echo "[OK] Context snapshot captured"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 6: GENERATE REPORT
# ═══════════════════════════════════════════════════════════════════════════
# Generate a comprehensive report from all session data.
# Format: executive summary → findings (by severity) → recommendations
# → evidence inventory → session metadata.

echo "━━━ Phase 6: Report Generation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

${SIRM} report
echo "[OK] Report generated: sessions/${CASE_ID}/report.md"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7: CLOSE AND SEAL
# ═══════════════════════════════════════════════════════════════════════════
# Close the session with a summary, then seal it for tamper-evidence.
# Sealing is irreversible — re-verifies all hashes, generates root hash,
# produces a self-contained evidentiary package.

echo "━━━ Phase 7: Close and Seal ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Close transitions ACTIVE → CLOSED
${SIRM} close \
  --summary "Critical: Vault root token exposed in CI logs for ~23 days. 14 NHIs potentially in blast radius. Token 498 days past rotation policy. Immediate rotation and audit log review required."
echo "[OK] Session closed"

# Seal transitions CLOSED → SEALED (irreversible)
${SIRM} seal
echo "[OK] Session sealed — tamper-evident package complete"
echo ""

# ── Verify seal integrity ───────────────────────────────────────────────────

echo "━━━ Seal Verification ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
${SIRM} verify-seal "sessions/${CASE_ID}/"
echo ""

# ── Summary ─────────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Incident Response Session Complete                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Case:     ${CASE_ID}"
echo "║  State:    SEALED                                           ║"
echo "║  Findings: 6 (2 F/dominant, 2 O/strong, 1 I/moderate, 1 H) ║"
echo "║  Evidence: 5 tool outputs + git log                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Artifacts:                                                 ║"
echo "║    sessions/${CASE_ID}/report.md      — Full report"
echo "║    sessions/${CASE_ID}/seal.json      — Seal manifest"
echo "║    sessions/${CASE_ID}/timeline.jsonl  — Event timeline"
echo "║    sessions/${CASE_ID}/evidence/       — All evidence"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next Steps:                                                ║"
echo "║    1. Rotate the exposed Vault root token immediately       ║"
echo "║    2. Audit Vault access logs for the exposure window       ║"
echo "║    3. Rotate all 14 AppRole credentials in blast radius     ║"
echo "║    4. Remove debug step from deploy-production.yml          ║"
echo "║    5. Review sealed session with security leadership        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
