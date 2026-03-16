#!/usr/bin/env bash
set -euo pipefail

# generate-report.sh — Generate human-readable report from secrets lifecycle metrics JSON
# Reads metrics JSON (from collect-metrics.sh), calculates risk score, and produces
# a formatted report with executive summary, section breakdowns, and action items.
# Usage: generate-report.sh --input <metrics.json> [--format terminal|markdown|json] [--verbose]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"; export REPO_ROOT
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; export TIMESTAMP

# ── Defaults ──────────────────────────────────────────────────────────────

INPUT_FILE=""
OUTPUT_FORMAT="terminal"
VERBOSE=""

# ── Color ─────────────────────────────────────────────────────────────────

_red()    { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;31m%s\033[0m' "$1"; }
_green()  { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;32m%s\033[0m' "$1"; }
_yellow() { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;33m%s\033[0m' "$1"; }
_blue()   { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[0;34m%s\033[0m' "$1"; }
_bold()   { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[1m%s\033[0m' "$1"; }
_dim()    { [[ -n "${NO_COLOR:-}" ]] && printf '%s' "$1" || printf '\033[2m%s\033[0m' "$1"; }

# ── Help ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$(_bold 'generate-report.sh') — Secrets lifecycle report generator

$(_bold 'USAGE')
  generate-report.sh --input <metrics.json> [OPTIONS]

$(_bold 'OPTIONS')
  --input <file>               Metrics JSON from collect-metrics.sh (required)
  --format terminal|markdown|json   Output format (default: terminal)
  --verbose                    Include per-check details in report
  --no-color                   Disable colored output (terminal format)
  -h, --help                   Show this help

$(_bold 'REPORT SECTIONS')
  1. Executive Summary — composite risk score, rating, one-line assessment
  2. Secrets Hygiene — secrets-doctor pass/warn/fail breakdown
  3. Certificate Health — cert inventory status table
  4. Credential Age — rotation compliance status
  5. Policy Compliance — control matrix pass rates by framework
  6. Secret Scanning — scanner results summary
  7. Trends — comparison against baseline (if available)
  8. Top 5 Action Items — prioritized by risk impact

$(_bold 'EXIT CODES')
  0   Report generated successfully
  2   Usage error or missing input

$(_bold 'EXAMPLES')
  generate-report.sh --input logs/metrics/metrics-latest.json
  generate-report.sh --input metrics.json --format markdown > report.md
  generate-report.sh --input metrics.json --format json | jq .
EOF
  exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    --input)      INPUT_FILE="$2"; shift 2 ;;
    --format)     OUTPUT_FORMAT="$2"; shift 2 ;;
    --verbose)    VERBOSE=1; shift ;;
    --no-color)   NO_COLOR=1; shift ;;
    *)
      printf 'Error: unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$INPUT_FILE" ]]; then
  printf 'Error: --input is required\n' >&2
  exit 2
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  printf 'Error: input file not found: %s\n' "$INPUT_FILE" >&2
  exit 2
fi

case "$OUTPUT_FORMAT" in
  terminal|markdown|json) ;;
  *)
    printf 'Error: invalid format: %s (use terminal, markdown, or json)\n' "$OUTPUT_FORMAT" >&2
    exit 2
    ;;
esac

# ── Generate report via Python ────────────────────────────────────────────

# Get the risk score first
RISK_JSON=$("${SCRIPT_DIR}/risk-scorer.sh" --input "$INPUT_FILE" --json 2>/dev/null || echo '{"risk_score":0,"rating":"UNKNOWN","categories":{}}')

# Main report generation
python3 << 'PYTHON_REPORT' - "$INPUT_FILE" "$OUTPUT_FORMAT" "$VERBOSE" "$RISK_JSON"
import json, sys

input_file = sys.argv[1]
output_format = sys.argv[2]
verbose = sys.argv[3] == "1"
risk_json = json.loads(sys.argv[4])

with open(input_file) as f:
    metrics = json.load(f)

sections = metrics.get("sections", {})
trends = metrics.get("trends", {})
timestamp = metrics.get("timestamp", "unknown")
risk_score = risk_json.get("risk_score", 0)
rating = risk_json.get("rating", "UNKNOWN")
categories = risk_json.get("categories", {})

# ── Trend indicator ──
def trend_icon(trend_str, fmt):
    if fmt == "terminal":
        icons = {"improving": "\033[0;32m\u2191\033[0m", "degrading": "\033[0;31m\u2193\033[0m", "stable": "\u2192", "new": "\u2022"}
    elif fmt == "markdown":
        icons = {"improving": ":arrow_up:", "degrading": ":arrow_down:", "stable": ":arrow_right:", "new": ":new:"}
    else:
        icons = {"improving": "UP", "degrading": "DOWN", "stable": "STABLE", "new": "NEW"}
    return icons.get(trend_str, "")

# ── Action items ──
action_items = []

# From secrets_doctor
doctor = sections.get("secrets_doctor", {})
doc_summary = doctor.get("summary", {})
if int(doc_summary.get("failed", 0)) > 0:
    action_items.append({
        "priority": 1,
        "category": "secrets_hygiene",
        "action": f"Fix {doc_summary['failed']} failing secrets-doctor check(s)",
        "impact": "HIGH",
    })
if int(doc_summary.get("warnings", 0)) > 0:
    action_items.append({
        "priority": 3,
        "category": "secrets_hygiene",
        "action": f"Address {doc_summary['warnings']} secrets-doctor warning(s)",
        "impact": "MEDIUM",
    })

# From certs
certs = sections.get("cert_inventory", {})
cert_list = certs.get("certificates", [])
expired = [c for c in cert_list if c.get("status") == "EXPIRED"]
expiring = [c for c in cert_list if c.get("status") == "EXPIRING_SOON"]
weak = [c for c in cert_list if c.get("status") == "WEAK_KEY"]

if expired:
    action_items.append({
        "priority": 1,
        "category": "cert_health",
        "action": f"Renew {len(expired)} expired certificate(s) immediately",
        "impact": "CRITICAL",
    })
if expiring:
    action_items.append({
        "priority": 2,
        "category": "cert_health",
        "action": f"Plan renewal for {len(expiring)} certificate(s) expiring soon",
        "impact": "HIGH",
    })
if weak:
    action_items.append({
        "priority": 2,
        "category": "cert_health",
        "action": f"Re-issue {len(weak)} certificate(s) with weak keys",
        "impact": "HIGH",
    })

# From credential age
creds = sections.get("credential_age", {})
cred_list = creds.get("credentials", [])
cred_fail = [c for c in cred_list if c.get("status") == "FAIL"]
if cred_fail:
    action_items.append({
        "priority": 1,
        "category": "credential_age",
        "action": f"Rotate {len(cred_fail)} credential(s) exceeding max age policy",
        "impact": "HIGH",
    })

# From control matrix
matrix = sections.get("control_matrix", {})
mx_summary = matrix.get("summary", {})
if int(mx_summary.get("fail", 0)) > 0:
    action_items.append({
        "priority": 2,
        "category": "policy_compliance",
        "action": f"Remediate {mx_summary['fail']} failing compliance control(s)",
        "impact": "HIGH",
    })
if int(mx_summary.get("manual", 0)) > 0:
    action_items.append({
        "priority": 4,
        "category": "policy_compliance",
        "action": f"Complete manual verification for {mx_summary['manual']} control(s)",
        "impact": "MEDIUM",
    })

# From scanning
scanning = sections.get("scanning", {})
scanners = scanning.get("scanners", [])
total_findings = sum(int(s.get("finding_count", 0)) for s in scanners if s.get("status") == "completed")
if total_findings > 0:
    action_items.append({
        "priority": 1,
        "category": "scanning",
        "action": f"Investigate and remediate {total_findings} secret scanning finding(s)",
        "impact": "CRITICAL",
    })

# Sort by priority, take top 5
action_items.sort(key=lambda x: x["priority"])
top_actions = action_items[:5]

# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════

if output_format == "json":
    report = {
        "report": "secret_lifecycle_report",
        "generated_at": timestamp,
        "risk_score": risk_score,
        "rating": rating,
        "categories": categories,
        "action_items": top_actions,
        "sections": {
            "secrets_doctor": doc_summary,
            "cert_inventory": {
                "total": len(cert_list),
                "expired": len(expired),
                "expiring_soon": len(expiring),
                "weak_key": len(weak),
                "ok": len(cert_list) - len(expired) - len(expiring) - len(weak),
            },
            "credential_age": {
                "total": len(cred_list),
                "compliant": len([c for c in cred_list if c.get("status") == "OK"]),
                "warning": len([c for c in cred_list if c.get("status") == "WARN"]),
                "non_compliant": len(cred_fail),
            },
            "control_matrix": mx_summary,
            "scanning": {
                "total_findings": total_findings,
                "scanners_run": len([s for s in scanners if s.get("status") == "completed"]),
            },
        },
        "trends": trends,
    }
    print(json.dumps(report, indent=2))

elif output_format == "markdown":
    print(f"# Secret Lifecycle Report")
    print(f"")
    print(f"**Generated:** {timestamp}")
    print(f"")
    print(f"## Executive Summary")
    print(f"")
    print(f"| Metric | Value |")
    print(f"|--------|-------|")
    print(f"| Risk Score | **{risk_score}/100** |")
    print(f"| Rating | **{rating}** |")
    print(f"")

    # Category table
    print(f"### Category Breakdown")
    print(f"")
    print(f"| Category | Weight | Score | Contribution |")
    print(f"|----------|--------|-------|--------------|")
    for cat_name in ["secrets_hygiene", "cert_health", "credential_age", "policy_compliance", "scanning"]:
        c = categories.get(cat_name, {})
        w = c.get("weight", 0)
        s = c.get("score", 0)
        contrib = c.get("weighted_contribution", 0)
        print(f"| {cat_name} | {w:.2f} | {s} | {contrib} |")
    print(f"")

    # Secrets Doctor
    print(f"## Secrets Hygiene")
    print(f"")
    print(f"| Check | Count |")
    print(f"|-------|-------|")
    print(f"| Passed | {doc_summary.get('passed', 0)} |")
    print(f"| Warnings | {doc_summary.get('warnings', 0)} |")
    print(f"| Failed | {doc_summary.get('failed', 0)} |")
    print(f"| Skipped | {doc_summary.get('skipped', 0)} |")
    print(f"")

    # Certificates
    print(f"## Certificate Health")
    print(f"")
    print(f"| Status | Count |")
    print(f"|--------|-------|")
    print(f"| OK | {len(cert_list) - len(expired) - len(expiring) - len(weak)} |")
    print(f"| Expiring Soon | {len(expiring)} |")
    print(f"| Weak Key | {len(weak)} |")
    print(f"| Expired | {len(expired)} |")
    print(f"| **Total** | **{len(cert_list)}** |")
    print(f"")

    # Credentials
    print(f"## Credential Age Compliance")
    print(f"")
    cred_ok = len([c for c in cred_list if c.get("status") == "OK"])
    cred_warn = len([c for c in cred_list if c.get("status") == "WARN"])
    print(f"| Status | Count |")
    print(f"|--------|-------|")
    print(f"| Compliant | {cred_ok} |")
    print(f"| Warning | {cred_warn} |")
    print(f"| Non-compliant | {len(cred_fail)} |")
    print(f"| **Total** | **{len(cred_list)}** |")
    print(f"")

    # Compliance
    print(f"## Policy Compliance")
    print(f"")
    print(f"| Status | Count |")
    print(f"|--------|-------|")
    print(f"| Pass | {mx_summary.get('pass', 0)} |")
    print(f"| Fail | {mx_summary.get('fail', 0)} |")
    print(f"| Manual | {mx_summary.get('manual', 0)} |")
    print(f"| N/A | {mx_summary.get('not_applicable', 0)} |")
    print(f"")

    # Scanning
    print(f"## Secret Scanning")
    print(f"")
    scanners_run = len([s for s in scanners if s.get("status") == "completed"])
    print(f"| Metric | Value |")
    print(f"|--------|-------|")
    print(f"| Scanners run | {scanners_run} |")
    print(f"| Total findings | {total_findings} |")
    print(f"")

    # Trends
    if trends and any(trends.values()):
        print(f"## Trends")
        print(f"")
        print(f"| Category | Metric | Previous | Current | Trend |")
        print(f"|----------|--------|----------|---------|-------|")
        for section_name, section_trends in trends.items():
            if isinstance(section_trends, dict):
                for metric_name, metric_data in section_trends.items():
                    if isinstance(metric_data, dict) and "trend" in metric_data:
                        t = metric_data["trend"]
                        icon = trend_icon(t, "markdown")
                        print(f"| {section_name} | {metric_name} | {metric_data.get('previous', '-')} | {metric_data.get('current', '-')} | {icon} {t} |")
        print(f"")

    # Action items
    if top_actions:
        print(f"## Top Action Items")
        print(f"")
        print(f"| # | Priority | Category | Action | Impact |")
        print(f"|---|----------|----------|--------|--------|")
        for i, item in enumerate(top_actions, 1):
            print(f"| {i} | P{item['priority']} | {item['category']} | {item['action']} | {item['impact']} |")
        print(f"")

    print(f"---")
    print(f"_Generated by `generate-report.sh` from `{input_file}`_")

elif output_format == "terminal":
    # Terminal output with ANSI
    B = "\033[1m"
    R = "\033[0m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    DIM = "\033[2m"

    # Score color
    if risk_score >= 70:
        sc = GREEN
    elif risk_score >= 50:
        sc = YELLOW
    else:
        sc = RED

    print(f"")
    print(f"{B}{'='*70}{R}")
    print(f"{B}         SECRET LIFECYCLE REPORT{R}")
    print(f"{B}{'='*70}{R}")
    print(f"  Generated: {timestamp}")
    print(f"")

    # Executive summary
    print(f"{B}--- Executive Summary ---{R}")
    print(f"")
    print(f"  Risk Score:  {sc}{risk_score}/100{R}  ({rating})")
    print(f"")

    # Progress bar
    bar_w = 50
    filled = risk_score * bar_w // 100
    empty = bar_w - filled
    bar = f"  [{sc}{'#' * filled}{R}{'.' * empty}]"
    print(bar)
    print(f"")

    # Category breakdown table
    print(f"  {'Category':<24} {'Weight':<8} {'Score':<8} {'Contribution':<14}")
    print(f"  {'─'*24} {'─'*6}   {'─'*6}   {'─'*12}")
    for cat_name in ["secrets_hygiene", "cert_health", "credential_age", "policy_compliance", "scanning"]:
        c = categories.get(cat_name, {})
        w = c.get("weight", 0)
        s = c.get("score", 0)
        contrib = c.get("weighted_contribution", 0)
        if s >= 70:
            scolor = GREEN
        elif s >= 50:
            scolor = YELLOW
        else:
            scolor = RED
        print(f"  {cat_name:<24} {w:<8.2f} {scolor}{s:<8}{R} {contrib:<14.1f}")
    print(f"")

    # Secrets Doctor
    print(f"{B}--- Secrets Hygiene ---{R}")
    print(f"")
    print(f"  {GREEN}Passed:{R}   {doc_summary.get('passed', 0)}")
    print(f"  {YELLOW}Warnings:{R} {doc_summary.get('warnings', 0)}")
    print(f"  {RED}Failed:{R}   {doc_summary.get('failed', 0)}")
    print(f"  {DIM}Skipped:{R}  {doc_summary.get('skipped', 0)}")
    print(f"")

    # Certs
    print(f"{B}--- Certificate Health ---{R}")
    print(f"")
    cert_ok = len(cert_list) - len(expired) - len(expiring) - len(weak)
    print(f"  {'Status':<16} {'Count':<8}")
    print(f"  {'─'*16} {'─'*6}")
    print(f"  {GREEN}{'OK':<16}{R} {cert_ok}")
    print(f"  {YELLOW}{'Expiring Soon':<16}{R} {len(expiring)}")
    print(f"  {RED}{'Weak Key':<16}{R} {len(weak)}")
    print(f"  {RED}{'Expired':<16}{R} {len(expired)}")
    print(f"  {'─'*24}")
    print(f"  {'Total':<16} {len(cert_list)}")
    print(f"")

    # Credentials
    print(f"{B}--- Credential Age ---{R}")
    print(f"")
    cred_ok = len([c for c in cred_list if c.get("status") == "OK"])
    cred_warn = len([c for c in cred_list if c.get("status") == "WARN"])
    print(f"  {GREEN}Compliant:{R}      {cred_ok}")
    print(f"  {YELLOW}Warning:{R}        {cred_warn}")
    print(f"  {RED}Non-compliant:{R}  {len(cred_fail)}")
    print(f"  Total:          {len(cred_list)}")
    print(f"")

    # Compliance
    print(f"{B}--- Policy Compliance ---{R}")
    print(f"")
    print(f"  {GREEN}Pass:{R}    {mx_summary.get('pass', 0)}")
    print(f"  {RED}Fail:{R}    {mx_summary.get('fail', 0)}")
    print(f"  {YELLOW}Manual:{R}  {mx_summary.get('manual', 0)}")
    print(f"  {DIM}N/A:{R}     {mx_summary.get('not_applicable', 0)}")
    print(f"")

    # Scanning
    print(f"{B}--- Secret Scanning ---{R}")
    print(f"")
    scanners_run = len([s for s in scanners if s.get("status") == "completed"])
    print(f"  Scanners run:    {scanners_run}")
    print(f"  Total findings:  ", end="")
    if total_findings == 0:
        print(f"{GREEN}0{R}")
    else:
        print(f"{RED}{total_findings}{R}")
    print(f"")

    # Trends
    if trends and any(v for v in trends.values() if v):
        print(f"{B}--- Trends ---{R}")
        print(f"")
        print(f"  {'Category':<20} {'Metric':<12} {'Prev':<8} {'Curr':<8} {'Trend':<12}")
        print(f"  {'─'*20} {'─'*10}   {'─'*6}   {'─'*6}   {'─'*10}")
        for section_name, section_trends in trends.items():
            if isinstance(section_trends, dict):
                for metric_name, metric_data in section_trends.items():
                    if isinstance(metric_data, dict) and "trend" in metric_data:
                        t = metric_data["trend"]
                        icon = trend_icon(t, "terminal")
                        prev = metric_data.get("previous", "-")
                        curr = metric_data.get("current", "-")
                        print(f"  {section_name:<20} {metric_name:<12} {str(prev):<8} {str(curr):<8} {icon} {t}")
        print(f"")

    # Action items
    if top_actions:
        print(f"{B}--- Top 5 Action Items ---{R}")
        print(f"")
        for i, item in enumerate(top_actions, 1):
            if item["impact"] == "CRITICAL":
                ic = RED
            elif item["impact"] == "HIGH":
                ic = YELLOW
            else:
                ic = DIM
            print(f"  {i}. [{ic}{item['impact']}{R}] {item['action']}")
            print(f"     Category: {item['category']}")
        print(f"")

    print(f"{B}{'='*70}{R}")
    print(f"  Report generated from: {input_file}")
    print(f"{B}{'='*70}{R}")
    print(f"")
PYTHON_REPORT
