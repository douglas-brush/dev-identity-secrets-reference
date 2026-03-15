#!/usr/bin/env bash

#!/usr/bin/env bash
# validate_reference.sh — Local validation harness for the Dev Identity & Secrets reference
#
# Validates all configuration files, policies, scripts, and documentation
# without requiring any infrastructure (Vault, Kubernetes, etc.).
#
# Usage: ./tests/e2e/validate_reference.sh [--report FILE] [--strict] [--help]
#
# Exit codes:
#   0 — All checks passed
#   1 — One or more checks failed
#   2 — Usage error

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPORT_FILE=""
STRICT_MODE=false

# Counters
TOTAL=0
PASSED=0
WARNED=0
FAILED=0
SKIPPED=0

# ── Color output ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# Disable colors if not a terminal
if [[ ! -t 1 ]]; then
  RED='' GREEN='' YELLOW='' BLUE='' DIM='' BOLD='' NC=''
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Validates all configuration files in the Dev Identity & Secrets reference
architecture without requiring any running infrastructure.

OPTIONS:
  --report FILE   Write validation report to FILE (in addition to stdout)
  --strict        Treat warnings as failures
  -h, --help      Show this help

CHECKS:
  - YAML syntax validation (python3 or yq)
  - HCL syntax validation (terraform fmt or hclfmt)
  - Shell script linting (shellcheck)
  - OPA policy compilation and tests (opa)
  - Kubernetes manifest validation (kubeconform or kubeval)
  - Internal documentation cross-references
  - Placeholder value detection

EOF
  exit 0
}

declare -a REPORT_LINES=()

log_result() {
  local status="$1" category="$2" detail="$3"
  TOTAL=$((TOTAL + 1))
  local icon
  case "$status" in
    PASS)
      PASSED=$((PASSED + 1))
      icon="${GREEN}PASS${NC}"
      ;;
    WARN)
      WARNED=$((WARNED + 1))
      icon="${YELLOW}WARN${NC}"
      if [[ "$STRICT_MODE" == true ]]; then
        FAILED=$((FAILED + 1))
        PASSED=$((PASSED - 1 + 1))  # don't double-count
        # In strict mode, warnings count as failures for exit code
      fi
      ;;
    FAIL)
      FAILED=$((FAILED + 1))
      icon="${RED}FAIL${NC}"
      ;;
    SKIP)
      SKIPPED=$((SKIPPED + 1))
      icon="${DIM}SKIP${NC}"
      ;;
  esac

  local line
  line="$(printf "  [%b] %-30s %s" "$icon" "$category" "$detail")"
  echo -e "$line"
  # Store plain text for report file
  REPORT_LINES+=("$(printf "  [%-4s] %-30s %s" "$status" "$category" "$detail")")
}

section() {
  local title="$1"
  echo ""
  echo -e "${BOLD}═══ ${title} ═══${NC}"
  REPORT_LINES+=("" "=== ${title} ===")
}

has_tool() {
  command -v "$1" &>/dev/null
}

# ── Argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    --report)     REPORT_FILE="$2"; shift 2 ;;
    --strict)     STRICT_MODE=true; shift ;;
    *)
      echo "Error: unknown argument: $1" >&2
      echo "Run $(basename "$0") --help for usage." >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"

# ── Banner ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║  Dev Identity & Secrets — Reference Validation Harness      ║${NC}"
echo -e "${BLUE}${BOLD}║  ${TIMESTAMP}                                          ║${NC}"
echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

if [[ "$STRICT_MODE" == true ]]; then
  echo -e "  ${YELLOW}Strict mode: warnings treated as failures${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 1. YAML Validation
# ══════════════════════════════════════════════════════════════════════════════

section "YAML Syntax Validation"

yaml_files=()
while IFS= read -r -d '' f; do
  yaml_files+=("$f")
done < <(find . -type f \( -name '*.yaml' -o -name '*.yml' \) \
  -not -path './.git/*' -not -path './node_modules/*' -print0 2>/dev/null)

yaml_validator=""
if [[ ${#yaml_files[@]} -eq 0 ]]; then
  log_result "SKIP" "yaml" "No YAML files found"
else
  # Detect best available YAML validator
  if has_tool python3 && python3 -c "import yaml" 2>/dev/null; then
    yaml_validator="python3"
  elif has_tool yq; then
    yaml_validator="yq"
  elif has_tool ruby && ruby -e "require 'yaml'" 2>/dev/null; then
    yaml_validator="ruby"
  fi

  if [[ -z "$yaml_validator" ]]; then
    log_result "SKIP" "yaml" "No YAML parser available (install python3+pyyaml or yq)"
  else
    yaml_errors=0
    yaml_error_files=()
    for f in "${yaml_files[@]}"; do
      valid=true
      case "$yaml_validator" in
        python3)
          if ! python3 -c "
import yaml, sys
try:
    with open(sys.argv[1], 'r') as fh:
        list(yaml.safe_load_all(fh))
except yaml.YAMLError as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
" "$f" 2>/dev/null; then
            valid=false
          fi
          ;;
        yq)
          if ! yq eval '.' "$f" > /dev/null 2>&1; then
            valid=false
          fi
          ;;
        ruby)
          if ! ruby -e "require 'yaml'; YAML.load_file(ARGV[0], permitted_classes: [Date, Time])" "$f" 2>/dev/null; then
            valid=false
          fi
          ;;
      esac
      if [[ "$valid" == false ]]; then
        yaml_errors=$((yaml_errors + 1))
        yaml_error_files+=("$f")
      fi
    done
    if [[ $yaml_errors -eq 0 ]]; then
      log_result "PASS" "yaml" "${#yaml_files[@]} files parsed successfully (${yaml_validator})"
    else
      log_result "FAIL" "yaml" "${yaml_errors}/${#yaml_files[@]} files have syntax errors"
      for ef in "${yaml_error_files[@]}"; do
        echo -e "         ${RED}${ef}${NC}"
      done
    fi
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# 2. HCL Validation
# ══════════════════════════════════════════════════════════════════════════════

section "HCL Syntax Validation"

hcl_files=()
while IFS= read -r -d '' f; do
  hcl_files+=("$f")
done < <(find . -type f -name '*.hcl' -not -path './.git/*' -print0 2>/dev/null)

if [[ ${#hcl_files[@]} -eq 0 ]]; then
  log_result "SKIP" "hcl" "No HCL files found"
elif has_tool hclfmt; then
  hcl_errors=0
  hcl_error_files=()
  for f in "${hcl_files[@]}"; do
    if ! hclfmt -check "$f" > /dev/null 2>&1; then
      hcl_errors=$((hcl_errors + 1))
      hcl_error_files+=("$f")
    fi
  done
  if [[ $hcl_errors -eq 0 ]]; then
    log_result "PASS" "hcl" "${#hcl_files[@]} files validated (hclfmt)"
  else
    log_result "FAIL" "hcl" "${hcl_errors}/${#hcl_files[@]} files have errors"
    for ef in "${hcl_error_files[@]}"; do
      echo -e "         ${RED}${ef}${NC}"
    done
  fi
elif has_tool python3 && python3 -c "import hcl2" 2>/dev/null; then
  # python-hcl2 can parse HCL2 files
  hcl_errors=0
  hcl_error_files=()
  for f in "${hcl_files[@]}"; do
    if ! python3 -c "
import hcl2, sys, json
try:
    with open(sys.argv[1], 'r') as fh:
        hcl2.load(fh)
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
" "$f" 2>/dev/null; then
      hcl_errors=$((hcl_errors + 1))
      hcl_error_files+=("$f")
    fi
  done
  if [[ $hcl_errors -eq 0 ]]; then
    log_result "PASS" "hcl" "${#hcl_files[@]} files validated (python-hcl2)"
  else
    log_result "FAIL" "hcl" "${hcl_errors}/${#hcl_files[@]} files have errors"
    for ef in "${hcl_error_files[@]}"; do
      echo -e "         ${RED}${ef}${NC}"
    done
  fi
else
  # Basic structural validation: check for balanced braces (non-comment lines only)
  hcl_errors=0
  hcl_error_files=()
  for f in "${hcl_files[@]}"; do
    # Use awk to count braces on non-comment lines
    result=$(awk '!/^[[:space:]]*#/ && !/^[[:space:]]*\/\// {
      for(i=1;i<=length($0);i++) {
        c=substr($0,i,1)
        if(c=="{") opens++
        if(c=="}") closes++
      }
    } END { print opens+0, closes+0 }' "$f" 2>/dev/null)
    opens="${result%% *}"
    closes="${result##* }"
    if [[ "$opens" -ne "$closes" ]]; then
      hcl_errors=$((hcl_errors + 1))
      hcl_error_files+=("$f")
    fi
  done
  if [[ $hcl_errors -eq 0 ]]; then
    log_result "PASS" "hcl" "${#hcl_files[@]} files pass basic structure check (brace balance)"
  else
    log_result "FAIL" "hcl" "${hcl_errors}/${#hcl_files[@]} files have unbalanced braces"
    for ef in "${hcl_error_files[@]}"; do
      echo -e "         ${RED}${ef}${NC}"
    done
  fi
  echo -e "         ${DIM}Install hclfmt for full HCL validation${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 3. Shell Script Linting
# ══════════════════════════════════════════════════════════════════════════════

section "Shell Script Linting"

sh_files=()
while IFS= read -r -d '' f; do
  sh_files+=("$f")
done < <(find . -type f -name '*.sh' -not -path './.git/*' -print0 2>/dev/null)

if [[ ${#sh_files[@]} -eq 0 ]]; then
  log_result "SKIP" "shellcheck" "No shell scripts found"
elif has_tool shellcheck; then
  sc_errors=0
  sc_warnings=0
  sc_error_files=()
  for f in "${sh_files[@]}"; do
    sc_output=""
    if ! sc_output=$(shellcheck -S warning -f gcc "$f" 2>&1); then
      if echo "$sc_output" | grep -q "error:"; then
        sc_errors=$((sc_errors + 1))
        sc_error_files+=("$f")
      else
        sc_warnings=$((sc_warnings + 1))
      fi
    fi
  done
  if [[ $sc_errors -eq 0 && $sc_warnings -eq 0 ]]; then
    log_result "PASS" "shellcheck" "${#sh_files[@]} scripts pass shellcheck"
  elif [[ $sc_errors -eq 0 ]]; then
    log_result "WARN" "shellcheck" "${sc_warnings}/${#sh_files[@]} scripts have warnings"
  else
    log_result "FAIL" "shellcheck" "${sc_errors} errors, ${sc_warnings} warnings in ${#sh_files[@]} scripts"
    for ef in "${sc_error_files[@]}"; do
      echo -e "         ${RED}${ef}${NC}"
    done
  fi
else
  log_result "SKIP" "shellcheck" "shellcheck not installed (brew install shellcheck)"
  echo -e "         ${DIM}Found ${#sh_files[@]} shell scripts that were not linted${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 4. OPA Policy Compilation & Tests
# ══════════════════════════════════════════════════════════════════════════════

section "OPA Policy Validation"

opa_files=()
while IFS= read -r -d '' f; do
  opa_files+=("$f")
done < <(find . -type f -name '*.rego' -not -path './.git/*' -print0 2>/dev/null)

opa_test_files=()
for f in "${opa_files[@]}"; do
  if [[ "$f" == *"_test.rego" ]]; then
    opa_test_files+=("$f")
  fi
done

if [[ ${#opa_files[@]} -eq 0 ]]; then
  log_result "SKIP" "opa-compile" "No OPA policy files found"
elif has_tool opa; then
  # Compile check
  opa_compile_errors=0
  opa_compile_error_files=()
  for f in "${opa_files[@]}"; do
    if ! opa check "$f" 2>/dev/null; then
      opa_compile_errors=$((opa_compile_errors + 1))
      opa_compile_error_files+=("$f")
    fi
  done
  if [[ $opa_compile_errors -eq 0 ]]; then
    log_result "PASS" "opa-compile" "${#opa_files[@]} policies compile successfully"
  else
    log_result "FAIL" "opa-compile" "${opa_compile_errors}/${#opa_files[@]} policies failed to compile"
    for ef in "${opa_compile_error_files[@]}"; do
      echo -e "         ${RED}${ef}${NC}"
    done
  fi

  # Run OPA tests
  if [[ ${#opa_test_files[@]} -gt 0 ]]; then
    opa_test_dirs=()
    for f in "${opa_test_files[@]}"; do
      d="$(dirname "$f")"
      # Deduplicate directories
      found=false
      for existing in "${opa_test_dirs[@]+"${opa_test_dirs[@]}"}"; do
        if [[ "$existing" == "$d" ]]; then
          found=true
          break
        fi
      done
      if [[ "$found" == false ]]; then
        opa_test_dirs+=("$d")
      fi
    done

    opa_test_failures=0
    for d in "${opa_test_dirs[@]}"; do
      if ! opa test "$d" -v 2>&1 | tail -5; then
        opa_test_failures=$((opa_test_failures + 1))
      fi
    done

    if [[ $opa_test_failures -eq 0 ]]; then
      log_result "PASS" "opa-test" "${#opa_test_files[@]} test files pass"
    else
      log_result "FAIL" "opa-test" "OPA tests failed in ${opa_test_failures} director(ies)"
    fi
  else
    log_result "SKIP" "opa-test" "No OPA test files (*_test.rego) found"
  fi
else
  log_result "SKIP" "opa-compile" "opa not installed (brew install opa)"
  echo -e "         ${DIM}Found ${#opa_files[@]} policy files that were not validated${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 5. Kubernetes Manifest Validation
# ══════════════════════════════════════════════════════════════════════════════

section "Kubernetes Manifest Validation"

# Identify Kubernetes manifests (YAML files with apiVersion + kind)
k8s_files=()
for f in "${yaml_files[@]}"; do
  if grep -q 'apiVersion:' "$f" 2>/dev/null && grep -q 'kind:' "$f" 2>/dev/null; then
    k8s_files+=("$f")
  fi
done

if [[ ${#k8s_files[@]} -eq 0 ]]; then
  log_result "SKIP" "k8s-manifests" "No Kubernetes manifests found"
elif has_tool kubeconform; then
  kc_errors=0
  kc_error_files=()
  for f in "${k8s_files[@]}"; do
    if ! kubeconform -strict -ignore-missing-schemas -summary "$f" 2>&1 | grep -q "VALID"; then
      # kubeconform may not know custom CRDs — check exit code
      if ! kubeconform -ignore-missing-schemas "$f" > /dev/null 2>&1; then
        kc_errors=$((kc_errors + 1))
        kc_error_files+=("$f")
      fi
    fi
  done
  if [[ $kc_errors -eq 0 ]]; then
    log_result "PASS" "k8s-manifests" "${#k8s_files[@]} manifests validated (kubeconform)"
  else
    log_result "FAIL" "k8s-manifests" "${kc_errors}/${#k8s_files[@]} manifests invalid"
    for ef in "${kc_error_files[@]}"; do
      echo -e "         ${RED}${ef}${NC}"
    done
  fi
elif has_tool kubeval; then
  kv_errors=0
  for f in "${k8s_files[@]}"; do
    if ! kubeval --strict --ignore-missing-schemas "$f" > /dev/null 2>&1; then
      kv_errors=$((kv_errors + 1))
    fi
  done
  if [[ $kv_errors -eq 0 ]]; then
    log_result "PASS" "k8s-manifests" "${#k8s_files[@]} manifests validated (kubeval)"
  else
    log_result "FAIL" "k8s-manifests" "${kv_errors}/${#k8s_files[@]} manifests invalid"
  fi
else
  log_result "SKIP" "k8s-manifests" "kubeconform/kubeval not installed"
  echo -e "         ${DIM}Found ${#k8s_files[@]} Kubernetes manifests that were not validated${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 6. Internal Documentation Cross-References
# ══════════════════════════════════════════════════════════════════════════════

section "Documentation Cross-References"

md_files=()
while IFS= read -r -d '' f; do
  md_files+=("$f")
done < <(find . -type f -name '*.md' -not -path './.git/*' -print0 2>/dev/null)

if [[ ${#md_files[@]} -eq 0 ]]; then
  log_result "SKIP" "doc-xrefs" "No markdown files found"
else
  broken_refs=0
  broken_ref_details=()
  for f in "${md_files[@]}"; do
    # Extract relative file links from markdown: [text](path) — exclude URLs, anchors, images
    while IFS= read -r link; do
      # Skip URLs (http/https/ftp/mailto)
      [[ "$link" =~ ^https?:// || "$link" =~ ^ftp:// || "$link" =~ ^mailto: ]] && continue
      # Skip pure anchors
      [[ "$link" =~ ^# ]] && continue
      # Skip empty links
      [[ -z "$link" ]] && continue

      # Remove anchor fragment
      link_path="${link%%#*}"
      # Remove query string
      link_path="${link_path%%\?*}"
      # Skip if empty after stripping
      [[ -z "$link_path" ]] && continue

      # Resolve relative to the file's directory
      file_dir="$(dirname "$f")"
      target="${file_dir}/${link_path}"

      if [[ ! -e "$target" ]]; then
        broken_refs=$((broken_refs + 1))
        broken_ref_details+=("${f} -> ${link_path}")
      fi
    done < <(grep -oP '\[(?:[^\]]*)\]\(\K[^)]+' "$f" 2>/dev/null || true)
  done

  if [[ $broken_refs -eq 0 ]]; then
    log_result "PASS" "doc-xrefs" "${#md_files[@]} markdown files, all cross-references resolve"
  else
    log_result "WARN" "doc-xrefs" "${broken_refs} broken cross-reference(s) found"
    # Show first 10
    shown=0
    for detail in "${broken_ref_details[@]}"; do
      if [[ $shown -ge 10 ]]; then
        echo -e "         ${DIM}... and $((broken_refs - 10)) more${NC}"
        break
      fi
      echo -e "         ${YELLOW}${detail}${NC}"
      shown=$((shown + 1))
    done
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# 7. Placeholder Value Detection
# ══════════════════════════════════════════════════════════════════════════════

section "Placeholder Value Detection"

# Common placeholder patterns that should be replaced before use
placeholder_patterns=(
  'YOUR[-_]'
  'CHANGE[-_]ME'
  'REPLACE[-_]ME'
  'TODO[-_]REPLACE'
  'example\.com'
  'example\.internal'
  'your-tenant-id'
  'your-project-id'
  'your-vault-name'
  '111122223333'
  'APP_ROLE_NAME'
  'PLACEHOLDER'
)

# Files that are expected to have placeholders (examples, templates, docs)
# We still scan them but report as INFO rather than WARN
placeholder_count=0
placeholder_details=()

# Only check non-documentation config files for unexpected placeholders
config_files=()
while IFS= read -r -d '' f; do
  config_files+=("$f")
done < <(find . -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.hcl' -o -name '*.json' -o -name '*.sh' \) \
  -not -path './.git/*' -not -path './node_modules/*' -not -path './docs/*' \
  -not -name '*README*' -not -name '*example*' -not -name '*.md' \
  -not -name 'validate_reference.sh' \
  -print0 2>/dev/null)

for f in "${config_files[@]}"; do
  for pattern in "${placeholder_patterns[@]}"; do
    if matches=$(grep -nE "$pattern" "$f" 2>/dev/null | head -3); then
      if [[ -n "$matches" ]]; then
        # Expected in example/template files
        if [[ "$f" == *"example"* || "$f" == *"template"* || "$f" == *"examples/"* ]]; then
          continue
        fi
        placeholder_count=$((placeholder_count + 1))
        placeholder_details+=("${f}: matches '${pattern}'")
        break  # One match per file is enough
      fi
    fi
  done
done

if [[ $placeholder_count -eq 0 ]]; then
  log_result "PASS" "placeholders" "No unexpected placeholder values in config files"
else
  log_result "WARN" "placeholders" "${placeholder_count} file(s) contain placeholder values"
  for detail in "${placeholder_details[@]}"; do
    echo -e "         ${YELLOW}${detail}${NC}"
  done
fi

# Count placeholders in example files for informational purposes
example_placeholders=0
while IFS= read -r -d '' f; do
  for pattern in "${placeholder_patterns[@]}"; do
    if grep -qE "$pattern" "$f" 2>/dev/null; then
      example_placeholders=$((example_placeholders + 1))
      break
    fi
  done
done < <(find . -type f \( -name '*.yaml' -o -name '*.hcl' -o -name '*.sh' \) \
  -path '*/examples/*' -not -path './.git/*' -print0 2>/dev/null)

if [[ $example_placeholders -gt 0 ]]; then
  echo -e "         ${DIM}${example_placeholders} example file(s) contain placeholders (expected)${NC}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 8. File Permission Checks
# ══════════════════════════════════════════════════════════════════════════════

section "File Permission Checks"

# Verify shell scripts are executable
non_exec_scripts=0
non_exec_list=()
for f in "${sh_files[@]}"; do
  if [[ ! -x "$f" ]]; then
    non_exec_scripts=$((non_exec_scripts + 1))
    non_exec_list+=("$f")
  fi
done

if [[ $non_exec_scripts -eq 0 ]]; then
  log_result "PASS" "script-perms" "All ${#sh_files[@]} shell scripts are executable"
else
  log_result "WARN" "script-perms" "${non_exec_scripts}/${#sh_files[@]} scripts not executable"
  for ef in "${non_exec_list[@]}"; do
    echo -e "         ${YELLOW}${ef}${NC}"
  done
fi

# ══════════════════════════════════════════════════════════════════════════════
# 9. Structure Validation
# ══════════════════════════════════════════════════════════════════════════════

section "Repository Structure"

expected_dirs=(
  "bootstrap"
  "docs"
  "examples"
  "platform/vault/config"
  "platform/vault/policies"
  "secrets"
  "tests"
  "tools"
)

missing_dirs=0
for d in "${expected_dirs[@]}"; do
  if [[ ! -d "$d" ]]; then
    missing_dirs=$((missing_dirs + 1))
    echo -e "         ${RED}Missing: ${d}${NC}"
  fi
done

if [[ $missing_dirs -eq 0 ]]; then
  log_result "PASS" "repo-structure" "All ${#expected_dirs[@]} expected directories present"
else
  log_result "FAIL" "repo-structure" "${missing_dirs}/${#expected_dirs[@]} expected directories missing"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BLUE}${BOLD}══════════════════════════════════════════════════════════════${NC}"

# Determine overall status
if [[ "$STRICT_MODE" == true ]]; then
  effective_failures=$((FAILED + WARNED))
else
  effective_failures=$FAILED
fi

if [[ $effective_failures -gt 0 ]]; then
  overall="${RED}FAILED${NC}"
elif [[ $WARNED -gt 0 ]]; then
  overall="${YELLOW}PASSED (with warnings)${NC}"
else
  overall="${GREEN}PASSED${NC}"
fi

echo -e "  Overall: ${overall}"
echo -e "  Total: ${TOTAL}  |  ${GREEN}Passed: ${PASSED}${NC}  |  ${YELLOW}Warned: ${WARNED}${NC}  |  ${RED}Failed: ${FAILED}${NC}  |  ${DIM}Skipped: ${SKIPPED}${NC}"
echo -e "${BLUE}${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Write report file ────────────────────────────────────────────────────────

if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "Dev Identity & Secrets — Validation Report"
    echo "Timestamp: ${TIMESTAMP}"
    echo "Strict mode: ${STRICT_MODE}"
    echo ""
    for line in "${REPORT_LINES[@]}"; do
      echo "$line"
    done
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  Total: ${TOTAL}  |  Passed: ${PASSED}  |  Warned: ${WARNED}  |  Failed: ${FAILED}  |  Skipped: ${SKIPPED}"
    if [[ $effective_failures -gt 0 ]]; then
      echo "  Overall: FAILED"
    elif [[ $WARNED -gt 0 ]]; then
      echo "  Overall: PASSED (with warnings)"
    else
      echo "  Overall: PASSED"
    fi
    echo "══════════════════════════════════════════════════════════════"
  } > "$REPORT_FILE"
  echo "Report written to: ${REPORT_FILE}"
fi

# ── Exit code ────────────────────────────────────────────────────────────────

if [[ $effective_failures -gt 0 ]]; then
  exit 1
fi
exit 0
