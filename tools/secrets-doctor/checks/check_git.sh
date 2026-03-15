#!/usr/bin/env bash

#!/usr/bin/env bash
# check_git.sh — Git security configuration validator
# Sourced by doctor.sh — uses pass/warn/fail/skip/info functions from parent
set -euo pipefail

check_git() {
  # ── Git repository check ───────────────────────────────────────────────

  if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree &>/dev/null; then
    skip "Not a git repository — skipping git checks"
    return
  fi

  pass "Git repository detected"

  # ── Pre-commit hooks ──────────────────────────────────────────────────

  local hooks_dir="${REPO_ROOT}/.git/hooks"
  local pre_commit_hook="${hooks_dir}/pre-commit"

  if [[ -f "$pre_commit_hook" ]]; then
    if [[ -x "$pre_commit_hook" ]]; then
      pass "pre-commit hook is installed and executable"

      # Check if it references secret scanning
      if grep -qiE '(gitleaks|detect-secrets|trufflehog|git-secrets|sops)' "$pre_commit_hook" 2>/dev/null; then
        pass "pre-commit hook includes secret scanning"
      else
        warn "pre-commit hook does not appear to include secret scanning"
      fi
    else
      warn "pre-commit hook exists but is not executable"
    fi
  else
    # Check for pre-commit framework config
    if [[ -f "${REPO_ROOT}/.pre-commit-config.yaml" ]]; then
      pass ".pre-commit-config.yaml found"

      # Check if pre-commit framework hooks are installed
      if command -v pre-commit &>/dev/null; then
        if pre-commit validate-config "${REPO_ROOT}/.pre-commit-config.yaml" &>/dev/null; then
          pass "pre-commit config is valid"
        else
          warn "pre-commit config has validation errors"
        fi

        # Check for secret scanning hooks in config
        if grep -qiE '(gitleaks|detect-secrets|trufflehog|git-secrets)' "${REPO_ROOT}/.pre-commit-config.yaml" 2>/dev/null; then
          pass "pre-commit config includes secret scanning hooks"
        else
          warn "pre-commit config does not include secret scanning hooks"
        fi

        # Check for SOPS-related hooks
        if grep -qiE '(sops|encrypted)' "${REPO_ROOT}/.pre-commit-config.yaml" 2>/dev/null; then
          pass "pre-commit config includes SOPS/encryption hooks"
        fi
      else
        warn "pre-commit framework not installed — run: pip install pre-commit && pre-commit install"
      fi
    else
      fail "No pre-commit hook or .pre-commit-config.yaml found"
    fi
  fi

  # ── .gitignore coverage ───────────────────────────────────────────────

  local gitignore="${REPO_ROOT}/.gitignore"
  if [[ -f "$gitignore" ]]; then
    pass ".gitignore exists"

    # Sensitive file extensions that should be ignored
    local sensitive_patterns=(
      '*.pem'
      '*.key'
      '*.p12'
      '*.pfx'
      '*.jks'
      '*.keystore'
      '.env'
      '*.env'
      '.env.*'
      '*.tfvars'
      '*secret*'
      'credentials'
      '*.age'
      'keys.txt'
      '.vault-token'
      '*.crt'
    )

    local covered=0
    local missing=0
    local missing_list=""

    for pattern in "${sensitive_patterns[@]}"; do
      # Normalize pattern for matching
      local search_pattern="${pattern//\*/}"
      if grep -qF "$search_pattern" "$gitignore" 2>/dev/null || \
         grep -q "^${pattern}$" "$gitignore" 2>/dev/null || \
         grep -q "^\\*${search_pattern}" "$gitignore" 2>/dev/null; then
        covered=$((covered + 1))
      else
        missing=$((missing + 1))
        missing_list="${missing_list} ${pattern}"
      fi
    done

    if [[ $missing -eq 0 ]]; then
      pass ".gitignore covers all ${covered} sensitive file patterns"
    elif [[ $missing -le 3 ]]; then
      warn ".gitignore covers ${covered}/$((covered + missing)) sensitive patterns — missing:${missing_list}"
    else
      fail ".gitignore missing ${missing} sensitive patterns:${missing_list}"
    fi

    # Check for negation patterns that might re-include secrets
    if grep -qE '^!.*\.(pem|key|env|tfvars|p12|pfx)' "$gitignore" 2>/dev/null; then
      warn ".gitignore contains negation patterns (!) for sensitive extensions — review carefully"
    fi
  else
    fail ".gitignore not found at repository root"
  fi

  # ── Git history scan (last 10 commits) ─────────────────────────────────

  local commit_count
  commit_count=$(git -C "$REPO_ROOT" rev-list --count HEAD 2>/dev/null || echo "0")

  if [[ "$commit_count" -eq 0 ]]; then
    skip "No commits in repository — skipping history scan"
  else
    local scan_depth=$((commit_count < 10 ? commit_count : 10))
    info "Scanning last ${scan_depth} commits for secrets..."

    if command -v gitleaks &>/dev/null; then
      local gl_output
      if gl_output=$(gitleaks detect --source="$REPO_ROOT" --log-opts="-${scan_depth}" --no-banner 2>&1); then
        pass "No secrets found in last ${scan_depth} commits (gitleaks)"
      else
        if echo "$gl_output" | grep -q "leaks found"; then
          fail "Secrets detected in recent git history — run: gitleaks detect --source='${REPO_ROOT}' --verbose"
        else
          pass "No secrets found in last ${scan_depth} commits (gitleaks)"
        fi
      fi
    else
      # Fallback: check diffs for common patterns
      local secret_patterns='(AKIA[0-9A-Z]{16}|-----BEGIN.*PRIVATE KEY-----|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48}|AGE-SECRET-KEY-)'
      local diff_output
      diff_output=$(git -C "$REPO_ROOT" log -p -"${scan_depth}" --diff-filter=A 2>/dev/null | \
        grep -En "$secret_patterns" 2>/dev/null | head -5 || true)

      if [[ -n "$diff_output" ]]; then
        fail "Potential secrets found in recent commit diffs (install gitleaks for comprehensive scan)"
      else
        pass "No obvious secrets in last ${scan_depth} commit diffs (basic scan)"
      fi
    fi
  fi

  # ── Signed commits ───────────────────────────────────────────────────

  local signing_key
  signing_key=$(git -C "$REPO_ROOT" config --get commit.gpgsign 2>/dev/null || echo "false")
  if [[ "$signing_key" == "true" ]]; then
    pass "Commit signing is enabled"
  else
    warn "Commit signing is not enabled — recommended for supply chain security"
  fi

  # ── Branch protection recommendations ─────────────────────────────────

  local default_branch
  default_branch=$(git -C "$REPO_ROOT" symbolic-ref --short HEAD 2>/dev/null || echo "main")

  # Check if remote exists
  if git -C "$REPO_ROOT" remote get-url origin &>/dev/null; then
    info "Remote: $(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null)"

    # Check if the repo is on GitHub (for branch protection API)
    local remote_url
    remote_url=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || echo "")
    if [[ "$remote_url" == *"github.com"* ]]; then
      if command -v gh &>/dev/null; then
        # Extract owner/repo
        local repo_slug
        repo_slug=$(echo "$remote_url" | sed -E 's#.*/([^/]+/[^/]+)(\.git)?$#\1#')
        if gh api "repos/${repo_slug}/branches/${default_branch}/protection" &>/dev/null 2>&1; then
          pass "Branch protection enabled on ${default_branch}"
        else
          warn "Branch protection not configured on ${default_branch} — recommended"
        fi
      else
        info "Install gh CLI to check branch protection status"
      fi
    fi
  else
    info "No remote configured — branch protection check skipped"
  fi

  # ── Large file check ──────────────────────────────────────────────────

  local large_secrets
  large_secrets=$(git -C "$REPO_ROOT" ls-files 2>/dev/null | while read -r f; do
    local full_path="${REPO_ROOT}/${f}"
    if [[ -f "$full_path" ]] && [[ "$f" == *.pem || "$f" == *.key || "$f" == *.p12 || "$f" == *.pfx ]]; then
      echo "$f"
    fi
  done)

  if [[ -n "$large_secrets" ]]; then
    local count
    count=$(echo "$large_secrets" | wc -l | tr -d ' ')
    fail "${count} secret file(s) tracked by git: $(echo "$large_secrets" | head -3 | tr '\n' ', ')"
  else
    pass "No secret files (.pem, .key, .p12, .pfx) tracked by git"
  fi
}
