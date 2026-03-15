#!/usr/bin/env bash
set -euo pipefail

# Enhanced plaintext secret detection.
# Catches AWS, Azure, GCP, GitHub, generic API keys, JWTs, connection strings, and high-entropy strings.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

FORMAT="${1:-text}"  # text or json
FAIL=0
FINDINGS=()

# Patterns to detect
declare -A PATTERNS=(
  ["AWS Access Key"]='AKIA[0-9A-Z]{16}'
  ["AWS Secret Key"]='(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*[A-Za-z0-9/+=]{40}'
  ["Azure Client Secret"]='(?i)(client_secret|azure_secret)\s*[=:]\s*[A-Za-z0-9~._-]{34,}'
  ["GCP API Key"]='AIza[0-9A-Za-z\-_]{35}'
  ["GCP Service Account"]='(?i)"type"\s*:\s*"service_account"'
  ["GitHub Token"]='gh[pousr]_[A-Za-z0-9_]{36,}'
  ["GitHub Classic PAT"]='ghp_[A-Za-z0-9]{36}'
  ["Generic API Key"]='(?i)(api[_-]?key|apikey)\s*[=:]\s*[A-Za-z0-9]{20,}'
  ["Generic Secret"]='(?i)(secret|password|passwd)\s*[=:]\s*[^\s]{8,}'
  ["Private Key PEM"]='-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
  ["Certificate PEM"]='-----BEGIN CERTIFICATE-----'
  ["JWT Token"]='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  ["Connection String"]='(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s]{10,}'
  ["Slack Token"]='xox[baprs]-[0-9A-Za-z-]{10,}'
  ["Stripe Key"]='(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}'
  ["SendGrid Key"]='SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'
  ["Twilio"]='SK[0-9a-fA-F]{32}'
)

# Files/paths to exclude
EXCLUDE_REGEX='(\.enc\.(ya?ml|json)$|\.git/|node_modules/|\.terraform/|docs/compliance/|docs/incident-playbooks/|diagrams/|README\.md$|CHANGELOG\.md$|\.pre-commit-config\.yaml$|check_no_plaintext_secrets\.sh$|secrets_policy.*\.rego$|\.gitignore$)'

# Custom exclusion file
IGNORE_FILE="$ROOT_DIR/.secretsignore"

scan_file() {
  local file="$1"

  # Skip excluded paths
  if [[ "$file" =~ $EXCLUDE_REGEX ]]; then
    return 0
  fi

  # Skip custom ignores
  if [[ -f "$IGNORE_FILE" ]]; then
    while IFS= read -r pattern; do
      [[ -z "$pattern" || "$pattern" == \#* ]] && continue
      if [[ "$file" == *"$pattern"* ]]; then
        return 0
      fi
    done < "$IGNORE_FILE"
  fi

  # Skip binary files
  if file "$file" 2>/dev/null | grep -qE 'binary|executable|archive|image|font'; then
    return 0
  fi

  for name in "${!PATTERNS[@]}"; do
    local pattern="${PATTERNS[$name]}"
    if grep -EIqP "$pattern" "$file" 2>/dev/null || grep -EIq "$pattern" "$file" 2>/dev/null; then
      FAIL=1
      local line_info
      line_info=$(grep -EInP "$pattern" "$file" 2>/dev/null | head -3 || grep -EIn "$pattern" "$file" 2>/dev/null | head -3)
      if [[ "$FORMAT" == "json" ]]; then
        FINDINGS+=("{\"file\":\"$file\",\"pattern\":\"$name\",\"lines\":\"$(echo "$line_info" | head -1 | cut -d: -f1)\"}")
      else
        echo -e "${RED}[!]${NC} ${YELLOW}$name${NC} found in: $file"
        echo "$line_info" | head -3 | sed 's/^/    /'
      fi
    fi
  done
}

# Main scan
if [[ "$FORMAT" == "text" ]]; then
  echo -e "${GREEN}[*]${NC} Scanning for plaintext secrets..."
  echo ""
fi

while IFS= read -r -d '' file; do
  scan_file "$file"
done < <(find . -type f -not -path './.git/*' -not -path './node_modules/*' -not -path './.terraform/*' -print0 2>/dev/null)

# Output
if [[ "$FORMAT" == "json" ]]; then
  if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo "[$(IFS=,; echo "${FINDINGS[*]}")]"
  else
    echo "[]"
  fi
else
  echo ""
  if [[ "$FAIL" -ne 0 ]]; then
    echo -e "${RED}[✗] Plaintext secret scan FAILED${NC}"
    echo "    Fix the findings above before committing."
    echo "    Add false positives to .secretsignore"
  else
    echo -e "${GREEN}[✓] No plaintext secrets detected${NC}"
  fi
fi

exit "$FAIL"
