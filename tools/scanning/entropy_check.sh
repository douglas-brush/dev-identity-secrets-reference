#!/usr/bin/env bash
set -euo pipefail

# entropy_check.sh — Entropy-based secret detection.
# Scans files for high-entropy strings that may be secrets or credentials.
# Reports file, line number, entropy score, and redacted snippet.

readonly SCRIPT_NAME="$(basename "$0")"
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Defaults
THRESHOLD="4.5"
FORMAT="text"
VERBOSE=0
EXCLUDE_PATTERNS=()
MIN_TOKEN_LENGTH=20
MAX_TOKEN_LENGTH=500
EXIT_CODE=0

# Colors (disabled in non-TTY or JSON mode)
if [[ -t 1 ]] && [[ "${FORMAT:-text}" == "text" ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Scan files for high-entropy strings that may be leaked secrets.

Options:
  --threshold FLOAT   Shannon entropy threshold (default: 4.5, range: 0-6)
  --exclude PATTERN   Glob pattern to exclude (repeatable)
  --format FORMAT     Output format: text or json (default: text)
  --min-length N      Minimum token length to evaluate (default: 20)
  --verbose           Show additional scan details
  --help              Show this help message

Exit codes:
  0  No high-entropy strings found
  1  High-entropy strings detected
  2  Script error

Examples:
  $SCRIPT_NAME
  $SCRIPT_NAME --threshold 5.0 --format json
  $SCRIPT_NAME --exclude '*.min.js' --exclude 'vendor/*'
EOF
  exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --exclude)   EXCLUDE_PATTERNS+=("$2"); shift 2 ;;
    --format)    FORMAT="$2"; shift 2 ;;
    --min-length) MIN_TOKEN_LENGTH="$2"; shift 2 ;;
    --verbose)   VERBOSE=1; shift ;;
    --help)      usage ;;
    *)           echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# Re-set colors after format is parsed
if [[ "$FORMAT" == "json" ]] || ! [[ -t 1 ]]; then
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

# Shannon entropy calculation in pure bash/awk
calculate_entropy() {
  local token="$1"
  echo "$token" | awk '
  {
    n = length($0)
    if (n == 0) { print 0; next }
    delete freq
    for (i = 1; i <= n; i++) {
      c = substr($0, i, 1)
      freq[c]++
    }
    entropy = 0
    for (c in freq) {
      p = freq[c] / n
      entropy -= p * (log(p) / log(2))
    }
    printf "%.4f\n", entropy
  }'
}

# File exclusion checks
should_skip_file() {
  local file="$1"

  # Skip binary files
  if file "$file" 2>/dev/null | grep -qE 'binary|executable|archive|image|font|compressed'; then
    return 0
  fi

  # Skip SOPS-encrypted files
  if [[ "$file" =~ \.enc\.(ya?ml|json)$ ]]; then
    return 0
  fi
  if head -20 "$file" 2>/dev/null | grep -qE '^sops:|"sops":'; then
    return 0
  fi

  # Skip known non-secret file types
  if [[ "$file" =~ \.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|tar|gz|lock)$ ]]; then
    return 0
  fi

  # Skip minified files
  if [[ "$file" =~ \.min\.(js|css)$ ]]; then
    return 0
  fi

  # Skip git internals
  if [[ "$file" =~ \.git/ ]]; then
    return 0
  fi

  # Skip test fixtures
  if [[ "$file" =~ tests/fixtures/ ]] || [[ "$file" =~ tests/unit/ ]] || [[ "$file" =~ tests/integration/ ]]; then
    return 0
  fi

  # Skip documentation
  if [[ "$file" =~ ^docs/ ]] || [[ "$file" =~ ^diagrams/ ]]; then
    return 0
  fi

  # Skip user-provided exclude patterns
  for pattern in "${EXCLUDE_PATTERNS[@]+"${EXCLUDE_PATTERNS[@]}"}"; do
    # shellcheck disable=SC2254
    case "$file" in
      $pattern) return 0 ;;
    esac
  done

  return 1
}

# Redact a token for safe display (show first 4 and last 4 chars)
redact() {
  local token="$1"
  local len=${#token}
  if [[ $len -le 12 ]]; then
    echo "${token:0:3}...${token: -3}"
  else
    echo "${token:0:4}...${token: -4}"
  fi
}

# Extract high-entropy tokens from a line
scan_line() {
  local file="$1"
  local line_num="$2"
  local line="$3"

  # Tokenize: split on whitespace, quotes, equals, colons, commas
  local tokens
  tokens=$(echo "$line" | tr -s '[:space:]"'"'"'=:,;{}[]()' '\n' | grep -E "^.{${MIN_TOKEN_LENGTH},${MAX_TOKEN_LENGTH}}$" || true)

  while IFS= read -r token; do
    [[ -z "$token" ]] && continue

    # Skip tokens that are obviously not secrets (common words, URLs without creds, etc.)
    if [[ "$token" =~ ^https?:// ]] && ! [[ "$token" =~ ://[^/]+:[^/]+@ ]]; then
      continue
    fi

    # Skip tokens that are all the same character
    if [[ "$token" =~ ^(.)\1+$ ]]; then
      continue
    fi

    # Skip hex-only strings that look like hashes in filenames or known patterns
    if [[ "$token" =~ ^[0-9a-f]{32,}$ ]] && [[ "$file" =~ \.(lock|sum)$ ]]; then
      continue
    fi

    local entropy
    entropy=$(calculate_entropy "$token")

    # Compare with threshold using awk
    if awk "BEGIN { exit !($entropy > $THRESHOLD) }"; then
      EXIT_CODE=1
      local redacted
      redacted=$(redact "$token")

      if [[ "$FORMAT" == "json" ]]; then
        printf '{"file":"%s","line":%d,"entropy":"%s","snippet":"%s"}\n' \
          "$file" "$line_num" "$entropy" "$redacted"
      else
        printf "%b[!]%b %s:%d  entropy=%s  %b%s%b\n" \
          "$RED" "$NC" "$file" "$line_num" "$entropy" "$YELLOW" "$redacted" "$NC"
      fi
    fi
  done <<< "$tokens"
}

# Main scan
main() {
  local file_count=0
  local findings_count=0
  local json_findings=()

  if [[ "$FORMAT" == "text" ]]; then
    printf "%b[*]%b Entropy scan (threshold=%.1f, min_length=%d)\n\n" \
      "$GREEN" "$NC" "$THRESHOLD" "$MIN_TOKEN_LENGTH"
  fi

  cd "$ROOT_DIR"

  while IFS= read -r -d '' file; do
    # Remove leading ./
    file="${file#./}"

    if should_skip_file "$file"; then
      [[ "$VERBOSE" -eq 1 ]] && printf "%b[~]%b Skipping: %s\n" "$BLUE" "$NC" "$file" >&2
      continue
    fi

    file_count=$((file_count + 1))
    [[ "$VERBOSE" -eq 1 ]] && printf "%b[~]%b Scanning: %s\n" "$BLUE" "$NC" "$file" >&2

    local line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      line_num=$((line_num + 1))

      # Skip short lines and comment-only lines
      [[ ${#line} -lt $MIN_TOKEN_LENGTH ]] && continue
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ "$line" =~ ^[[:space:]]*/\* ]] && continue
      [[ "$line" =~ ^[[:space:]]*// ]] && continue

      local output
      output=$(scan_line "$file" "$line_num" "$line")
      if [[ -n "$output" ]]; then
        if [[ "$FORMAT" == "json" ]]; then
          while IFS= read -r json_line; do
            json_findings+=("$json_line")
          done <<< "$output"
        else
          echo "$output"
        fi
        findings_count=$((findings_count + 1))
      fi
    done < "$file" 2>/dev/null || true

  done < <(find . -type f -not -path './.git/*' -not -path './node_modules/*' \
    -not -path './.terraform/*' -not -path './.venv/*' -print0 2>/dev/null)

  # Output summary
  if [[ "$FORMAT" == "json" ]]; then
    if [[ ${#json_findings[@]} -gt 0 ]]; then
      printf '{"threshold":%s,"files_scanned":%d,"findings":[' "$THRESHOLD" "$file_count"
      local first=1
      for f in "${json_findings[@]}"; do
        [[ $first -eq 0 ]] && printf ","
        printf '%s' "$f"
        first=0
      done
      printf ']}\n'
    else
      printf '{"threshold":%s,"files_scanned":%d,"findings":[]}\n' "$THRESHOLD" "$file_count"
    fi
  else
    echo ""
    printf "Scanned %d files\n" "$file_count"
    if [[ $EXIT_CODE -eq 0 ]]; then
      printf "%b[ok]%b No high-entropy strings detected above threshold %.1f\n" \
        "$GREEN" "$NC" "$THRESHOLD"
    else
      printf "%b[!!]%b High-entropy strings found — review findings above\n" "$RED" "$NC"
      printf "    Adjust threshold with --threshold or exclude paths with --exclude\n"
    fi
  fi

  exit "$EXIT_CODE"
}

main "$@"
