// Package config provides validation utilities for repository structure,
// SOPS configuration, Vault HCL policies, and plaintext secret scanning.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecretFinding represents a single finding from plaintext secret scanning.
type SecretFinding struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	PatternName string `json:"pattern_name"`
	MatchedText string `json:"matched_text"`
	Severity    string `json:"severity"`
}

// secretPattern defines a regex pattern for detecting hardcoded secrets.
type secretPattern struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
}

var secretPatterns = []secretPattern{
	{
		Name:     "AWS Access Key",
		Regex:    regexp.MustCompile(`(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:[^A-Z0-9]|$)`),
		Severity: "high",
	},
	{
		Name:     "AWS Secret Key",
		Regex:    regexp.MustCompile(`(?i)(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
		Severity: "high",
	},
	{
		Name:     "Generic API Key Assignment",
		Regex:    regexp.MustCompile(`(?i)(?:api_key|apikey|api_secret)\s*[=:]\s*['"][A-Za-z0-9_\-]{20,}['"]`),
		Severity: "high",
	},
	{
		Name:     "Generic Password Assignment",
		Regex:    regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]`),
		Severity: "medium",
	},
	{
		Name:     "Generic Token Assignment",
		Regex:    regexp.MustCompile(`(?i)(?:token|bearer|auth_token)\s*[=:]\s*['"][A-Za-z0-9_\-\.]{20,}['"]`),
		Severity: "medium",
	},
	{
		Name:     "Private Key Block",
		Regex:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		Severity: "critical",
	},
	{
		Name:     "GitHub Token",
		Regex:    regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`),
		Severity: "high",
	},
	{
		Name:     "Slack Token",
		Regex:    regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[A-Za-z0-9\-]{20,}`),
		Severity: "high",
	},
	{
		Name:     "Vault Token",
		Regex:    regexp.MustCompile(`(?:hvs|s)\.[A-Za-z0-9]{24,}`),
		Severity: "high",
	},
	{
		Name:     "Connection String with Password",
		Regex:    regexp.MustCompile(`(?i)(?:mongodb|postgres|mysql|redis)://[^:]+:[^@]+@`),
		Severity: "high",
	},
}

// scannableExtensions defines which file types to scan.
var scannableExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true, ".rs": true,
	".java": true, ".rb": true, ".php": true, ".yaml": true, ".yml": true,
	".json": true, ".toml": true, ".ini": true, ".cfg": true, ".conf": true,
	".env": true, ".sh": true, ".bash": true, ".zsh": true, ".ps1": true,
	".tf": true, ".hcl": true, ".xml": true, ".properties": true, ".gradle": true,
}

// skipDirs defines directories to skip during scanning.
var skipDirs = map[string]bool{
	".git": true, "__pycache__": true, "node_modules": true,
	".venv": true, "venv": true, ".tox": true, ".mypy_cache": true,
	".pytest_cache": true, "dist": true, "build": true, ".eggs": true,
}

// maxScanSize is the maximum file size to scan (1 MB).
const maxScanSize = 1_048_576

// expectedDirs are required directories for a well-formed repository.
var expectedDirs = []string{
	"platform/vault/policies",
	"secrets",
	"docs",
}

// expectedFiles are required files for a well-formed repository.
var expectedFiles = []string{
	".sops.yaml",
}

// ValidateRepoStructure checks that a repository follows the
// dev-identity-secrets-reference layout conventions.
//
// Returns a list of issues found. An empty list means the repo is valid.
func ValidateRepoStructure(root string) []string {
	var issues []string

	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return []string{fmt.Sprintf("repository root not found or not a directory: %s", root)}
	}

	// Check expected directories
	for _, d := range expectedDirs {
		p := filepath.Join(root, d)
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			issues = append(issues, fmt.Sprintf("missing expected directory: %s", d))
		}
	}

	// Check expected files
	for _, f := range expectedFiles {
		p := filepath.Join(root, f)
		if _, err := os.Stat(p); err != nil {
			issues = append(issues, fmt.Sprintf("missing expected file: %s", f))
		}
	}

	// Validate .sops.yaml if present
	sopsPath := filepath.Join(root, ".sops.yaml")
	if _, err := os.Stat(sopsPath); err == nil {
		sopsIssues := validateSopsYAML(sopsPath)
		for _, issue := range sopsIssues {
			issues = append(issues, ".sops.yaml: "+issue)
		}
	}

	// Validate Vault policies
	policyDir := filepath.Join(root, "platform", "vault", "policies")
	if fi, err := os.Stat(policyDir); err == nil && fi.IsDir() {
		entries, _ := os.ReadDir(policyDir)
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".hcl") {
				hclPath := filepath.Join(policyDir, entry.Name())
				relPath, _ := filepath.Rel(root, hclPath)
				policyIssues := ValidateVaultPolicy(hclPath)
				for _, issue := range policyIssues {
					issues = append(issues, relPath+": "+issue)
				}
			}
		}
	}

	// Check secrets directory structure
	secretsDir := filepath.Join(root, "secrets")
	if fi, err := os.Stat(secretsDir); err == nil && fi.IsDir() {
		expectedEnvs := map[string]bool{"dev": true, "staging": true, "prod": true}
		entries, _ := os.ReadDir(secretsDir)
		actualEnvs := make(map[string]bool)
		for _, e := range entries {
			if e.IsDir() {
				actualEnvs[e.Name()] = true
			}
		}
		for env := range expectedEnvs {
			if !actualEnvs[env] {
				issues = append(issues, fmt.Sprintf("missing secrets environment directory: secrets/%s", env))
			}
		}
	}

	return issues
}

// ScanPlaintextSecrets scans files at the given path for hardcoded secrets.
//
// If path is a file, only that file is scanned. If a directory, it is walked
// recursively. Returns a list of findings.
func ScanPlaintextSecrets(path string) ([]SecretFinding, error) {
	var findings []SecretFinding

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.IsDir() {
		fileFindigs := scanFile(path)
		return fileFindigs, nil
	}

	err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if fi.IsDir() {
			if skipDirs[fi.Name()] || strings.HasSuffix(fi.Name(), ".egg-info") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(fi.Name()))
		if scannableExtensions[ext] {
			findings = append(findings, scanFile(p)...)
		}
		return nil
	})
	if err != nil {
		return findings, fmt.Errorf("walk %s: %w", path, err)
	}

	return findings, nil
}

// ValidateVaultPolicy validates a Vault HCL policy file for correctness.
//
// Returns a list of issues found. An empty list means the policy is valid.
func ValidateVaultPolicy(path string) []string {
	var issues []string

	content, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("file not found: %s", path)}
	}

	text := string(content)
	if strings.TrimSpace(text) == "" {
		return []string{"policy file is empty"}
	}

	pathBlockRe := regexp.MustCompile(`path\s+"([^"]+)"\s*\{([^}]*)\}`)
	capabilitiesRe := regexp.MustCompile(`capabilities\s*=\s*\[([^\]]*)\]`)

	validCaps := map[string]bool{
		"create": true, "read": true, "update": true, "delete": true,
		"list": true, "sudo": true, "deny": true, "patch": true,
	}
	dangerousCaps := map[string]bool{"sudo": true, "delete": true}

	blocks := pathBlockRe.FindAllStringSubmatch(text, -1)
	if len(blocks) == 0 {
		return []string{"no 'path' blocks found — is this a valid Vault policy?"}
	}

	for _, match := range blocks {
		vaultPath := match[1]
		blockBody := match[2]
		prefix := fmt.Sprintf(`path "%s"`, vaultPath)

		capMatch := capabilitiesRe.FindStringSubmatch(blockBody)
		if capMatch == nil {
			issues = append(issues, fmt.Sprintf("%s: missing 'capabilities' list", prefix))
			continue
		}

		rawCaps := capMatch[1]
		caps := parseCaps(rawCaps)

		for _, cap := range caps {
			if !validCaps[cap] {
				issues = append(issues, fmt.Sprintf("%s: unknown capability '%s'", prefix, cap))
			}
			if dangerousCaps[cap] {
				issues = append(issues, fmt.Sprintf("%s: uses dangerous capability '%s' — ensure this is intentional", prefix, cap))
			}
		}

		// Warn on broad paths
		if strings.HasSuffix(vaultPath, "*") && !strings.HasSuffix(vaultPath, "/*") {
			issues = append(issues, fmt.Sprintf("%s: very broad path pattern — consider narrowing scope", prefix))
		}

		// Warn on root-level access
		if vaultPath == "*" || vaultPath == "sys/*" || vaultPath == "auth/*" {
			issues = append(issues, fmt.Sprintf("%s: root-level access — this should only be in emergency/admin policies", prefix))
		}
	}

	return issues
}

// --------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------

func validateSopsYAML(path string) []string {
	var issues []string

	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("cannot read: %v", err)}
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return []string{fmt.Sprintf("invalid YAML: %v", err)}
	}

	rulesRaw, ok := raw["creation_rules"]
	if !ok {
		return []string{"missing 'creation_rules' key"}
	}

	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return []string{"'creation_rules' must be a list"}
	}

	if len(rules) == 0 {
		return []string{"'creation_rules' is empty — no encryption rules defined"}
	}

	for i, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			issues = append(issues, fmt.Sprintf("rule %d: must be a mapping", i))
			continue
		}
		prefix := fmt.Sprintf("rule %d", i)

		pathRegex, _ := rule["path_regex"].(string)
		if pathRegex == "" {
			issues = append(issues, fmt.Sprintf("%s: missing 'path_regex'", prefix))
		} else {
			if _, err := regexp.Compile(pathRegex); err != nil {
				issues = append(issues, fmt.Sprintf("%s: invalid regex '%s': %v", prefix, pathRegex, err))
			}
		}

		keyFields := []string{"kms", "azure_keyvault", "gcp_kms", "age", "pgp", "hc_vault_transit_uri"}
		hasKey := false
		for _, k := range keyFields {
			if v, ok := rule[k].(string); ok && v != "" {
				hasKey = true
				break
			}
		}
		if !hasKey {
			issues = append(issues, fmt.Sprintf("%s: no encryption key source (kms, age, gcp_kms, azure_keyvault, pgp)", prefix))
		}
	}

	return issues
}

func scanFile(path string) []SecretFinding {
	var findings []SecretFinding

	fi, err := os.Stat(path)
	if err != nil || fi.Size() > maxScanSize || fi.Size() == 0 {
		return findings
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return findings
	}

	lines := strings.Split(string(content), "\n")
	for lineNum, line := range lines {
		for _, pat := range secretPatterns {
			match := pat.Regex.FindString(line)
			if match != "" {
				// Redact the match
				redacted := match
				if len(redacted) > 12 {
					redacted = redacted[:4] + "..." + redacted[len(redacted)-4:]
				} else if len(redacted) > 4 {
					redacted = redacted[:4] + "..."
				}
				findings = append(findings, SecretFinding{
					FilePath:    path,
					LineNumber:  lineNum + 1,
					PatternName: pat.Name,
					MatchedText: redacted,
					Severity:    pat.Severity,
				})
			}
		}
	}
	return findings
}

func parseCaps(raw string) []string {
	var caps []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			caps = append(caps, part)
		}
	}
	return caps
}
