package config

import (
	"os"
	"path/filepath"
	"testing"
)

// setupRepo creates a minimal valid repo structure in a temp directory.
func setupRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	dirs := []string{
		"platform/vault/policies",
		"secrets/dev",
		"secrets/staging",
		"secrets/prod",
		"docs",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	sopsYAML := `creation_rules:
  - path_regex: "secrets/.*"
    age: "age1abc123"
    encrypted_regex: "^(password|token|secret)$"
`
	if err := os.WriteFile(filepath.Join(root, ".sops.yaml"), []byte(sopsYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	return root
}

func TestValidateRepoStructure_Valid(t *testing.T) {
	root := setupRepo(t)
	issues := ValidateRepoStructure(root)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d: %v", len(issues), issues)
	}
}

func TestValidateRepoStructure_MissingDirs(t *testing.T) {
	root := t.TempDir()
	// Only create .sops.yaml, no directories
	if err := os.WriteFile(filepath.Join(root, ".sops.yaml"), []byte("creation_rules:\n  - path_regex: \".*\"\n    age: abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	issues := ValidateRepoStructure(root)
	if len(issues) == 0 {
		t.Fatal("expected issues for missing directories")
	}

	foundPolicies := false
	foundSecrets := false
	foundDocs := false
	for _, issue := range issues {
		if issue == "missing expected directory: platform/vault/policies" {
			foundPolicies = true
		}
		if issue == "missing expected directory: secrets" {
			foundSecrets = true
		}
		if issue == "missing expected directory: docs" {
			foundDocs = true
		}
	}
	if !foundPolicies {
		t.Error("expected missing policies dir issue")
	}
	if !foundSecrets {
		t.Error("expected missing secrets dir issue")
	}
	if !foundDocs {
		t.Error("expected missing docs dir issue")
	}
}

func TestValidateRepoStructure_MissingSopsYAML(t *testing.T) {
	root := t.TempDir()
	for _, d := range expectedDirs {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.MkdirAll(filepath.Join(root, "secrets/dev"), 0o755)
	os.MkdirAll(filepath.Join(root, "secrets/staging"), 0o755)
	os.MkdirAll(filepath.Join(root, "secrets/prod"), 0o755)

	issues := ValidateRepoStructure(root)
	found := false
	for _, issue := range issues {
		if issue == "missing expected file: .sops.yaml" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected missing .sops.yaml issue, got: %v", issues)
	}
}

func TestValidateRepoStructure_MissingEnvDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range expectedDirs {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	os.MkdirAll(filepath.Join(root, "secrets/dev"), 0o755)
	// Missing staging and prod
	os.WriteFile(filepath.Join(root, ".sops.yaml"), []byte("creation_rules:\n  - path_regex: \".*\"\n    age: x\n"), 0o644)

	issues := ValidateRepoStructure(root)
	foundStaging := false
	foundProd := false
	for _, issue := range issues {
		if issue == "missing secrets environment directory: secrets/staging" {
			foundStaging = true
		}
		if issue == "missing secrets environment directory: secrets/prod" {
			foundProd = true
		}
	}
	if !foundStaging {
		t.Errorf("expected missing staging issue, got: %v", issues)
	}
	if !foundProd {
		t.Errorf("expected missing prod issue, got: %v", issues)
	}
}

func TestValidateRepoStructure_InvalidRoot(t *testing.T) {
	issues := ValidateRepoStructure("/nonexistent/path")
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %v", len(issues), issues)
	}
}

func TestValidateRepoStructure_VaultPolicies(t *testing.T) {
	root := setupRepo(t)

	// Add a valid policy
	policy := `path "kv/data/myapp/*" {
  capabilities = ["read", "list"]
}`
	os.WriteFile(filepath.Join(root, "platform/vault/policies/app.hcl"), []byte(policy), 0o644)

	issues := ValidateRepoStructure(root)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d: %v", len(issues), issues)
	}
}

func TestValidateVaultPolicy_Valid(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "policy.hcl")
	content := `path "kv/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "kv/metadata/myapp/*" {
  capabilities = ["read"]
}`
	os.WriteFile(tmp, []byte(content), 0o644)

	issues := ValidateVaultPolicy(tmp)
	if len(issues) != 0 {
		t.Errorf("expected no issues, got: %v", issues)
	}
}

func TestValidateVaultPolicy_EmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.hcl")
	os.WriteFile(tmp, []byte(""), 0o644)

	issues := ValidateVaultPolicy(tmp)
	if len(issues) != 1 || issues[0] != "policy file is empty" {
		t.Errorf("expected 'policy file is empty', got: %v", issues)
	}
}

func TestValidateVaultPolicy_NoPathBlocks(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.hcl")
	os.WriteFile(tmp, []byte("# just a comment\n"), 0o644)

	issues := ValidateVaultPolicy(tmp)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d: %v", len(issues), issues)
	}
}

func TestValidateVaultPolicy_DangerousCaps(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "danger.hcl")
	content := `path "sys/leases/*" {
  capabilities = ["read", "sudo", "delete"]
}`
	os.WriteFile(tmp, []byte(content), 0o644)

	issues := ValidateVaultPolicy(tmp)
	foundSudo := false
	foundDelete := false
	for _, issue := range issues {
		if contains(issue, "sudo") {
			foundSudo = true
		}
		if contains(issue, "delete") {
			foundDelete = true
		}
	}
	if !foundSudo {
		t.Error("expected warning about 'sudo'")
	}
	if !foundDelete {
		t.Error("expected warning about 'delete'")
	}
}

func TestValidateVaultPolicy_RootAccess(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "root.hcl")
	content := `path "*" {
  capabilities = ["read"]
}`
	os.WriteFile(tmp, []byte(content), 0o644)

	issues := ValidateVaultPolicy(tmp)
	foundRoot := false
	for _, issue := range issues {
		if contains(issue, "root-level access") {
			foundRoot = true
		}
	}
	if !foundRoot {
		t.Error("expected root-level access warning")
	}
}

func TestValidateVaultPolicy_MissingFile(t *testing.T) {
	issues := ValidateVaultPolicy("/nonexistent.hcl")
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got: %v", issues)
	}
}

func TestScanPlaintextSecrets_NoFindings(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.py"), []byte("print('hello world')\n"), 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestScanPlaintextSecrets_FindsAWSKey(t *testing.T) {
	dir := t.TempDir()
	content := `aws_config = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
}`
	os.WriteFile(filepath.Join(dir, "config.py"), []byte(content), 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for AWS key")
	}
	found := false
	for _, f := range findings {
		if f.PatternName == "AWS Access Key" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AWS Access Key pattern, got: %v", findings)
	}
}

func TestScanPlaintextSecrets_FindsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	content := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
	os.WriteFile(filepath.Join(dir, "key.conf"), []byte(content), 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for private key")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity = %s, want critical", findings[0].Severity)
	}
}

func TestScanPlaintextSecrets_FindsGitHubToken(t *testing.T) {
	dir := t.TempDir()
	content := `token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"`
	os.WriteFile(filepath.Join(dir, "ci.yaml"), []byte(content), 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternName == "GitHub Token" {
			found = true
		}
	}
	if !found {
		t.Error("expected GitHub Token finding")
	}
}

func TestScanPlaintextSecrets_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "dep")
	os.MkdirAll(nmDir, 0o755)
	os.WriteFile(filepath.Join(nmDir, "config.js"), []byte(`password = "hunter2secret"`), 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (node_modules skipped), got %d", len(findings))
	}
}

func TestScanPlaintextSecrets_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a file larger than maxScanSize
	large := make([]byte, maxScanSize+100)
	for i := range large {
		large[i] = 'x'
	}
	os.WriteFile(filepath.Join(dir, "large.py"), large, 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for oversized file, got %d", len(findings))
	}
}

func TestScanPlaintextSecrets_SingleFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret.py")
	os.WriteFile(f, []byte(`api_key = "sk_live_1234567890abcdefghij"`), 0o644)

	findings, err := ScanPlaintextSecrets(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for single file scan")
	}
}

func TestScanPlaintextSecrets_RedactsMatch(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.py")
	os.WriteFile(f, []byte(`-----BEGIN RSA PRIVATE KEY-----`), 0o644)

	findings, err := ScanPlaintextSecrets(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	// Should be redacted, not showing full match
	if findings[0].MatchedText == "-----BEGIN RSA PRIVATE KEY-----" {
		t.Error("expected redacted match text")
	}
}

func TestScanPlaintextSecrets_NonexistentPath(t *testing.T) {
	_, err := ScanPlaintextSecrets("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestScanPlaintextSecrets_ConnectionString(t *testing.T) {
	dir := t.TempDir()
	content := `db_url = "postgres://admin:secret@db.example.com:5432/mydb"`
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o644)

	findings, err := ScanPlaintextSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternName == "Connection String with Password" {
			found = true
		}
	}
	if !found {
		t.Error("expected connection string finding")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsImpl(s, sub))
}

func containsImpl(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
