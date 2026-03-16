package sops

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// mockRunner simulates the sops binary for testing.
type mockRunner struct {
	stdout   string
	stderr   string
	err      error
	lastArgs []string
}

func (m *mockRunner) Run(name string, args ...string) (string, string, error) {
	m.lastArgs = args
	return m.stdout, m.stderr, m.err
}

func TestDecryptFile_JSON(t *testing.T) {
	// Create a temp file to satisfy the os.Stat check
	tmp := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(tmp, []byte(`{"sops":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	mock := &mockRunner{
		stdout: `{"username":"admin","password":"secret"}`,
	}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	result, err := DecryptFile(tmp, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["username"] != "admin" {
		t.Errorf("username = %v", result["username"])
	}
	if result["password"] != "secret" {
		t.Errorf("password = %v", result["password"])
	}
}

func TestDecryptFile_YAML(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(tmp, []byte("sops: {}"), 0o644); err != nil {
		t.Fatal(err)
	}

	mock := &mockRunner{
		stdout: "database:\n  host: localhost\n  port: 5432\n",
	}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	result, err := DecryptFile(tmp, "yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	db, ok := result["database"].(map[string]interface{})
	if !ok {
		t.Fatalf("database not a map: %T", result["database"])
	}
	if db["host"] != "localhost" {
		t.Errorf("host = %v", db["host"])
	}
}

func TestDecryptFile_Dotenv(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "secrets.env")
	if err := os.WriteFile(tmp, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	mock := &mockRunner{
		stdout: "DB_HOST=localhost\nDB_PORT=5432\nDB_PASS=\"secret value\"\n# comment\n",
	}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	result, err := DecryptFile(tmp, "dotenv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["DB_HOST"] != "localhost" {
		t.Errorf("DB_HOST = %v", result["DB_HOST"])
	}
	if result["DB_PASS"] != "secret value" {
		t.Errorf("DB_PASS = %v (quotes should be stripped)", result["DB_PASS"])
	}
}

func TestDecryptFile_NotFound(t *testing.T) {
	SetRunner(&mockRunner{})
	defer SetRunner(ExecRunner{})

	_, err := DecryptFile("/nonexistent/file.json", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDecryptFile_SopsError(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(tmp, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	mock := &mockRunner{
		stderr: "decryption failed: no key found",
		err:    fmt.Errorf("exit status 1"),
	}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	_, err := DecryptFile(tmp, "")
	if err == nil {
		t.Fatal("expected error when sops fails")
	}
	de, ok := err.(*DecryptError)
	if !ok {
		t.Fatalf("expected *DecryptError, got %T", err)
	}
	if de.Detail != "decryption failed: no key found" {
		t.Errorf("detail = %s", de.Detail)
	}
}

func TestDecryptFile_OutputFormatPassedToArgs(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(tmp, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	mock := &mockRunner{stdout: `{"k":"v"}`}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	_, _ = DecryptFile(tmp, "json")

	found := false
	for i, arg := range mock.lastArgs {
		if arg == "--output-type" && i+1 < len(mock.lastArgs) && mock.lastArgs[i+1] == "json" {
			found = true
		}
	}
	if !found {
		t.Errorf("--output-type json not found in args: %v", mock.lastArgs)
	}
}

func TestDecryptFile_AutoDetectFormat(t *testing.T) {
	tests := []struct {
		filename string
		format   string
	}{
		{"secrets.json", "json"},
		{"secrets.yaml", "yaml"},
		{"secrets.yml", "yaml"},
		{"secrets.env", "dotenv"},
		{"secrets.enc.yaml", "yaml"},
		{"secrets.enc.json", "json"},
		{"unknown.txt", "json"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := detectFormat(tt.filename)
			if got != tt.format {
				t.Errorf("detectFormat(%s) = %s, want %s", tt.filename, got, tt.format)
			}
		})
	}
}

func TestDecryptBytes_JSON(t *testing.T) {
	mock := &mockRunner{
		stdout: `{"decrypted":"value"}`,
	}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	result, err := DecryptBytes([]byte(`{"encrypted":"ENC[AES256_GCM,...]"}`), "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["decrypted"] != "value" {
		t.Errorf("decrypted = %v", result["decrypted"])
	}
}

func TestDecryptBytes_SopsError(t *testing.T) {
	mock := &mockRunner{
		stderr: "key not found",
		err:    fmt.Errorf("exit status 1"),
	}
	SetRunner(mock)
	defer SetRunner(ExecRunner{})

	_, err := DecryptBytes([]byte("{}"), "json")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseSopsConfig_Valid(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".sops.yaml")
	content := `creation_rules:
  - path_regex: "secrets/prod/.*"
    kms: "arn:aws:kms:us-east-1:123:key/abc"
    encrypted_regex: "^(password|token|secret)$"
  - path_regex: "secrets/dev/.*"
    age: "age1abc123"
`
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ParseSopsConfig(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.CreationRules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cfg.CreationRules))
	}
	if cfg.CreationRules[0].KMS != "arn:aws:kms:us-east-1:123:key/abc" {
		t.Errorf("rule 0 kms = %s", cfg.CreationRules[0].KMS)
	}
	if cfg.CreationRules[1].Age != "age1abc123" {
		t.Errorf("rule 1 age = %s", cfg.CreationRules[1].Age)
	}
}

func TestParseSopsConfig_NotFound(t *testing.T) {
	_, err := ParseSopsConfig("/nonexistent/.sops.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseSopsConfig_InvalidYAML(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".sops.yaml")
	if err := os.WriteFile(tmp, []byte(":::invalid"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ParseSopsConfig(tmp)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestSopsConfig_HasCloudKMS(t *testing.T) {
	tests := []struct {
		name  string
		rules []SopsCreationRule
		want  bool
	}{
		{
			name:  "with AWS KMS",
			rules: []SopsCreationRule{{KMS: "arn:aws:kms:..."}},
			want:  true,
		},
		{
			name:  "with Azure",
			rules: []SopsCreationRule{{AzureKeyVault: "https://..."}},
			want:  true,
		},
		{
			name:  "with GCP",
			rules: []SopsCreationRule{{GCPKMS: "projects/..."}},
			want:  true,
		},
		{
			name:  "age only",
			rules: []SopsCreationRule{{Age: "age1..."}},
			want:  false,
		},
		{
			name:  "empty",
			rules: nil,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SopsConfig{CreationRules: tt.rules}
			if got := cfg.HasCloudKMS(); got != tt.want {
				t.Errorf("HasCloudKMS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDotenv(t *testing.T) {
	input := `KEY1=value1
KEY2="quoted value"
KEY3='single quoted'
# comment
EMPTY=

`
	result := parseDotenv(input)
	if result["KEY1"] != "value1" {
		t.Errorf("KEY1 = %v", result["KEY1"])
	}
	if result["KEY2"] != "quoted value" {
		t.Errorf("KEY2 = %v", result["KEY2"])
	}
	if result["KEY3"] != "single quoted" {
		t.Errorf("KEY3 = %v", result["KEY3"])
	}
	if result["EMPTY"] != "" {
		t.Errorf("EMPTY = %v", result["EMPTY"])
	}
}

func TestDecryptError_Message(t *testing.T) {
	err := &DecryptError{Path: "test.json", Detail: "key not found"}
	expected := "sops decryption failed for test.json: key not found"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestNotInstalledError_Message(t *testing.T) {
	err := &NotInstalledError{}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
