// Package sops provides helpers for decrypting SOPS-encrypted files.
//
// It shells out to the sops binary, which must be installed and available
// on PATH. Supports JSON, YAML, and dotenv formats.
package sops

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CommandRunner abstracts exec.Command for testability.
// The default implementation uses os/exec. Tests can substitute a mock.
type CommandRunner interface {
	// Run executes the given command with arguments and returns stdout, stderr, and any error.
	Run(name string, args ...string) (stdout, stderr string, err error)
}

// ExecRunner is the default CommandRunner using os/exec.
type ExecRunner struct{}

// Run executes a command and captures stdout and stderr.
func (ExecRunner) Run(name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// defaultRunner is the package-level runner used by public functions.
var defaultRunner CommandRunner = ExecRunner{}

// SetRunner overrides the command runner (for testing).
func SetRunner(r CommandRunner) {
	defaultRunner = r
}

// NotInstalledError is returned when the sops binary is not found on PATH.
type NotInstalledError struct{}

func (e *NotInstalledError) Error() string {
	return "sops binary not found on PATH; install from https://github.com/getsops/sops"
}

// DecryptError is returned when sops decryption fails.
type DecryptError struct {
	Path   string
	Detail string
}

func (e *DecryptError) Error() string {
	msg := fmt.Sprintf("sops decryption failed for %s", e.Path)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// findSops locates the sops binary on PATH.
func findSops() (string, error) {
	path, err := exec.LookPath("sops")
	if err != nil {
		return "", &NotInstalledError{}
	}
	return path, nil
}

// DecryptFile decrypts a SOPS-encrypted file and returns its contents as a map.
//
// The format is auto-detected from the file extension unless outputFormat
// is specified ("json", "yaml", or "dotenv"). Returns a map[string]interface{}
// with the decrypted data.
func DecryptFile(path string, outputFormat string) (map[string]interface{}, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", path)
	}

	sopsPath, err := findSops()
	if err != nil {
		return nil, err
	}

	args := []string{"--decrypt"}
	if outputFormat != "" {
		args = append(args, "--output-type", outputFormat)
	}
	args = append(args, path)

	stdout, stderr, err := defaultRunner.Run(sopsPath, args...)
	if err != nil {
		return nil, &DecryptError{Path: path, Detail: strings.TrimSpace(stderr)}
	}

	fmt_ := outputFormat
	if fmt_ == "" {
		fmt_ = detectFormat(path)
	}
	return parseOutput(stdout, fmt_, path)
}

// DecryptBytes decrypts SOPS-encrypted bytes (as if from a JSON or YAML document).
//
// The data is written to a temporary file, decrypted, and the result returned.
// inputFormat should be "json" or "yaml".
func DecryptBytes(data []byte, inputFormat string) (map[string]interface{}, error) {
	sopsPath, err := findSops()
	if err != nil {
		return nil, err
	}

	ext := ".json"
	if inputFormat == "yaml" || inputFormat == "yml" {
		ext = ".yaml"
	}

	tmpFile, err := os.CreateTemp("", "sops-decrypt-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	args := []string{"--decrypt", "--input-type", inputFormat, "--output-type", inputFormat, tmpFile.Name()}
	stdout, stderr, err := defaultRunner.Run(sopsPath, args...)
	if err != nil {
		return nil, &DecryptError{Path: "<bytes>", Detail: strings.TrimSpace(stderr)}
	}

	return parseOutput(stdout, inputFormat, "<bytes>")
}

// SopsCreationRule represents a single creation rule from .sops.yaml.
type SopsCreationRule struct {
	PathRegex      string `yaml:"path_regex" json:"path_regex"`
	KMS            string `yaml:"kms,omitempty" json:"kms,omitempty"`
	AzureKeyVault  string `yaml:"azure_keyvault,omitempty" json:"azure_keyvault,omitempty"`
	GCPKMS         string `yaml:"gcp_kms,omitempty" json:"gcp_kms,omitempty"`
	Age            string `yaml:"age,omitempty" json:"age,omitempty"`
	PGP            string `yaml:"pgp,omitempty" json:"pgp,omitempty"`
	EncryptedRegex string `yaml:"encrypted_regex,omitempty" json:"encrypted_regex,omitempty"`
}

// SopsConfig represents a parsed .sops.yaml configuration file.
type SopsConfig struct {
	Path          string             `json:"path"`
	CreationRules []SopsCreationRule `yaml:"creation_rules" json:"creation_rules"`
}

// ParseSopsConfig reads and parses a .sops.yaml file.
func ParseSopsConfig(path string) (*SopsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(".sops.yaml not found: %s", path)
		}
		return nil, fmt.Errorf("read .sops.yaml: %w", err)
	}

	var raw struct {
		CreationRules []SopsCreationRule `yaml:"creation_rules"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse .sops.yaml: %w", err)
	}

	return &SopsConfig{
		Path:          path,
		CreationRules: raw.CreationRules,
	}, nil
}

// HasCloudKMS returns true if any creation rule uses a cloud KMS provider
// (AWS KMS, Azure Key Vault, or GCP KMS).
func (c *SopsConfig) HasCloudKMS() bool {
	for _, r := range c.CreationRules {
		if r.KMS != "" || r.AzureKeyVault != "" || r.GCPKMS != "" {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

func detectFormat(path string) string {
	name := strings.ToLower(filepath.Base(path))
	// Handle .enc. prefix: secrets.enc.yaml -> yaml
	if strings.Contains(name, ".enc.") {
		parts := strings.SplitAfter(name, ".enc.")
		if len(parts) > 1 {
			ext := parts[len(parts)-1]
			switch ext {
			case "yaml", "yml":
				return "yaml"
			case "json":
				return "json"
			case "env", "dotenv":
				return "dotenv"
			}
		}
	}
	ext := strings.TrimPrefix(filepath.Ext(name), ".")
	switch ext {
	case "yaml", "yml":
		return "yaml"
	case "json":
		return "json"
	case "env", "dotenv":
		return "dotenv"
	}
	return "json"
}

func parseOutput(stdout, format, sourcePath string) (map[string]interface{}, error) {
	switch format {
	case "json":
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &result); err != nil {
			return nil, &DecryptError{Path: sourcePath, Detail: fmt.Sprintf("failed to parse JSON output: %v", err)}
		}
		return result, nil
	case "yaml", "yml":
		var result map[string]interface{}
		if err := yaml.Unmarshal([]byte(stdout), &result); err != nil {
			return nil, &DecryptError{Path: sourcePath, Detail: fmt.Sprintf("failed to parse YAML output: %v", err)}
		}
		if result == nil {
			return map[string]interface{}{}, nil
		}
		return result, nil
	case "dotenv":
		return parseDotenv(stdout), nil
	default:
		// Try JSON first, fall back to YAML
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &result); err == nil {
			return result, nil
		}
		if err := yaml.Unmarshal([]byte(stdout), &result); err == nil && result != nil {
			return result, nil
		}
		return nil, &DecryptError{Path: sourcePath, Detail: "failed to parse output as JSON or YAML"}
	}
}

func parseDotenv(content string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[0] == value[len(value)-1] {
			value = value[1 : len(value)-1]
		}
		result[key] = value
	}
	return result
}
