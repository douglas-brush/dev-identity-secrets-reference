// Package main provides the secrets-sdk CLI tool.
//
// Commands:
//   - doctor: Validate repository structure, .sops.yaml, and Vault policies
//   - vault-health: Check Vault connectivity and health status
//   - scan: Scan files for plaintext secrets
//   - decrypt: Decrypt a SOPS-encrypted file
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/config"
	"github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/sops"
	"github.com/Brush-Cyber/dev-identity-secrets-reference/lib/go/vault"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var version = "0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "secrets-sdk",
		Short:   "Developer identity and secrets management toolkit",
		Version: version,
	}

	rootCmd.AddCommand(doctorCmd())
	rootCmd.AddCommand(vaultHealthCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(decryptCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func doctorCmd() *cobra.Command {
	var (
		root    string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Validate repository structure, .sops.yaml, and Vault policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			issues := config.ValidateRepoStructure(root)

			if jsonOut {
				data := map[string]interface{}{
					"issues": issues,
					"count":  len(issues),
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(data)
			}

			if len(issues) > 0 {
				fmt.Fprintf(os.Stderr, "Found %d issue(s):\n\n", len(issues))
				for i, issue := range issues {
					fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, issue)
				}
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			}

			fmt.Println("All checks passed.")
			return nil
		},
	}

	cmd.Flags().StringVar(&root, "root", ".", "Repository root directory")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	return cmd
}

func vaultHealthCmd() *cobra.Command {
	var (
		addr    string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "vault-health",
		Short: "Check Vault connectivity and health status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := vault.NewClient(addr)
			report := client.Health(context.Background())

			if jsonOut {
				data := map[string]interface{}{
					"overall": string(report.OverallStatus()),
					"checks":  report.Checks,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(data)
			}

			fmt.Println(report.Summary())
			fmt.Println()
			for _, check := range report.Checks {
				color := colorForStatus(check.Status)
				fmt.Printf("  %s%s: %s%s\n", color, check.Name, check.Status, colorReset)
				if check.Detail != "" {
					fmt.Printf("    %s\n", check.Detail)
				}
				if check.LatencyMs > 0 {
					fmt.Printf("    latency: %.1fms\n", check.LatencyMs)
				}
			}
			fmt.Println()

			if report.OverallStatus() == vault.HealthStatusUnhealthy {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "Vault address (default: VAULT_ADDR or http://127.0.0.1:8200)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	return cmd
}

func scanCmd() *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan files or directories for plaintext secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := config.ScanPlaintextSecrets(args[0])
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(findings)
			}

			if len(findings) > 0 {
				fmt.Fprintf(os.Stderr, "Found %d potential secret(s):\n\n", len(findings))
				for _, f := range findings {
					sevColor := colorForSeverity(f.Severity)
					fmt.Fprintf(os.Stderr, "  %s[%s] %s%s\n", sevColor, strings.ToUpper(f.Severity), f.PatternName, colorReset)
					fmt.Fprintf(os.Stderr, "    %s:%d\n", f.FilePath, f.LineNumber)
					fmt.Fprintf(os.Stderr, "    matched: %s\n\n", f.MatchedText)
				}
				os.Exit(1)
			}

			fmt.Println("No plaintext secrets found.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output results as JSON")
	return cmd
}

func decryptCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a SOPS-encrypted file and print the plaintext",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := sops.DecryptFile(args[0], outputFormat)
			if err != nil {
				return fmt.Errorf("decryption failed: %w", err)
			}

			fmt_ := outputFormat
			if fmt_ == "" {
				fmt_ = "json"
			}

			switch fmt_ {
			case "yaml":
				enc := yaml.NewEncoder(os.Stdout)
				enc.SetIndent(2)
				return enc.Encode(data)
			default:
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(data)
			}
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output-format", "", "Force output format (json, yaml)")
	return cmd
}

// ANSI color codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
)

func colorForStatus(status vault.HealthStatus) string {
	switch status {
	case vault.HealthStatusHealthy:
		return colorGreen
	case vault.HealthStatusDegraded:
		return colorYellow
	case vault.HealthStatusUnhealthy:
		return colorRed
	default:
		return ""
	}
}

func colorForSeverity(sev string) string {
	switch sev {
	case "critical", "high":
		return colorRed
	case "medium":
		return colorYellow
	default:
		return ""
	}
}
