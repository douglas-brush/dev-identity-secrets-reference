.PHONY: help setup validate scan audit test clean doctor tree

SHELL := /bin/bash
ROOT_DIR := $(shell pwd)

# Colors
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
NC     := \033[0m

help: ## Show available targets
	@echo "Dev Identity & Secrets Reference"
	@echo "================================"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# === Setup ===
setup: ## Install pre-commit hooks and validate dependencies
	@echo "$(GREEN)[*] Installing pre-commit hooks...$(NC)"
	@command -v pre-commit >/dev/null 2>&1 && pre-commit install || echo "$(YELLOW)[!] pre-commit not found — install with: pip install pre-commit$(NC)"
	@echo "$(GREEN)[*] Checking required tools...$(NC)"
	@./tools/secrets-doctor/doctor.sh deps

# === Validation ===
validate: scan lint ## Run all validation checks

scan: ## Scan for plaintext secrets
	@echo "$(GREEN)[*] Running secret scan...$(NC)"
	@./bootstrap/scripts/check_no_plaintext_secrets.sh
	@echo "$(GREEN)[*] Checking secrets/ directory encryption...$(NC)"
	@find secrets/ -name "*.yaml" -o -name "*.yml" -o -name "*.json" 2>/dev/null | grep -v "\.enc\." | grep -v "README" | grep -v ".gitkeep" && echo "$(RED)[!] Unencrypted files found in secrets/$(NC)" && exit 1 || echo "$(GREEN)[ok] All secrets files encrypted$(NC)"

lint: ## Lint shell scripts and YAML
	@echo "$(GREEN)[*] Linting shell scripts...$(NC)"
	@find . -name "*.sh" -not -path "./.git/*" -exec shellcheck -e SC1091 {} + 2>/dev/null || echo "$(YELLOW)[!] shellcheck not installed$(NC)"
	@echo "$(GREEN)[*] Validating YAML...$(NC)"
	@find . -name "*.yaml" -o -name "*.yml" | grep -v ".git" | grep -v "\.enc\." | while read f; do python3 -c "import yaml; yaml.safe_load(open('$$f'))" 2>/dev/null || echo "$(RED)[!] Invalid YAML: $$f$(NC)"; done

# === Security Audit ===
audit: ## Run full security audit
	@echo "$(GREEN)[*] Running secrets-doctor audit...$(NC)"
	@./tools/secrets-doctor/doctor.sh audit

# === Testing ===
test: ## Run OPA policy tests and integration tests
	@echo "$(GREEN)[*] Running OPA policy tests...$(NC)"
	@command -v opa >/dev/null 2>&1 && opa test tests/opa/ -v || echo "$(YELLOW)[!] OPA not installed$(NC)"
	@echo "$(GREEN)[*] Running compliance checks...$(NC)"
	@./tests/compliance/check_controls.sh

# === Diagnostics ===
doctor: ## Run secrets-doctor diagnostic tool
	@./tools/secrets-doctor/doctor.sh

tree: ## Show repository structure
	@find . -maxdepth 3 -not -path './.git/*' -not -path './node_modules/*' | sort | head -100

# === Cleanup ===
clean: ## Remove temporary and decrypted files
	@echo "$(GREEN)[*] Cleaning temporary files...$(NC)"
	@find . -name "*.dec.yaml" -o -name "*.dec.yml" -o -name "*.dec.json" -o -name "*.plain.yaml" -o -name "*.plain.yml" | xargs rm -f 2>/dev/null || true
	@rm -f /tmp/*.env /tmp/*.dec.yaml 2>/dev/null || true
	@echo "$(GREEN)[ok] Cleaned$(NC)"

# === Diagrams ===
diagrams: ## Render Mermaid diagrams (requires mmdc)
	@echo "$(GREEN)[*] Rendering diagrams...$(NC)"
	@command -v mmdc >/dev/null 2>&1 && find diagrams/ -name "*.mmd" -exec sh -c 'mmdc -i "$$1" -o "$${1%.mmd}.svg" -t dark' _ {} \; || echo "$(YELLOW)[!] mermaid-cli not installed — npm install -g @mermaid-js/mermaid-cli$(NC)"
