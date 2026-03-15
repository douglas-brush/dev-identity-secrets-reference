.PHONY: help setup validate scan lint audit test doctor tree clean diagrams \
       sdk-install sdk-test sdk-lint \
       dev-up dev-down dev-setup dev-demo dev-reset \
       drill inventory rotate-check rotate-sops \
       e2e all

SHELL := /bin/bash
ROOT_DIR := $(shell pwd)

# Colors
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
CYAN   := \033[0;36m
BOLD   := \033[1m
NC     := \033[0m

help: ## Show available targets
	@echo ""
	@echo "$(BOLD)Dev Identity & Secrets Reference$(NC)"
	@echo "================================"
	@echo ""
	@echo "$(CYAN)--- Setup & Diagnostics ---$(NC)"
	@echo "  $(GREEN)setup$(NC)                Install pre-commit hooks and validate dependencies"
	@echo "  $(GREEN)doctor$(NC)               Run secrets-doctor diagnostic tool"
	@echo "  $(GREEN)tree$(NC)                 Show repository structure"
	@echo ""
	@echo "$(CYAN)--- Validation & Security ---$(NC)"
	@echo "  $(GREEN)validate$(NC)             Run all validation checks (scan + lint)"
	@echo "  $(GREEN)scan$(NC)                 Scan for plaintext secrets"
	@echo "  $(GREEN)lint$(NC)                 Lint shell scripts and YAML"
	@echo "  $(GREEN)audit$(NC)               Run full security audit"
	@echo ""
	@echo "$(CYAN)--- Testing ---$(NC)"
	@echo "  $(GREEN)test$(NC)                 Run OPA policy tests and compliance checks"
	@echo "  $(GREEN)e2e$(NC)                  Run end-to-end reference validation"
	@echo "  $(GREEN)all$(NC)                  Full CI check (validate + test + e2e)"
	@echo ""
	@echo "$(CYAN)--- Python SDK ---$(NC)"
	@echo "  $(GREEN)sdk-install$(NC)          Install Python SDK in dev mode"
	@echo "  $(GREEN)sdk-test$(NC)             Run SDK tests"
	@echo "  $(GREEN)sdk-lint$(NC)             Lint SDK source"
	@echo ""
	@echo "$(CYAN)--- Local Dev Environment ---$(NC)"
	@echo "  $(GREEN)dev-up$(NC)               Start Docker Compose dev environment"
	@echo "  $(GREEN)dev-down$(NC)             Stop Docker Compose dev environment"
	@echo "  $(GREEN)dev-setup$(NC)            Run Vault setup inside dev container"
	@echo "  $(GREEN)dev-demo$(NC)             Run interactive demo"
	@echo "  $(GREEN)dev-reset$(NC)            Destroy and recreate dev environment"
	@echo ""
	@echo "$(CYAN)--- Operations ---$(NC)"
	@echo "  $(GREEN)drill$(NC)                Run break-glass drill"
	@echo "  $(GREEN)inventory$(NC)            Run non-human identity inventory scan"
	@echo "  $(GREEN)rotate-check$(NC)         Dry-run Vault secret rotation check"
	@echo "  $(GREEN)rotate-sops$(NC)          Dry-run SOPS key rotation check"
	@echo ""
	@echo "$(CYAN)--- Housekeeping ---$(NC)"
	@echo "  $(GREEN)clean$(NC)                Remove temporary and decrypted files"
	@echo "  $(GREEN)diagrams$(NC)             Render Mermaid diagrams (requires mmdc)"
	@echo ""

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

e2e: ## Run end-to-end reference validation
	@echo "$(GREEN)[*] Running E2E validation...$(NC)"
	@./tests/e2e/validate_reference.sh

all: validate test e2e ## Full CI check (validate + test + e2e)

# === Python SDK ===
sdk-install: ## Install Python SDK in dev mode
	@echo "$(GREEN)[*] Installing Python SDK...$(NC)"
	@cd lib/python && pip install -e ".[dev]"

sdk-test: ## Run SDK tests
	@echo "$(GREEN)[*] Running SDK tests...$(NC)"
	@cd lib/python && pytest tests/ -v

sdk-lint: ## Lint SDK source
	@echo "$(GREEN)[*] Linting SDK...$(NC)"
	@cd lib/python && ruff check secrets_sdk/

# === Local Dev Environment ===
dev-up: ## Start Docker Compose dev environment
	@echo "$(GREEN)[*] Starting dev environment...$(NC)"
	@cd dev && docker compose up -d

dev-down: ## Stop Docker Compose dev environment
	@echo "$(GREEN)[*] Stopping dev environment...$(NC)"
	@cd dev && docker compose down

dev-setup: ## Run Vault setup inside dev container
	@echo "$(GREEN)[*] Running Vault setup...$(NC)"
	@cd dev && docker compose exec vault /vault/setup.sh

dev-demo: ## Run interactive demo
	@echo "$(GREEN)[*] Running demo...$(NC)"
	@cd dev && ./demo.sh

dev-reset: ## Destroy and recreate dev environment
	@echo "$(YELLOW)[*] Resetting dev environment (volumes will be destroyed)...$(NC)"
	@cd dev && docker compose down -v && docker compose up -d

# === Operations ===
drill: ## Run break-glass drill
	@echo "$(GREEN)[*] Running break-glass drill...$(NC)"
	@./tools/drill/break_glass_drill.sh

inventory: ## Run non-human identity inventory scan
	@echo "$(GREEN)[*] Running identity inventory...$(NC)"
	@./tools/audit/identity_inventory.sh

rotate-check: ## Dry-run Vault secret rotation check
	@echo "$(GREEN)[*] Checking Vault secret rotation (dry-run)...$(NC)"
	@./tools/rotate/rotate_vault_secrets.sh --dry-run

rotate-sops: ## Dry-run SOPS key rotation check
	@echo "$(GREEN)[*] Checking SOPS key rotation (dry-run)...$(NC)"
	@./tools/rotate/rotate_sops_keys.sh --dry-run

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
