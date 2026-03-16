.PHONY: help setup validate scan lint audit test doctor tree clean diagrams \
       sdk-install sdk-test sdk-lint \
       sdk-install-go sdk-test-go sdk-lint-go \
       sdk-install-ts sdk-test-ts sdk-lint-ts \
       dev-up dev-down dev-setup dev-demo dev-reset dev-proxy \
       drill inventory rotate-check rotate-sops \
       sign verify ceremony-root ceremony-intermediate \
       scan-enhanced entropy-check test-integration \
       sirm-init sirm-status sirm-seal sirm-report \
       test-opa test-compliance test-bats \
       cert-inventory cert-monitor \
       compliance-matrix compliance-evidence \
       all-tests e2e all

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
	@echo "  $(GREEN)setup$(NC)                    Install pre-commit hooks and validate dependencies"
	@echo "  $(GREEN)doctor$(NC)                   Run secrets-doctor diagnostic tool"
	@echo "  $(GREEN)tree$(NC)                     Show repository structure"
	@echo ""
	@echo "$(CYAN)--- Validation & Security ---$(NC)"
	@echo "  $(GREEN)validate$(NC)                 Run all validation checks (scan + lint)"
	@echo "  $(GREEN)scan$(NC)                     Scan for plaintext secrets"
	@echo "  $(GREEN)scan-enhanced$(NC)            Run enhanced secret scanner with DLP patterns"
	@echo "  $(GREEN)entropy-check$(NC)            Run entropy-based high-risk detection"
	@echo "  $(GREEN)lint$(NC)                     Lint shell scripts and YAML"
	@echo "  $(GREEN)audit$(NC)                    Run full security audit"
	@echo ""
	@echo "$(CYAN)--- Testing ---$(NC)"
	@echo "  $(GREEN)test$(NC)                     Run OPA policy tests and compliance checks"
	@echo "  $(GREEN)test-opa$(NC)                 Run OPA policy tests only"
	@echo "  $(GREEN)test-compliance$(NC)          Run compliance control checks only"
	@echo "  $(GREEN)test-bats$(NC)                Run BATS shell tests"
	@echo "  $(GREEN)test-integration$(NC)         Run integration tests (SOPS, PKI, SSH CA, Transit)"
	@echo "  $(GREEN)e2e$(NC)                      Run end-to-end reference validation"
	@echo "  $(GREEN)all-tests$(NC)                Run ALL test suites (Python + Go + TS + BATS + OPA)"
	@echo "  $(GREEN)all$(NC)                      Full CI check (validate + test + e2e)"
	@echo ""
	@echo "$(CYAN)--- Python SDK ---$(NC)"
	@echo "  $(GREEN)sdk-install$(NC)              Install Python SDK in dev mode"
	@echo "  $(GREEN)sdk-test$(NC)                 Run Python SDK tests"
	@echo "  $(GREEN)sdk-lint$(NC)                 Lint Python SDK source"
	@echo ""
	@echo "$(CYAN)--- Go SDK ---$(NC)"
	@echo "  $(GREEN)sdk-install-go$(NC)           Download Go SDK dependencies"
	@echo "  $(GREEN)sdk-test-go$(NC)              Run Go SDK tests"
	@echo "  $(GREEN)sdk-lint-go$(NC)              Vet Go SDK source"
	@echo ""
	@echo "$(CYAN)--- TypeScript SDK ---$(NC)"
	@echo "  $(GREEN)sdk-install-ts$(NC)           Install TypeScript SDK dependencies"
	@echo "  $(GREEN)sdk-test-ts$(NC)              Run TypeScript SDK tests"
	@echo "  $(GREEN)sdk-lint-ts$(NC)              Lint TypeScript SDK source"
	@echo ""
	@echo "$(CYAN)--- Local Dev Environment ---$(NC)"
	@echo "  $(GREEN)dev-up$(NC)                   Start Docker Compose dev environment"
	@echo "  $(GREEN)dev-down$(NC)                 Stop Docker Compose dev environment"
	@echo "  $(GREEN)dev-setup$(NC)                Run Vault setup inside dev container"
	@echo "  $(GREEN)dev-demo$(NC)                 Run interactive demo"
	@echo "  $(GREEN)dev-reset$(NC)                Destroy and recreate dev environment"
	@echo "  $(GREEN)dev-proxy$(NC)                Start local Vault dev proxy"
	@echo ""
	@echo "$(CYAN)--- Signing & Ceremony ---$(NC)"
	@echo "  $(GREEN)sign$(NC)                     Sign artifacts using cosign/notation"
	@echo "  $(GREEN)verify$(NC)                   Verify artifact signatures"
	@echo "  $(GREEN)ceremony-root$(NC)            Run root CA key ceremony (dry-run by default)"
	@echo "  $(GREEN)ceremony-intermediate$(NC)    Run intermediate CA ceremony (dry-run by default)"
	@echo ""
	@echo "$(CYAN)--- SIRM Session Management ---$(NC)"
	@echo "  $(GREEN)sirm-init$(NC)                Bootstrap a new SIRM session"
	@echo "  $(GREEN)sirm-status$(NC)              Show current SIRM session status"
	@echo "  $(GREEN)sirm-report$(NC)              Generate SIRM session report"
	@echo "  $(GREEN)sirm-seal$(NC)                Seal current SIRM session (irreversible)"
	@echo ""
	@echo "$(CYAN)--- Compliance ---$(NC)"
	@echo "  $(GREEN)compliance-matrix$(NC)        Generate compliance control matrix"
	@echo "  $(GREEN)compliance-evidence$(NC)      Generate compliance evidence package"
	@echo ""
	@echo "$(CYAN)--- Certificate Management ---$(NC)"
	@echo "  $(GREEN)cert-inventory$(NC)           Scan and inventory all certificates"
	@echo "  $(GREEN)cert-monitor$(NC)             Monitor certificate expiry and alert"
	@echo ""
	@echo "$(CYAN)--- Operations ---$(NC)"
	@echo "  $(GREEN)drill$(NC)                    Run break-glass drill"
	@echo "  $(GREEN)inventory$(NC)                Run non-human identity inventory scan"
	@echo "  $(GREEN)rotate-check$(NC)             Dry-run Vault secret rotation check"
	@echo "  $(GREEN)rotate-sops$(NC)              Dry-run SOPS key rotation check"
	@echo ""
	@echo "$(CYAN)--- Housekeeping ---$(NC)"
	@echo "  $(GREEN)clean$(NC)                    Remove temporary and decrypted files"
	@echo "  $(GREEN)diagrams$(NC)                 Render Mermaid diagrams (requires mmdc)"
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
	@find . -name "*.sh" -not -path "./.git/*" -not -path "./.venv/*" -not -path "*/node_modules/*" -exec shellcheck -e SC1091 {} + 2>/dev/null || echo "$(YELLOW)[!] shellcheck not installed$(NC)"
	@echo "$(GREEN)[*] Validating YAML...$(NC)"
	@find . -name "*.yaml" -o -name "*.yml" | grep -v ".git" | grep -v "\.enc\." | grep -v "node_modules" | while read f; do python3 -c "import yaml; yaml.safe_load(open('$$f'))" 2>/dev/null || echo "$(RED)[!] Invalid YAML: $$f$(NC)"; done

# === Security Audit ===
audit: ## Run full security audit
	@echo "$(GREEN)[*] Running secrets-doctor audit...$(NC)"
	@./tools/secrets-doctor/doctor.sh audit

# === Testing ===
test: test-opa test-compliance ## Run OPA policy tests and compliance checks

test-opa: ## Run OPA policy tests
	@echo "$(GREEN)[*] Running OPA policy tests...$(NC)"
	@command -v opa >/dev/null 2>&1 && opa test tests/opa/ -v || echo "$(YELLOW)[!] OPA not installed$(NC)"

test-compliance: ## Run compliance control checks
	@echo "$(GREEN)[*] Running compliance checks...$(NC)"
	@./tests/compliance/check_controls.sh

test-bats: ## Run BATS shell tests
	@echo "$(GREEN)[*] Running BATS tests...$(NC)"
	@command -v bats >/dev/null 2>&1 && bats tests/unit/*.bats || echo "$(YELLOW)[!] BATS not installed — install with: brew install bats-core$(NC)"

test-integration: ## Run integration tests (SOPS, PKI, SSH CA, Transit)
	@echo "$(GREEN)[*] Running integration tests...$(NC)"
	@./tests/integration/run_all.sh

e2e: ## Run end-to-end reference validation
	@echo "$(GREEN)[*] Running E2E validation...$(NC)"
	@./tests/e2e/validate_reference.sh

all-tests: sdk-test sdk-test-go sdk-test-ts test-bats test-opa test-compliance ## Run ALL test suites
	@echo "$(GREEN)[ok] All test suites complete$(NC)"

all: validate test e2e ## Full CI check (validate + test + e2e)

# === Python SDK ===
sdk-install: ## Install Python SDK in dev mode
	@echo "$(GREEN)[*] Installing Python SDK...$(NC)"
	@cd lib/python && pip install -e ".[dev]"

sdk-test: ## Run Python SDK tests
	@echo "$(GREEN)[*] Running Python SDK tests...$(NC)"
	@cd lib/python && pytest tests/ -v

sdk-lint: ## Lint Python SDK source
	@echo "$(GREEN)[*] Linting Python SDK...$(NC)"
	@cd lib/python && ruff check secrets_sdk/

# === Go SDK ===
sdk-install-go: ## Download Go SDK dependencies
	@echo "$(GREEN)[*] Downloading Go SDK dependencies...$(NC)"
	@cd lib/go && go mod download

sdk-test-go: ## Run Go SDK tests
	@echo "$(GREEN)[*] Running Go SDK tests...$(NC)"
	@cd lib/go && go test ./... -v

sdk-lint-go: ## Vet Go SDK source
	@echo "$(GREEN)[*] Vetting Go SDK...$(NC)"
	@cd lib/go && go vet ./...

# === TypeScript SDK ===
sdk-install-ts: ## Install TypeScript SDK dependencies
	@echo "$(GREEN)[*] Installing TypeScript SDK dependencies...$(NC)"
	@cd lib/typescript && npm install

sdk-test-ts: ## Run TypeScript SDK tests
	@echo "$(GREEN)[*] Running TypeScript SDK tests...$(NC)"
	@cd lib/typescript && npm test

sdk-lint-ts: ## Lint TypeScript SDK source
	@echo "$(GREEN)[*] Linting TypeScript SDK...$(NC)"
	@cd lib/typescript && npx tsc --noEmit

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

dev-proxy: ## Start local Vault dev proxy
	@echo "$(GREEN)[*] Starting local Vault dev proxy...$(NC)"
	@./platform/local-dev/vault-dev-proxy.sh

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

# === Signing & Ceremony ===
sign: ## Sign artifacts using cosign/notation
	@echo "$(GREEN)[*] Signing artifacts...$(NC)"
	@./tools/signing/sign_artifact.sh

verify: ## Verify artifact signatures
	@echo "$(GREEN)[*] Verifying artifact signatures...$(NC)"
	@./tools/signing/verify_artifact.sh

ceremony-root: ## Run root CA key ceremony (dry-run by default)
	@echo "$(GREEN)[*] Running root CA ceremony (dry-run)...$(NC)"
	@./tools/ceremony/root_ca_ceremony.sh --dry-run

ceremony-intermediate: ## Run intermediate CA ceremony (dry-run by default)
	@echo "$(GREEN)[*] Running intermediate CA ceremony (dry-run)...$(NC)"
	@./tools/ceremony/intermediate_ca_ceremony.sh --dry-run

# === SIRM Session Management ===
sirm-init: ## Bootstrap a new SIRM session
	@echo "$(GREEN)[*] Bootstrapping SIRM session...$(NC)"
	@./tools/sirm/sirm-bootstrap.sh

sirm-status: ## Show current SIRM session status
	@./tools/sirm/sirm-session.sh status

sirm-report: ## Generate SIRM session report
	@echo "$(GREEN)[*] Generating SIRM session report...$(NC)"
	@./tools/sirm/sirm-session.sh report

sirm-seal: ## Seal current SIRM session (irreversible)
	@echo "$(YELLOW)[*] Sealing SIRM session (irreversible)...$(NC)"
	@./tools/sirm/sirm-session.sh seal

# === Enhanced Scanning ===
scan-enhanced: ## Run enhanced secret scanner with DLP patterns
	@echo "$(GREEN)[*] Running enhanced secret scan...$(NC)"
	@./tools/scanning/scan_repo.sh

entropy-check: ## Run entropy-based high-risk detection
	@echo "$(GREEN)[*] Running entropy-based detection...$(NC)"
	@./tools/scanning/entropy_check.sh

# === Compliance ===
compliance-matrix: ## Generate compliance control matrix
	@echo "$(GREEN)[*] Generating compliance control matrix...$(NC)"
	@./tools/compliance/control_matrix.sh

compliance-evidence: ## Generate compliance evidence package
	@echo "$(GREEN)[*] Generating compliance evidence...$(NC)"
	@./tools/compliance/generate_evidence.sh

# === Certificate Management ===
cert-inventory: ## Scan and inventory all certificates
	@echo "$(GREEN)[*] Running certificate inventory...$(NC)"
	@./tools/audit/cert_inventory.sh

cert-monitor: ## Monitor certificate expiry and alert
	@echo "$(GREEN)[*] Running certificate monitor...$(NC)"
	@./tools/audit/cert_monitor.sh

# === Diagnostics ===
doctor: ## Run secrets-doctor diagnostic tool
	@./tools/secrets-doctor/doctor.sh

tree: ## Show repository structure
	@find . -maxdepth 3 -not -path './.git/*' -not -path './node_modules/*' -not -path './.venv/*' -not -path '*/__pycache__/*' | sort | head -120

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
