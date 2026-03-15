# Local development environment for developer identity & secrets management.
# Run 'make help' for available targets.

COMPOSE := docker compose
VAULT_CONTAINER := dev-vault

.PHONY: help up down setup demo logs clean reset status shell-vault shell-pg

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start the dev stack
	@cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) up -d
	@printf '\033[1;32mStack is up.\033[0m Waiting for services to be healthy...\n'
	@$(COMPOSE) exec vault vault status >/dev/null 2>&1 && \
		printf '\033[1;32mVault:\033[0m   http://localhost:8200/ui\n' || \
		printf '\033[1;33mVault:\033[0m   starting...\n'
	@$(COMPOSE) exec postgres pg_isready -U postgres >/dev/null 2>&1 && \
		printf '\033[1;32mPostgres:\033[0m localhost:5432\n' || \
		printf '\033[1;33mPostgres:\033[0m starting...\n'

down: ## Stop the dev stack
	$(COMPOSE) down

setup: ## Bootstrap Vault (engines, policies, AppRole, PKI, demo data)
	@printf '\033[1;34mBootstrapping Vault...\033[0m\n'
	$(COMPOSE) exec vault sh /vault/scripts/setup.sh

demo: ## Run the interactive demo (use 'make demo-auto' for non-interactive)
	@chmod +x demo.sh
	./demo.sh

demo-auto: ## Run the demo non-interactively
	@chmod +x demo.sh
	./demo.sh --auto

logs: ## Tail all service logs
	$(COMPOSE) logs -f

logs-vault: ## Tail Vault logs only
	$(COMPOSE) logs -f vault

logs-pg: ## Tail PostgreSQL logs only
	$(COMPOSE) logs -f postgres

clean: ## Stop stack and remove all volumes
	$(COMPOSE) down -v
	@printf '\033[1;33mVolumes removed.\033[0m Run make up && make setup to start fresh.\n'

reset: clean up ## Clean everything and re-bootstrap
	@sleep 3
	@$(MAKE) setup

status: ## Show service status and health
	$(COMPOSE) ps
	@printf '\n'
	@$(COMPOSE) exec vault vault status 2>/dev/null || printf '\033[1;31mVault not reachable\033[0m\n'

shell-vault: ## Open a shell in the Vault container
	$(COMPOSE) exec vault sh

shell-pg: ## Open psql in the PostgreSQL container
	$(COMPOSE) exec postgres psql -U postgres -d demo
