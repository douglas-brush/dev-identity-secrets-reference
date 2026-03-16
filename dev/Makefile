# Local development environment for developer identity & secrets management.
# Run 'make help' for available targets.

COMPOSE := docker compose
VAULT_CONTAINER := dev-vault

.PHONY: help up down setup demo logs clean reset status shell-vault shell-pg \
        monitoring-up monitoring-down grafana prometheus seed-demo-data \
        logs-vault logs-pg demo-auto agent-logs agent-secrets

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start the dev stack (Vault + PostgreSQL + Vault Agent)
	@cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) up -d
	@printf '\033[1;32mStack is up.\033[0m Waiting for services to be healthy...\n'
	@$(COMPOSE) exec vault vault status >/dev/null 2>&1 && \
		printf '\033[1;32mVault:\033[0m        http://localhost:8200/ui\n' || \
		printf '\033[1;33mVault:\033[0m        starting...\n'
	@$(COMPOSE) exec postgres pg_isready -U postgres >/dev/null 2>&1 && \
		printf '\033[1;32mPostgres:\033[0m     localhost:5432\n' || \
		printf '\033[1;33mPostgres:\033[0m     starting...\n'
	@printf '\033[1;32mVault Agent:\033[0m  http://localhost:8100 (proxy)\n'

down: ## Stop the dev stack
	$(COMPOSE) down
	$(COMPOSE) --profile monitoring down 2>/dev/null || true

setup: ## Bootstrap Vault (engines, policies, AppRole, PKI, demo data)
	@printf '\033[1;34mBootstrapping Vault...\033[0m\n'
	$(COMPOSE) exec vault sh /vault/scripts/setup.sh

demo: ## Run the interactive demo (use 'make demo-auto' for non-interactive)
	@chmod +x demo.sh
	./demo.sh

demo-auto: ## Run the demo non-interactively
	@chmod +x demo.sh
	./demo.sh --auto

seed-demo-data: ## Seed Vault with realistic demo data (KV, DB roles, PKI, Transit, AppRole)
	@chmod +x scripts/seed-demo-data.sh
	./scripts/seed-demo-data.sh

logs: ## Tail all service logs
	$(COMPOSE) logs -f

logs-vault: ## Tail Vault logs only
	$(COMPOSE) logs -f vault

logs-pg: ## Tail PostgreSQL logs only
	$(COMPOSE) logs -f postgres

agent-logs: ## Tail Vault Agent logs
	$(COMPOSE) logs -f vault-agent

agent-secrets: ## Show rendered secrets from Vault Agent
	@docker exec dev-vault-agent sh -c 'ls -la /tmp/secrets/ 2>/dev/null && echo "---" && cat /tmp/secrets/*.json 2>/dev/null || echo "No secrets rendered yet"'

# ── Monitoring ──────────────────────────────────────────────────────

monitoring-up: ## Start monitoring stack (Prometheus + Grafana)
	@cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) --profile monitoring up -d
	@printf '\033[1;32mMonitoring stack is up.\033[0m\n'
	@printf '\033[1;32mPrometheus:\033[0m   http://localhost:9090\n'
	@printf '\033[1;32mGrafana:\033[0m      http://localhost:3000 (admin/admin)\n'

monitoring-down: ## Stop monitoring stack
	$(COMPOSE) --profile monitoring down

grafana: ## Open Grafana in the default browser
	@open http://localhost:3000/d/vault-health-dev/vault-health-operations 2>/dev/null || \
		xdg-open http://localhost:3000/d/vault-health-dev/vault-health-operations 2>/dev/null || \
		printf 'Open http://localhost:3000/d/vault-health-dev/vault-health-operations\n'

prometheus: ## Open Prometheus in the default browser
	@open http://localhost:9090 2>/dev/null || \
		xdg-open http://localhost:9090 2>/dev/null || \
		printf 'Open http://localhost:9090\n'

# ── Lifecycle ───────────────────────────────────────────────────────

clean: ## Stop stack and remove all volumes
	$(COMPOSE) --profile monitoring down -v 2>/dev/null || $(COMPOSE) down -v
	@printf '\033[1;33mVolumes removed.\033[0m Run make up && make setup to start fresh.\n'

reset: clean up ## Clean everything and re-bootstrap
	@sleep 3
	@$(MAKE) setup

status: ## Show service status and health
	$(COMPOSE) ps
	@$(COMPOSE) --profile monitoring ps 2>/dev/null || true
	@printf '\n'
	@$(COMPOSE) exec vault vault status 2>/dev/null || printf '\033[1;31mVault not reachable\033[0m\n'

shell-vault: ## Open a shell in the Vault container
	$(COMPOSE) exec vault sh

shell-pg: ## Open psql in the PostgreSQL container
	$(COMPOSE) exec postgres psql -U postgres -d demo
