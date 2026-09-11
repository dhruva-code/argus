# Argus — developer entrypoints
.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Stack ───────────────────────────────────────────────────────────────────
.PHONY: up
up: ## Start the full stack (postgres, redis, minio, gateway, orchestrator, web)
	$(COMPOSE) up -d --build
	@echo "web:      http://localhost:3000"
	@echo "api docs: http://localhost:8000/api/docs"

.PHONY: infra
infra: ## Start only backing services (postgres, redis, minio) for local dev
	$(COMPOSE) up -d postgres redis minio

.PHONY: down
down: ## Stop the stack (keeps volumes)
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and delete all data volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail logs from all services
	$(COMPOSE) logs -f

# ── Database ────────────────────────────────────────────────────────────────
.PHONY: migrate
migrate: ## Apply database migrations
	cd apis/gateway && alembic upgrade head

.PHONY: migration
migration: ## Create a new migration:  make migration m="add x table"
	cd apis/gateway && alembic revision --autogenerate -m "$(m)"

.PHONY: seed
seed: ## Load demo organization, admin user, and demo project
	cd apis/gateway && python -m app.seed

# ── Tests ───────────────────────────────────────────────────────────────────
.PHONY: test
test: test-api test-orch ## Run all test suites

.PHONY: test-api
test-api: ## Run gateway (Python) tests
	cd apis/gateway && pytest -q

.PHONY: test-orch
test-orch: ## Run orchestrator (Go) tests
	cd orchestrator && go test ./...

.PHONY: test-scope-parity
test-scope-parity: ## Verify Go and Python scope engines agree on the shared fixtures
	cd orchestrator && go test ./internal/scope -run TestFixtureParity -v
	cd apis/gateway && pytest -q tests/test_scope_parity.py

.PHONY: test-web
test-web: ## Type-check and lint the frontend
	cd web && npm run lint && npm run typecheck

# ── Lint ────────────────────────────────────────────────────────────────────
.PHONY: lint
lint: ## Lint everything
	cd apis/gateway && ruff check . && ruff format --check .
	cd orchestrator && gofmt -l . && go vet ./...
	cd web && npm run lint

.PHONY: fmt
fmt: ## Auto-format everything
	cd apis/gateway && ruff format . && ruff check --fix .
	cd orchestrator && gofmt -w .
	cd web && npm run format

# ── Build ───────────────────────────────────────────────────────────────────
.PHONY: build-orch
build-orch: ## Build the orchestrator binary to orchestrator/bin/orchestrator
	cd orchestrator && go build -o bin/orchestrator ./cmd/orchestrator

.PHONY: cli
cli: ## Install the argus CLI into the current environment
	cd cli && pip install -e .
