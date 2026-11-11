.PHONY: up down db test smoke check

up: ## Start Postgres, run migrations and start the service
	docker compose up --build

down: ## Stop the stack and delete its data
	docker compose down --volumes

db: ## Start only Postgres, for running tests locally
	docker compose up -d postgres
	docker compose exec postgres psql -U gatehouse -d gatehouse -tc \
	  "SELECT 1 FROM pg_database WHERE datname = 'gatehouse_test'" | grep -q 1 || \
	  docker compose exec postgres createdb -U gatehouse gatehouse_test

test: ## Run the whole test suite (needs `make db`)
	pnpm test

smoke: ## Walk the main flows against the running stack (needs `make up`)
	./scripts/smoke.sh

check: ## Everything CI runs
	pnpm format:check && pnpm lint && pnpm typecheck && $(MAKE) test
