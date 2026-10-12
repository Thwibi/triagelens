# TriageLens task runner.
#
# `make` is not installed everywhere, so scripts/task.py is the single source of
# truth for every target below. Keep the two in sync; the Makefile only forwards.

PYTHON ?= python
TASK := $(PYTHON) scripts/task.py

.DEFAULT_GOAL := help
.PHONY: help install backend-install frontend-install lint typecheck test build all \
        backend-lint backend-format backend-typecheck backend-test backend-coverage \
        frontend-lint frontend-typecheck frontend-test frontend-build e2e \
        frontend-budget \
        backend-lock lock-check scripts-lint dev backend-run docker-build clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install all dependencies
	$(TASK) install

backend-install: ## Install the backend and its dev extras
	$(TASK) backend-install

frontend-install: ## Install pinned frontend dependencies
	$(TASK) frontend-install

lint: ## Lint backend and frontend
	$(TASK) lint

typecheck: ## Type-check backend and frontend
	$(TASK) typecheck

test: ## Test backend and frontend
	$(TASK) test

all: ## Run every quality gate
	$(TASK) all

build: ## Install, check and build for production
	$(TASK) build

backend-lint: ## Lint the backend
	$(TASK) backend-lint

scripts-lint: ## Lint the repository tooling
	$(TASK) scripts-lint

backend-format: ## Format the backend
	$(TASK) backend-format

backend-typecheck: ## Type-check the backend
	$(TASK) backend-typecheck

backend-test: ## Test the backend
	$(TASK) backend-test

backend-coverage: ## Test the backend under coverage
	$(TASK) backend-coverage

perf: ## Run the benchmarks and record docs/perf-results.md
	$(TASK) perf

perf-e2e: ## Run the spec 09 section 8 targets (SCALE=full|smoke)
	TRIAGELENS_PERF_SCALE=$(SCALE) $(TASK) perf-e2e

package: ## Build the offline install bundle into dist/
	$(TASK) package

backend-lock: ## Regenerate the hashed runtime lockfile
	$(TASK) backend-lock

lock-check: ## Fail if the lockfile has drifted from pyproject
	$(TASK) lock-check

frontend-lint: ## Lint the frontend
	$(TASK) frontend-lint

frontend-typecheck: ## Type-check the frontend
	$(TASK) frontend-typecheck

frontend-test: ## Test the frontend
	$(TASK) frontend-test

frontend-build: ## Build the frontend into backend/app/static
	$(TASK) frontend-build

e2e: ## Build the app and run the browser E2E suite (Playwright)
	$(TASK) e2e

frontend-budget: ## Enforce the spec 07 bundle-size budget on the built frontend
	$(TASK) frontend-budget

dev: ## Run the Vite dev server with the API proxied
	$(TASK) dev

backend-run: ## Serve the API and built frontend
	$(TASK) backend-run

docker-build: ## Build the production image
	$(TASK) docker-build

clean: ## Remove build output and caches
	rm -rf backend/app/static frontend/node_modules/.vite
	find . -name __pycache__ -type d -prune -exec rm -rf {} +