# ATHAR — judge path is `make demo`. Every target is idempotent (second run is clean).
SHELL := /bin/bash
COMPOSE ?= docker compose
API_EXEC := $(COMPOSE) exec -T api

# The api container writes the generated estate and the exports into the ./data bind mount. The
# image gives /app/data to its own uid 10001, but a bind mount replaces that directory with the
# host's, and on Linux Docker creates a missing bind-mount source owned by root — so the container
# user cannot write it and `make seed` fails on a clean clone. Running the container as the calling
# user fixes it in both directions: the mount is writable, and everything the image ships is
# world-readable. Exported so `docker compose` interpolates them.
export ATHAR_UID ?= $(shell id -u)
export ATHAR_GID ?= $(shell id -g)
SCAN ?=
SEED ?=

# Advisories with no fix inside the pinned range, ignored by id with the reason in
# .github/workflows/ci.yml. Keep this list and the `security` job's flags identical.
PIP_AUDIT_IGNORES ?= --ignore-vuln PYSEC-2026-1845

.PHONY: help demo up down reset seed scan advance agent export verify types test test-backend test-frontend \
        test-contracts build-web eval eval-local eval-sample security contracts-artifact lint ci contracts-build \
        dev-api dev-web logs

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

demo: up seed ## Judge path: bring everything up, generate + ingest + scan 12 months, print URL and accounts
	@echo
	@echo "  ATHAR is up:  $${PUBLIC_URL:-http://localhost:8080}"
	@echo "  API docs:     http://localhost:8000/api/docs"
	@echo "  Accounts (password from .env):"
	@echo "    analyst@athar.local   analyst   (run scans, agents, uploads)"
	@echo "    approver@athar.local  approver  (approve / reject / apply remediation)"
	@echo "    judge@athar.local     viewer    (read-only)"
	@echo

up: ## Start db, anvil, api, web (builds images if not pulled)
	@test -f .env || cp .env.example .env
	@mkdir -p data
	$(COMPOSE) up -d --build --wait db anvil api web

down: ## Stop containers (keeps volumes)
	$(COMPOSE) down

reset: ## Stop and drop volumes (Postgres, Anvil state); next demo regenerates the identical estate
	$(COMPOSE) down -v
	rm -rf data/estate

seed: ## Generate the estate for ATHAR_SEED, ingest and scan every month (idempotent)
	$(API_EXEC) athar seed

scan: ## Diff + rules + score + attest for the current month
	$(API_EXEC) athar scan $(if $(SCAN),--month $(SCAN),)

advance: ## Simulate the next month, then scan it
	$(API_EXEC) athar generate --advance
	$(API_EXEC) athar ingest --latest
	$(API_EXEC) athar scan

agent: ## Run investigate / plan / summary on open findings (cache-aware)
	$(API_EXEC) athar agent run

export: ## Write CSV, JSON sidecar and PDF for the current scan into data/exports/
	$(API_EXEC) athar export --format csv --out data/exports/findings.csv
	$(API_EXEC) athar export --format json --out data/exports/findings.json
	$(API_EXEC) athar export --format pdf --out data/exports/findings.pdf

verify: ## Recompute the Merkle root for a scan and compare with the chain (SCAN=n)
	$(API_EXEC) athar verify $(if $(SCAN),--scan $(SCAN),)

types: ## Regenerate frontend API types from the running API's OpenAPI document
	cd frontend && npx openapi-typescript http://localhost:8000/api/openapi.json -o src/api/schema.d.ts

contracts-build: ## Compile the contract and refresh the committed ABI/bytecode artifact used by the API
	cd contracts && forge build --silent
	python3 scripts/sync_contract_artifact.py

test: test-backend test-frontend ## pytest + vitest

# Deliberately a superset of CI's `backend-tests` job, which runs `-m "not slow"` to keep a hosted
# runner under its time budget. Locally the slow markers (the 12-month estate shape and round-trip
# tests) are the ones most worth having, so this runs everything.
#
# `ATHAR_REQUIRE_INTEGRATION` is what makes a green run mean something: without it, an unreachable
# Postgres or Anvil skips about fifty tests and the suite still reports success, so this could pass
# on a machine that had never started a database. Set here, those become failures naming the
# `docker compose up` that fixes them. Run the bare `pytest` yourself when you want the skips.
test-backend:
	cd backend && ATHAR_REQUIRE_INTEGRATION=1 uv run pytest -q

test-frontend:
	cd frontend && npm run test --silent

test-contracts: ## forge test
	cd contracts && forge build --sizes && forge test -vv

contracts-artifact: ## CI's "Artifact in sync" check: the committed ABI/bytecode matches the source
	cd contracts && forge build --silent
	python3 scripts/sync_contract_artifact.py
	git diff --exit-code -- backend/athar/ledger/artifacts/

build-web: ## Production bundle (CI's `frontend` job builds it; a type error only the build sees fails here)
	cd frontend && npm run build

eval: ## Precision / recall vs ground truth: ATHAR_SEED, then ATHAR_EVAL_SEED (both from .env)
	$(API_EXEC) athar eval
	$(API_EXEC) athar eval --held-out --report

eval-sample: ## CI's `eval` job: the SPEC §17 gates on the two small sample estates (rebuilt here)
	cd backend && uv run athar eval --sample 42 --gate && uv run athar eval --sample 7 --gate

security: ## CI's `security` job: pip-audit over the lock, npm audit over what ships, gitleaks
	@set -euo pipefail; \
	  req="$$(mktemp "$${TMPDIR:-/tmp}/athar-audit-XXXXXX")"; \
	  trap 'rm -f "$$req"' EXIT; \
	  cd backend; \
	  uv export --frozen --all-groups --no-emit-project > "$$req"; \
	  uv run pip-audit --strict --desc on --require-hashes -r "$$req" $(PIP_AUDIT_IGNORES)
	cd frontend && npm audit --audit-level=high
	@if command -v gitleaks >/dev/null 2>&1; then \
	  gitleaks detect --no-banner --redact; \
	else \
	  echo "  gitleaks not installed — skipped locally; CI's security job always runs it over the"; \
	  echo "  full history (gitleaks/gitleaks-action). Install it with 'brew install gitleaks'."; \
	fi

lint: ## ruff, mypy, eslint, forge fmt --check
	cd backend && uv run ruff format --check . && uv run ruff check . && uv run mypy athar
	cd frontend && npm run lint --silent && npm run typecheck --silent
	cd contracts && forge fmt --check

# Every GitHub Actions job, in the same order: lint · backend-tests · frontend · contracts ·
# eval · security · compose-config. `publish-images` is not here — it needs a GHCR token and
# only runs on `main`. Everything above compose-config runs without Docker.
ci: lint test build-web test-contracts contracts-artifact eval-sample security ## Everything GitHub Actions runs
	@if command -v docker >/dev/null 2>&1; then \
	  test -f .env || cp .env.example .env; \
	  $(COMPOSE) config -q && echo "  compose config valid"; \
	else \
	  echo "  docker CLI not installed — skipping 'docker compose config' (CI's compose-config job runs it)"; \
	fi

dev-api: ## Run the API on the host with reload (db + anvil from compose)
	cd backend && uv run uvicorn athar.services.wiring:create_app --factory --reload --port 8000

dev-web: ## Vite dev server proxying /api to localhost:8000
	cd frontend && npm run dev

# --- host fallback (no Docker) ------------------------------------------------
# `make demo` is the documented judge path. These targets do the same work against a
# Postgres and an Anvil already running on the host, for a machine where Docker is
# unavailable. They need: uv, Foundry (anvil), Node 22, and Postgres reachable at
# DATABASE_URL. See README "Running without Docker".

.PHONY: demo-local seed-local api-local web-local anvil-local scan-local advance-local agent-local \
        export-local verify-local reset-local

demo-local: seed-local ## Same pipeline as `make demo`, against host Postgres + Anvil
	@echo
	@echo "  Estate seeded. Start the two servers in separate shells:"
	@echo "    make api-local     # the API"
	@echo "    make web-local     # the dashboard"
	@echo
	@echo "  ATHAR is then up:  http://localhost:5173"
	@echo "  API docs:          http://localhost:8000/api/docs"
	@echo "  Accounts (password from .env):"
	@echo "    analyst@athar.local   analyst   (run scans, agents, uploads)"
	@echo "    approver@athar.local  approver  (approve / reject / apply remediation)"
	@echo "    judge@athar.local     viewer    (read-only)"
	@echo

anvil-local: ## Start a local Anvil node with persistent state
	anvil --port 8545 --chain-id 31337 --block-time 1 --state data/anvil-state.json

seed-local: ## Migrate, seed users, generate, ingest and scan every month on the host
	cd backend && uv run athar seed

api-local: ## Run the API on the host (migrations, ledger deploy and user seeding on startup)
	cd backend && uv run athar serve

web-local: ## Vite dev server against the host API
	cd frontend && npm run dev

scan-local: ## Diff + rules + score + attest for the current month, on the host
	cd backend && uv run athar scan $(if $(SCAN),--month $(SCAN),)

advance-local: ## Simulate the next month, then scan it, on the host
	cd backend && uv run athar generate --advance
	cd backend && uv run athar ingest --latest
	cd backend && uv run athar scan

agent-local: ## Run investigate / plan / summary on open findings, on the host
	cd backend && uv run athar agent run

eval-local: ## Precision / recall on the host: ATHAR_SEED, then ATHAR_EVAL_SEED (both from .env)
	cd backend && uv run athar eval
	cd backend && uv run athar eval --held-out --report

export-local: ## Write CSV, JSON sidecar and PDF into data/exports/, on the host
	cd backend && uv run athar export --format csv --out ../data/exports/findings.csv
	cd backend && uv run athar export --format json --out ../data/exports/findings.json
	cd backend && uv run athar export --format pdf --out ../data/exports/findings.pdf

verify-local: ## Recompute the Merkle root for a scan and compare with the chain (SCAN=n), on the host
	cd backend && uv run athar verify $(if $(SCAN),--scan $(SCAN),)

reset-local: ## Drop the host schema and the generated estate; next demo-local regenerates the identical one
	cd backend && uv run python -c "from alembic import command; from athar.db.migrate import alembic_config; command.downgrade(alembic_config(), 'base')"
	rm -rf data/estate data/anvil-state.json

logs:
	$(COMPOSE) logs -f --tail=100 api
