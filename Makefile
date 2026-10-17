# Convenience targets (Linux / macOS / Git Bash). See README for the Windows equivalents.
.PHONY: install dev test lint format check update up down logs build backup

install:        ## Install dependencies and the Chromium browser
	uv sync
	uv run playwright install chromium

dev:            ## Run the API with auto-reload on http://localhost:8000
	uv run uvicorn app.main:app --reload --port 8000

test:           ## Run the test suite
	uv run pytest -q

lint:           ## Lint (ruff)
	uv run ruff check .

format:         ## Format code (ruff)
	uv run ruff format .

check: lint test ## Lint and test

update:         ## Bump Python packages and tool pins to their latest releases
	uv run python scripts/update_deps.py

up:             ## Start the full stack with Docker Compose
	docker compose up -d

down:           ## Stop the stack
	docker compose down

logs:           ## Follow application logs
	docker compose logs -f app

build:          ## Rebuild the application image
	docker compose build --pull

backup:         ## Dump the database and data volume to backups/
	bash scripts/backup.sh
