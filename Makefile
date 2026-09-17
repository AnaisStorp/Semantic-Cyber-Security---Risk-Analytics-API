# `make` alone lists the targets.

.DEFAULT_GOAL := help
.PHONY: help install lock fmt lint test cov check run api build up down clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Create .venv from uv.lock and install git hooks
	uv sync --locked
	uv run pre-commit install --hook-type pre-commit --hook-type pre-push

lock:  ## Update uv.lock after editing pyproject.toml
	uv lock

fmt:  ## Format the code
	uv run ruff format .
	uv run ruff check . --fix

lint:  ## Lint without changing anything
	uv run ruff check .
	uv run ruff format --check .

test:  ## Run the test suite
	uv run pytest -v

cov:  ## Run tests with a coverage report
	uv run pytest --cov=app --cov-report=term-missing --cov-report=html
	@echo "HTML report: htmlcov/index.html"

check: lint test  ## Lint and test, like CI

run:  ## Start the Streamlit dashboard
	uv run streamlit run streamlit_app.py

api:  ## Start the FastAPI server with autoreload
	uv run uvicorn app.main:app --reload

build:  ## Build the Docker image
	docker build -t scsra:local .

up:  ## Start dashboard + API with Docker Compose
	docker compose up --build

down:  ## Stop and remove the containers
	docker compose down

clean:  ## Remove caches and build artefacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage coverage.xml
