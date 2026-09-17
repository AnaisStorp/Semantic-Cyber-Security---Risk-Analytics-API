# Self-documenting task runner. `make` alone prints the available targets.

.DEFAULT_GOAL := help
.PHONY: help install fmt lint test cov check run api build up down clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'


install:  ## Create the venv and install all dependencies
	python3 -m venv .venv
	./.venv/bin/python -m pip install --upgrade pip
	./.venv/bin/python -m pip install -r requirements-dev.txt
	./.venv/bin/pre-commit install

fmt:  ## Format the code
	ruff format .
	ruff check . --fix

lint:  ## Lint without changing anything (what CI runs)
	ruff check .
	ruff format --check .

test:  ## Run the test suite
	pytest -v

cov:  ## Run tests with a coverage report
	pytest --cov=app --cov-report=term-missing --cov-report=html
	@echo "HTML report: htmlcov/index.html"

check: lint test  ## Lint and test. run this before pushing

run:  ## Start the Streamlit dashboard
	streamlit run streamlit_app.py

api:  ## Start the FastAPI server with autoreload
	uvicorn app.main:app --reload

build:  ## Build the Docker image
	docker build -t scsra:local .

up:  ## Start dashboard + API with Docker Compose
	docker compose up --build

down:  ## Stop and remove the containers
	docker compose down

clean:  ## Remove caches and build artefacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache htmlcov .coverage
