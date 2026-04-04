.PHONY: help install install-dev test lint format security clean run

# Default target
help:
	@echo "RepoSentinel - GitHub Security Scanner"
	@echo ""
	@echo "Available commands:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  test         Run tests with coverage"
	@echo "  lint         Run linting (flake8, mypy, bandit)"
	@echo "  format       Format code (black, isort)"
	@echo "  security     Run security checks (safety, bandit)"
	@echo "  clean        Clean cache and build artifacts"
	@echo "  run          Run the scanner"
	@echo ""

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev,security]"
	pre-commit install

# Development
test:
	pytest --cov=. --cov-report=html --cov-report=term

lint:
	ruff check .
	mypy .

format:
	ruff format .

# Security
security:
	pip-audit
	bandit -r . -f json -o bandit-report.json || true

# Docker
docker-build:
	docker build -t repo-sentinel .

docker-run:
	docker run --rm -it --env-file .env repo-sentinel --help

# Maintenance
clean:
	rm -rf `find . -name __pycache__`
	rm -rf `find . -name "*.pyc"`
	rm -rf *.egg-info
	rm -rf .ruff_cache
	rm -rf build/
	rm -rf dist/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# Running the application
run:
	python src/main.py --help

# Development workflow
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify everything works."

# CI/CD helpers
ci-test:
	pytest --cov=. --cov-report=xml

ci-lint:
	ruff check .
	mypy .

ci-security:
	safety check
	bandit -r . -f json -o bandit-report.json

# Build and distribution
build:
	python -m build

upload-test:
	python -m twine upload --repository testpypi dist/*

upload:
	python -m twine upload dist/*
