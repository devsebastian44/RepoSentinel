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
	flake8 . --max-line-length=88 --extend-ignore=E203,W503
	mypy .
	bandit -r . -f json -o bandit-report.json || true

format:
	black .
	isort .

# Security
security:
	safety check
	bandit -r . -f json -o bandit-report.json || true

# Maintenance
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# Running the application
run:
	python main.py --help

# Development workflow
dev-setup: install-dev
	@echo "Development environment setup complete!"
	@echo "Run 'make test' to verify everything works."

# CI/CD helpers
ci-test:
	pytest --cov=. --cov-report=xml

ci-lint:
	flake8 . --max-line-length=88 --extend-ignore=E203,W503
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
