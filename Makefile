.PHONY: help install install-dev lint format test coverage clean docker-up docker-down

help:
	@echo "Rex Auth Server - Available Commands"
	@echo "===================================="
	@echo "  make install          Install production dependencies"
	@echo "  make install-dev      Install development dependencies"
	@echo "  make lint             Run all linting checks (flake8, isort, black)"
	@echo "  make format           Format code with black and isort"
	@echo "  make test             Run tests with pytest"
	@echo "  make coverage         Run tests with coverage report"
	@echo "  make db-init          Initialize database migrations"
	@echo "  make db-migrate       Create migration"
	@echo "  make db-upgrade       Apply migrations"
	@echo "  make run              Run development server"
	@echo "  make clean            Remove cache files and directories"
	@echo "  make docker-build     Build Docker image"
	@echo "  make docker-up        Start Docker containers"
	@echo "  make docker-down      Stop Docker containers"

install:
	pip install -r requirements.txt

install-dev: install
	pip install -r requirements-dev.txt

lint:
	isort --check-only app tests
	black --check app tests
	flake8 app tests

format:
	isort app tests
	black app tests

test:
	pytest tests/ -v

coverage:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

db-init:
	flask db init

db-migrate:
	flask db migrate -m "auto"

db-upgrade:
	flask db upgrade

run:
	flask --app manage.py run --port 8000

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".coverage" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true

docker-build:
	docker build -t rex-auth-server:latest .

docker-up:
	docker compose up --build

docker-down:
	docker compose down

.DEFAULT_GOAL := help
