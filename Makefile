.PHONY: help install test lint format clean check

help:
	@echo "Available commands:"
	@echo "  make install    - Install required dependencies"
	@echo "  make test       - Run tests with pytest"
	@echo "  make lint       - Run ruff linter, formatter check, mypy, and quality scale"
	@echo "  make format     - Run ruff formatter"
	@echo "  make check      - Run format check, lint, and test"
	@echo "  make clean      - Remove build and cache files"

install:
	pip install -r requirements_test.txt

test:
	pytest tests/ -v --cov=custom_components.issue_reporter --cov-report=term-missing

lint:
	ruff check .
	ruff format --check .
	mypy custom_components/issue_reporter
	python3 script/check_quality_scale.py

format:
	ruff format .

check: lint test

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache coverage.xml .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
