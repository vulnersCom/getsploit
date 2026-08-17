.PHONY: build check coverage format leaks lint release sync test

sync:
	uv sync --all-groups

format:
	uv run ruff check --fix .
	uv run ruff format .

lint:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy

leaks:
	uv run detect-secrets-hook $(shell git ls-files --cached --others --exclude-standard)  # pragma: allowlist secret

test:
	uv run pytest -q -n auto

coverage:
	uv run pytest -q -n auto --cov=getsploit --cov-branch --cov-report=term-missing --cov-fail-under=100

build:
	uv build --no-sources

release: check
	uv run twine check dist/*
	uv run check-wheel-contents dist/*.whl

check: leaks lint coverage build
