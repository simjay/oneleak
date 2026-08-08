.PHONY: install lint format format-check typecheck test test-cov \
        build publish publish-test docs-serve docs-build \
        precommit-install clean ci all

install:
	uv sync --all-extras

lint:
	uv run ruff check oneleak tests

format:
	uv run ruff format oneleak tests
	uv run ruff check --fix oneleak tests

format-check:
	uv run ruff format --check oneleak tests

typecheck:
	uv run mypy oneleak

test:
	uv run pytest

test-cov:
	uv run pytest --cov=oneleak --cov-report=term-missing

build:
	uv build

# Manual/local publish fallback. Primary path is the tag-triggered
# GitHub Actions trusted-publish workflow (.github/workflows/publish.yml).
# Requires UV_PUBLISH_TOKEN in the environment.
publish: build
	uv publish

publish-test: build
	uv publish --publish-url https://test.pypi.org/legacy/

docs-serve:
	uv run mkdocs serve

docs-build:
	uv run mkdocs build --strict

precommit-install:
	uv run pre-commit install

clean:
	rm -rf dist build *.egg-info .pytest_cache .mypy_cache .ruff_cache site

ci: lint format-check typecheck test

all: ci build
