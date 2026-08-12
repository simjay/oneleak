PY := oneleaks tests scripts

# mkdocs-material prints an unconditional multi-line advocacy notice about
# MkDocs 2.0 on every invocation (see material/templates/__init__.py: it
# never checks the installed mkdocs version). It's red-on-stderr and reads
# like a build error in CI logs, but says nothing about this project. Our
# actual response to MkDocs 2.0 is the `mkdocs<2.0` pin in pyproject.toml.
# NO_MKDOCS_2_WARNING is the opt-out that same file provides.
export NO_MKDOCS_2_WARNING := true

.PHONY: install format lint test bench build publish publish-test \
        docs-serve docs-build docs-deploy clean ci

install:
	uv sync --all-extras
	uv run pre-commit install

format:
	uv run ruff format $(PY)
	uv run ruff check --fix $(PY)

lint:
	uv run ruff check $(PY)
	uv run ruff format --check $(PY)
	uv run mypy oneleaks

test:
	uv run pytest --cov=oneleaks --cov-report=term-missing

bench:
	uv run python scripts/benchmark.py

build:
	uv build

# Manual/local publish fallback. Primary path is the tag-triggered GitHub
# Actions trusted-publish workflow (.github/workflows/publish.yml), which
# needs no token. Requires UV_PUBLISH_TOKEN in the environment.
publish: build
	uv publish

publish-test: build
	uv publish --publish-url https://test.pypi.org/legacy/

docs-serve:
	uv run mkdocs serve

docs-build:
	uv run mkdocs build --strict

# Secondary docs host (GitHub Pages), the one actually driven by GitHub
# Actions (.github/workflows/docs.yml). The primary host is Read the Docs,
# which builds automatically from its own webhook once the repo is connected
# there (see .readthedocs.yaml). No CI step can trigger that directly.
docs-deploy:
	uv run mkdocs gh-deploy --force

clean:
	rm -rf dist build *.egg-info .pytest_cache .mypy_cache .ruff_cache .hypothesis site

ci: lint test docs-build
