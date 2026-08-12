<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/lockup-on-dark.svg">
  <img src="docs/assets/lockup-on-light.svg" alt="oneleaks" width="560">
</picture>

[![PyPI](https://img.shields.io/pypi/v/oneleaks?style=flat-square)](https://pypi.org/project/oneleaks/)
[![Python](https://img.shields.io/pypi/pyversions/oneleaks?style=flat-square)](https://pypi.org/project/oneleaks/)
[![CI](https://img.shields.io/github/actions/workflow/status/simjay/oneleaks/ci.yml?branch=main&label=ci&style=flat-square)](https://github.com/simjay/oneleaks/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/readthedocs/oneleaks?style=flat-square)](https://oneleaks.readthedocs.io/)
[![License](https://img.shields.io/pypi/l/oneleaks?style=flat-square)](LICENSE)
[![Ruff](https://img.shields.io/badge/code_style-ruff-261230?style=flat-square)](https://github.com/astral-sh/ruff)

**One scanner for secrets *and* PII.** Most tools do one or the other. gitleaks and detect-secrets find credentials but ship no PII rules at all, so catching both normally means running two tools and merging two report formats. oneleaks finds both in a single pass, and redacts both with the same call.

```console
$ oneleaks scan .
[critical] openai-api-key (openai_api_key) at config.py:1 -- sk-p****aaa
[high] ssn (ssn) at seed.py:1 -- ***-**-6789
[high] credit-card (credit_card) at seed.py:2 -- ************1111
[low] email (email) at seed.py:3 -- a***@example.com
```

Every finding carries a `category` of `secret`, `pii`, or `sensitive`, so you can still route or filter them separately.

```python
secrets = [f for f in result.findings if f.category == "secret"]
pii     = [f for f in result.findings if f.category == "pii"]
```

It is lightweight and pure-Python, designed to run anywhere Python runs: agent workflows, pre-commit hooks, CI, and embedded pipelines. No external binary, no ML models, and no network calls required. The one exception is `git` itself, used only by `oneleaks.git`.

## Install

```bash
pip install oneleaks
pip install "oneleaks[mcp]"   # + MCP server for agent runtimes
```

Or from source:

```bash
git clone https://github.com/simjay/oneleaks && cd oneleaks
pip install -e ".[mcp]"
```

Requires Python >= 3.11.

## Python API

```python
import oneleaks

result = oneleaks.scan("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")
if not result.safe:
    for finding in result.findings:
        print(finding.rule_id, finding.severity, finding.preview)

safe = oneleaks.sanitize("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")
print(safe.text)
# OPENAI_API_KEY=<OPENAI_API_KEY_1>
# email=<EMAIL_1>
```

### Reversible sanitization

```python
result = oneleaks.sanitize(text, reveal=True)
restored = oneleaks.desanitize(result.text, result.mapping)  # restored == text
```

`result.mapping` is only populated with `reveal=True`, never by default.

### Git, including history

```python
oneleaks.git.scan_changed()   # working-tree changes + untracked files
oneleaks.git.scan_staged()    # staged (index) content
oneleaks.git.scan_history()   # commit history: finds secrets later removed from the tree
```

### Custom rules

```python
oneleaks.scan(text, rules=["company-rules.yaml"])
oneleaks.scan(text, rules=[MyPythonRule()])
```

## CLI

```bash
oneleaks scan .
oneleaks scan --changed
oneleaks scan --staged
oneleaks scan --history
oneleaks scan . --json
oneleaks scan . --fail-on high

# adopting oneleaks on a repo that already has findings: baseline them, fail only on new ones
oneleaks scan . --baseline .oneleaks-baseline.json --update-baseline
oneleaks scan . --baseline .oneleaks-baseline.json

some-command | oneleaks sanitize -
oneleaks sanitize file.txt --map mapping.json   # writes a reversible mapping (0600, never default)
oneleaks desanitize sanitized.txt --map mapping.json
```

Exit codes: `0` clean, `1` findings detected, `2` execution/configuration error.

## MCP server

```bash
oneleaks-mcp
```

Exposes `scan_text`, `scan_path`, `sanitize_text`, `desanitize_text` as MCP tools over stdio, for agent runtimes to call directly. See [docs/mcp.md](https://oneleaks.readthedocs.io/en/latest/mcp/).

## Config

`.oneleaks.yaml` in your project root:

```yaml
exclude:
  - "node_modules/**"
pii:
  ipv4: false
disabled_rules:
  - datadog-api-key
allow:
  paths:
    - "tests/fixtures/**"
```

## Development

```bash
uv sync --all-extras
make format   # ruff format + ruff check --fix
make lint     # ruff check + ruff format --check + mypy
make test     # pytest with coverage
make ci       # lint + test + docs-build (what GitHub Actions runs)
```
