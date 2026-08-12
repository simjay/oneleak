# oneleaks

oneleaks is a lightweight, pure-Python scanner and sanitizer for secrets and PII, designed to run anywhere Python runs: agent workflows, pre-commit hooks, CI, and embedded pipelines. No external binary, no ML models, no network calls required (the one exception: `git` itself, used only by `oneleaks.git`).

Full docs: **[oneleaks.readthedocs.io](https://oneleaks.readthedocs.io/)**. The [architecture](https://oneleaks.readthedocs.io/architecture/) page explains the detection pipeline and sanitization algorithm in detail.

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

Exposes `scan_text`, `scan_path`, `sanitize_text`, `desanitize_text` as MCP tools over stdio, for agent runtimes to call directly. See [docs/mcp.md](https://oneleaks.readthedocs.io/mcp/).

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

See [AGENTS.md](AGENTS.md) for a repo orientation aimed at coding agents, [CONTRIBUTING.md](CONTRIBUTING.md) for the human contribution guide, and [docs/](https://oneleaks.readthedocs.io/) for full documentation.
