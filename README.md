# oneleak

oneleak is a lightweight, pure-Python scanner and sanitizer for secrets and PII, designed to run anywhere Python runs -- agent workflows, pre-commit hooks, CI, and embedded pipelines. No external binary, no ML models, no network calls required (the one exception: `git` itself, used only by `oneleak.git`).

Full docs: **[oneleak.readthedocs.io](https://oneleak.readthedocs.io/)** — [architecture](https://oneleak.readthedocs.io/architecture/) explains the detection pipeline and sanitization algorithm in detail.

## Install

```bash
pip install oneleak
pip install "oneleak[mcp]"   # + MCP server for agent runtimes
```

Or from source:

```bash
git clone https://github.com/simjay/oneleak && cd oneleak
pip install -e ".[mcp]"
```

Requires Python >= 3.11.

## Python API

```python
import oneleak

result = oneleak.scan("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")
if not result.safe:
    for finding in result.findings:
        print(finding.rule_id, finding.severity, finding.preview)

safe = oneleak.sanitize("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")
print(safe.text)
# OPENAI_API_KEY=<OPENAI_API_KEY_1>
# email=<EMAIL_1>
```

### Reversible sanitization

```python
result = oneleak.sanitize(text, reveal=True)
restored = oneleak.desanitize(result.text, result.mapping)  # restored == text
```

`result.mapping` is only populated with `reveal=True` -- never by default.

### Git, including history

```python
oneleak.git.scan_changed()   # working-tree changes + untracked files
oneleak.git.scan_staged()    # staged (index) content
oneleak.git.scan_history()   # commit history -- finds secrets later removed from the tree
```

### Custom rules

```python
oneleak.scan(text, rules=["company-rules.yaml"])
oneleak.scan(text, rules=[MyPythonRule()])
```

## CLI

```bash
oneleak scan .
oneleak scan --changed
oneleak scan --staged
oneleak scan --history
oneleak scan . --json
oneleak scan . --fail-on high

some-command | oneleak sanitize -
oneleak sanitize file.txt --map mapping.json   # writes a reversible mapping (0600, never default)
oneleak desanitize sanitized.txt --map mapping.json
```

Exit codes: `0` clean, `1` findings detected, `2` execution/configuration error.

## MCP server

```bash
oneleak-mcp
```

Exposes `scan_text`, `scan_path`, `sanitize_text`, `desanitize_text` as MCP tools over stdio, for agent runtimes to call directly. See [docs/mcp.md](https://oneleak.readthedocs.io/mcp/).

## Config

`.oneleak.yaml` in your project root:

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
make ci       # lint + test + docs-build -- what GitHub Actions runs
```

See [AGENTS.md](AGENTS.md) for a repo orientation aimed at coding agents, [CONTRIBUTING.md](CONTRIBUTING.md) for the human contribution guide, and [docs/](https://oneleak.readthedocs.io/) for full documentation.
