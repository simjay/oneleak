# oneleak

oneleak is a lightweight, pure-Python scanner and sanitizer for secrets and PII, designed to run anywhere Python runs -- agent workflows, pre-commit hooks, CI, and embedded pipelines. No external binary, no ML models, no network calls required.

## Install

```bash
pip install -e .           # from a checkout, for now (not yet published to PyPI)
pip install -e ".[pii-ml]" # optional Presidio-backed PII detection
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

### Git

```python
oneleak.git.scan_changed()  # working-tree changes + untracked files
oneleak.git.scan_staged()   # staged (index) content
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
oneleak scan . --json
oneleak scan . --fail-on high

some-command | oneleak sanitize -
oneleak sanitize file.txt --map mapping.json   # writes a reversible mapping (0600, never default)
oneleak desanitize sanitized.txt --map mapping.json
```

Exit codes: `0` clean, `1` findings detected, `2` execution/configuration error.

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
uv sync
uv run pytest
uv run ruff check oneleak tests
uv run mypy oneleak
```

See `.plan/prd.md`, `.plan/spec.md`, and `.plan/plan.md` for the full design, and `.plan/concepts.md` for background on the detection techniques used.
