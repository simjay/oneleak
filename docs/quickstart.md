# Quickstart

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

## Scan text

```python
import oneleaks

result = oneleaks.scan("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")

result.safe      # False
result.risk      # "critical"
result.findings  # list[Finding]
```

Each `Finding` never carries the raw sensitive value, only a masked `preview` (`sk-p****789`) and an HMAC-based `fingerprint` you can use to recognize repeats.

## Scan files and directories

```python
from pathlib import Path

oneleaks.scan(Path("config.yaml"))
oneleaks.scan(Path("."))
```

!!! warning "A `str` is always content, never a path"

    `oneleaks.scan("config.yaml")` scans the eleven characters `config.yaml`. It does **not** open that file. Wrap filesystem input in `Path(...)`, as above. This is deliberate: guessing whether a string is a path or a payload would silently read files when you meant to scan text.

Binary files and files over 10 MB are skipped automatically. `.git/`, `node_modules/`, `.venv/`, `venv/`, `__pycache__/`, `dist/`, and `build/` are excluded by default.

## Sanitize

```python
safe = oneleaks.sanitize("Email alice@example.com twice: alice@example.com")
print(safe.text)
# Email <EMAIL_1> twice: <EMAIL_1>
```

Repeated values reuse the same placeholder within one call. See [Sanitization](sanitization.md) for the reversible-mapping (`reveal=True` / `desanitize()`) workflow.

## Scan git changes

```python
oneleaks.git.scan_changed()  # working-tree changes + untracked files
oneleaks.git.scan_staged()   # staged (index) content, not the working-tree version
oneleaks.git.scan_history()  # commit history: finds secrets later removed from the tree
```

This is the core "did the agent just leak something" loop: scan after every edit, act on findings before continuing.

## Next steps

- [CLI Reference](cli.md) for `oneleaks scan` / `sanitize` / `desanitize`
- [Configuration](configuration.md) for `.oneleaks.yaml`
- [Baselines](configuration.md#baselines) to adopt oneleaks on a repo that already has findings, without a blocking flag-day
- [Custom Rules](rules.md) to extend detection without forking the library
- [MCP Server](mcp.md) to expose scan/sanitize as tools for an agent runtime
- [How Scanning & Sanitization Work](architecture.md) for the detection pipeline in detail
- [Concepts](concepts.md) for the field knowledge behind the design (entropy, validators, fingerprinting, and why some competitor techniques weren't adopted)
