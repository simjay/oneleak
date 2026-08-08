# Quickstart

## Install

```bash
pip install oneleak
pip install "oneleak[mcp]"   # + MCP server for agent runtimes
```

Requires Python >= 3.11.

## Scan text

```python
import oneleak

result = oneleak.scan("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")

result.safe      # False
result.risk      # "critical"
result.findings  # list[Finding]
```

Each `Finding` never carries the raw sensitive value — only a masked `preview` (`sk-p****789`) and an HMAC-based `fingerprint` you can use to recognize repeats.

## Scan files and directories

```python
from pathlib import Path

oneleak.scan(Path("config.yaml"))
oneleak.scan(Path("."))
```

Binary files and files over 10 MB are skipped automatically. `.git/`, `node_modules/`, `.venv/`, `venv/`, `__pycache__/`, `dist/`, and `build/` are excluded by default.

## Sanitize

```python
safe = oneleak.sanitize("Email alice@example.com twice: alice@example.com")
print(safe.text)
# Email <EMAIL_1> twice: <EMAIL_1>
```

Repeated values reuse the same placeholder within one call. See [Sanitization](sanitization.md) for the reversible-mapping (`reveal=True` / `desanitize()`) workflow.

## Scan git changes

```python
oneleak.git.scan_changed()  # working-tree changes + untracked files
oneleak.git.scan_staged()   # staged (index) content, not the working-tree version
oneleak.git.scan_history()  # commit history -- finds secrets later removed from the tree
```

This is the core "did the agent just leak something" loop: scan after every edit, act on findings before continuing.

## Next steps

- [CLI Reference](cli.md) for `oneleak scan` / `sanitize` / `desanitize`
- [Configuration](configuration.md) for `.oneleak.yaml`
- [Custom Rules](rules.md) to extend detection without forking the library
- [MCP Server](mcp.md) to expose scan/sanitize as tools for an agent runtime
- [How Scanning & Sanitization Work](architecture.md) for the detection pipeline in detail
