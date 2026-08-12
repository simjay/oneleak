# Quickstart

## Install

```bash
pip install oneleaks
```

Add the MCP server if you want agent runtimes to call oneleaks directly:

```bash
pip install "oneleaks[mcp]"
```

Or from source:

```bash
git clone https://github.com/simjay/oneleaks && cd oneleaks
pip install -e ".[mcp]"
```

Requires Python 3.11 or newer.

## Your first scan

=== "CLI"

    ```bash
    oneleaks scan .
    ```

    Exit codes: `0` clean, `1` findings, `2` error. That's what makes it usable in CI.

=== "Python"

    ```python
    import oneleaks

    result = oneleaks.scan("OPENAI_API_KEY=sk-proj-...\nemail=alice@example.com")

    result.safe      # False
    result.risk      # "critical"
    result.findings  # list[Finding]
    ```

A `Finding` never carries the raw value. You get a masked `preview` like `sk-p****789`, plus an HMAC `fingerprint` for recognizing repeats.

## Scanning files and directories

```python
from pathlib import Path

oneleaks.scan(Path("config.yaml"))   # one file
oneleaks.scan(Path("."))             # whole tree
```

!!! warning "A `str` is always content, never a path"

    `oneleaks.scan("config.yaml")` scans those eleven characters. It does **not** open the file.

    Wrap filesystem input in `Path(...)`. Guessing whether a string is a path or a payload would silently read files when you meant to scan text.

Binary files and anything over 10 MB are skipped. Common noise directories like `.git/`, `node_modules/`, and `.venv/` are excluded automatically — the full list is in [Configuration](configuration.md#fields).

## Sanitizing

```python
safe = oneleaks.sanitize("Email alice@example.com twice: alice@example.com")
print(safe.text)
# Email <EMAIL_1> twice: <EMAIL_1>
```

The same value reuses the same placeholder within a call, so the text stays coherent.

To recover the originals later, see the reversible-mapping workflow in [Sanitization](sanitization.md).

## Scanning git

```python
oneleaks.git.scan_changed()  # working-tree changes + untracked files
oneleaks.git.scan_staged()   # staged content, which can differ from disk
oneleaks.git.scan_history()  # commits, including secrets since removed
```

`scan_changed()` is the core agent loop: scan after every edit, act on findings before continuing.

`scan_history()` catches what the others structurally can't — a secret committed last year and deleted since is still in the repo.

## Next steps

- [CLI Reference](cli.md) — every command and flag
- [Configuration](configuration.md) — `.oneleaks.yaml`
- [Baselines](configuration.md#baselines) — adopt oneleaks on a repo that already has findings
- [Custom Rules](rules.md) — extend detection without forking
- [MCP Server](mcp.md) — expose scan and sanitize to an agent
