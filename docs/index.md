# oneleaks

A lightweight, **pure-Python** scanner and sanitizer for secrets and PII.

It runs anywhere Python runs: local development, pre-commit hooks, CI, and agent workflows.

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

## What it finds

| Category | Examples |
|---|---|
| **Secrets** | Provider API keys, generic credential assignments, high-entropy tokens, private keys, JWTs, connection strings |
| **PII** | Email, phone, SSN, credit card, IPv4/IPv6, IBAN, IMEI, MAC address, routing numbers |
| **Your own** | Custom YAML, JSON, or Python rules |

Detection is deterministic. No external binary, no network service, no ML model.

## Why oneleaks

**Pure Python.** `pip install oneleaks` and go. No Go binary, no Docker image.

**One scanner for secrets *and* PII.** Most tools pick one. oneleaks does both in a single pass.

**Sanitization is first-class.** `sanitize()` replaces values with typed, numbered placeholders like `<EMAIL_1>`, and can optionally export a reversible mapping.

**Agent-friendly.** Fast enough to run on every agent turn, with JSON output, stdin/stdout piping, and `git.scan_changed()` for "what did the agent just touch?"

## Where to go next

**Start here**

- [Quickstart](quickstart.md) — install, first scan, first sanitize
- [Configuration](configuration.md) — `.oneleaks.yaml`, and adopting oneleaks on an existing codebase

**Using it**

- [CLI Reference](cli.md) — every command and flag
- [Custom Rules](rules.md) — add your own patterns
- [Sanitization](sanitization.md) — the reversible-mapping workflow
- [MCP Server](mcp.md) — expose oneleaks to agent runtimes

**Understanding it**

- [How Scanning & Sanitization Work](architecture.md) — the pipeline, stage by stage
- [Concepts](concepts.md) — entropy, validators, fingerprinting, and the reasoning behind the design
- [API Reference](api.md) — generated from docstrings
