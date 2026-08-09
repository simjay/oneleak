# oneleak

oneleak is a lightweight, **pure-Python** sensitive-data scanner and sanitizer, designed to run anywhere Python runs: local development, pre-commit hooks, CI, and agent workflows.

It provides one scanning engine for:

- **Secrets and credentials**: provider-specific API keys, generic credential assignments, high-entropy tokens, private keys, JWTs, connection strings
- **PII**: email, phone, SSN, credit card, IPv4/IPv6, IBAN
- **Custom sensitive information**: your own YAML, JSON, or Python rules

Core detection is deterministic: no external binary, no network service, no ML model required.

## Why oneleak

- **Pure Python.** `pip install oneleak` and go: no Go binary, no Docker image.
- **One scanner for secrets and PII.** Most tools pick one. oneleak does both in a single pass.
- **Sanitization is first-class, not an afterthought.** `oneleak.sanitize()` redacts with typed, numbered placeholders (`<EMAIL_1>`, `<OPENAI_API_KEY_1>`), and can optionally export a reversible mapping.
- **Agent-friendly.** Fast enough to invoke on every agent turn, with JSON output, stdin/stdout, and `oneleak.git.scan_changed()` for "what did the agent just touch."

## Quick example

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

See [Quickstart](quickstart.md) to get started, or the [CLI Reference](cli.md) for command-line usage.

## Documentation

- **[Getting Started](quickstart.md)**: install, first scan, first sanitize
- **[Guides](cli.md)**: CLI reference, custom rules, sanitization, the MCP server
- **[Advanced: How Scanning & Sanitization Work](architecture.md)**: the detection pipeline stage by stage, why suppression runs before overlap resolution, the sanitization algorithm, and how git history scanning avoids breaking multi-line secrets
- **[Advanced: Concepts](concepts.md)**: the field knowledge behind the design, entropy, validators, fingerprinting, baselines, and why some competitor techniques were evaluated and not adopted
- **[API Reference](api.md)**: generated from docstrings
