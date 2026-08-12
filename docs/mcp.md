# MCP Server

oneleaks ships an [MCP](https://modelcontextprotocol.io/) server so an agent runtime can call `scan`/`sanitize`/`desanitize` directly as tools, instead of shelling out to the CLI. This is the most direct way to plug oneleaks into the "sanitize tool output before it reaches LLM context" workflow described in [Sanitization](sanitization.md).

## Install

```bash
pip install "oneleaks[mcp]"
```

This pulls in the official MCP Python SDK (`mcp`), pinned below its still-in-beta 2.0 line. It's a separate extra, not a core dependency, so the base `oneleaks` package stays dependency-light.

## Run

```bash
oneleaks-mcp
```

or

```bash
python -m oneleaks.mcp_server
```

The server uses stdio transport (standard input/output), the way local MCP servers are normally launched by a client, not something you run standalone and connect to over a network.

## Configure a client

Example for Claude Desktop / Claude Code style MCP config (`claude_desktop_config.json` or equivalent):

```json
{
  "mcpServers": {
    "oneleaks": {
      "command": "oneleaks-mcp"
    }
  }
}
```

The server auto-discovers `.oneleaks.yaml` from its working directory, the same way the CLI does. Point the client's working directory at your project root if you want project-specific config (excluded paths, disabled rules, severity overrides, etc.) to apply.

## Tools

### `scan_text(content: str) -> dict`

Scan a string for secrets and PII. Returns the same shape as `oneleaks scan --json`:

```json
{"safe": false, "risk": "critical", "findings": [...]}
```

### `scan_path(path: str) -> dict`

Same as `scan_text`, but for a file or directory path. Mirrors `oneleaks scan <path>`.

### `sanitize_text(content: str, reveal: bool = False) -> dict`

Redacts secrets/PII with typed, numbered placeholders (`<EMAIL_1>`, `<OPENAI_API_KEY_1>`, ...):

```json
{"text": "email=<EMAIL_1>", "mapping": null}
```

With `reveal=True`, `mapping` is populated (`{placeholder: {value, rule_id, fingerprint}}`) so the sanitized text can be reversed later via `desanitize_text`. Treat that mapping exactly as sensitively as the original content: it contains raw values.

### `desanitize_text(text: str, mapping: dict) -> dict`

Reverses `sanitize_text(..., reveal=True)`:

```json
{"text": "email=alice@example.com"}
```

## The agent pattern this enables

An agent can work entirely on sanitized text (the model itself never sees a raw secret) and rehydrate the real value only at the point of actually performing an action:

```text
tool output
     |
scan_text / sanitize_text(reveal=True)
     |
agent works on sanitized text, decides on an action
     |
desanitize_text right before the action actually needs the real value
```

See [Sanitization](sanitization.md) for more on why this is reversible tokenization, not one-way redaction, and what that implies about protecting the mapping.
