# MCP Server

oneleaks ships an [MCP](https://modelcontextprotocol.io/) server, so an agent runtime can call `scan`, `sanitize`, and `desanitize` directly as tools instead of shelling out to the CLI.

It's the most direct way to run the "sanitize tool output before it reaches the model" workflow from [Sanitization](sanitization.md).

## Install

```bash
pip install "oneleaks[mcp]"
```

This pulls in the official MCP Python SDK, pinned below its still-in-beta 2.0 line.

It's a separate extra rather than a core dependency, so base `oneleaks` stays dependency-light.

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

The server auto-discovers `.oneleaks.yaml` from its working directory, the same way the CLI does.

!!! tip "Point the client's working directory at your project root"

    Otherwise your project config will not apply: excluded paths, disabled rules, severity overrides.

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

With `reveal=True`, `mapping` is populated as `{placeholder: {value, rule_id, fingerprint}}`, so the text can be reversed later with `desanitize_text`.

That mapping contains raw values. Treat it exactly as sensitively as the original content.

### `desanitize_text(text: str, mapping: dict) -> dict`

Reverses `sanitize_text(..., reveal=True)`:

```json
{"text": "email=alice@example.com"}
```

## The agent pattern this enables

An agent works entirely on sanitized text, so the model never sees a raw secret. The real value comes back only at the moment an action needs it:

```text
tool output
     |
scan_text / sanitize_text(reveal=True)
     |
agent works on sanitized text, decides on an action
     |
desanitize_text right before the action actually needs the real value
```

See [Sanitization](sanitization.md) for why this is reversible tokenization rather than one-way redaction, and what that means for protecting the mapping.
