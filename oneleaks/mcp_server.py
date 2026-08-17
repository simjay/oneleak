"""MCP server exposing scan/sanitize/desanitize as tools for agent runtimes.

Run with `oneleaks-mcp` (installed via `pip install oneleaks[mcp]`), or
`python -m oneleaks.mcp_server`. Uses stdio transport, the standard way
local MCP servers are launched by clients like Claude Code / Claude Desktop.

Each tool auto-discovers `.oneleaks.yaml` from the server process's working
directory, matching the CLI's behavior: an MCP server is inherently invoked
with a project directory as context, so there's no reason to make an agent
pass config explicitly on every call.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from oneleaks.config import discover_config
from oneleaks.findings import finding_to_dict
from oneleaks.models import Finding, MappingEntry, severity_rank
from oneleaks.sanitizer import desanitize as _desanitize
from oneleaks.sanitizer import sanitize as _sanitize
from oneleaks.scanner import scan as _scan

mcp = FastMCP("oneleaks")


def _scan_payload(findings: list[Finding]) -> dict:
    risk = max((f.severity for f in findings), key=severity_rank) if findings else None
    return {
        "safe": len(findings) == 0,
        "risk": risk,
        "findings": [finding_to_dict(f) for f in findings],
    }


@mcp.tool()
def scan_text(content: str) -> dict:
    """Scan text for secrets and PII. Returns {safe, risk, findings}, the
    same shape as `oneleaks scan --json`.
    """
    result = _scan(content, config=discover_config())
    return _scan_payload(result.findings)


@mcp.tool()
def scan_path(path: str) -> dict:
    """Scan a file or directory for secrets and PII. Returns {safe, risk,
    findings}, the same shape as `oneleaks scan <path> --json`.
    """
    result = _scan(Path(path), config=discover_config())
    return _scan_payload(result.findings)


@mcp.tool()
def sanitize_text(content: str, reveal: bool = False) -> dict:
    """Redact secrets/PII in text with typed, numbered placeholders
    (<EMAIL_1>, <OPENAI_API_KEY_1>, ...). If reveal=True, also returns a
    mapping usable with desanitize_text to reverse it later. Treat that
    mapping exactly as sensitively as the original content: it contains raw
    values.
    """
    result = _sanitize(content, config=discover_config(), reveal=reveal)
    mapping = None
    if result.mapping is not None:
        mapping = {
            placeholder: {"value": e.value, "rule_id": e.rule_id, "fingerprint": e.fingerprint}
            for placeholder, e in result.mapping.items()
        }
    return {"text": result.text, "mapping": mapping}


@mcp.tool()
def desanitize_text(text: str, mapping: dict) -> dict:
    """Reverse sanitize_text(..., reveal=True) using the mapping it returned.
    Placeholders in the mapping absent from `text`, and placeholder-shaped
    tokens in `text` absent from the mapping, are left untouched.
    """
    entries = {
        placeholder: MappingEntry(
            value=entry["value"], rule_id=entry["rule_id"], fingerprint=entry.get("fingerprint")
        )
        for placeholder, entry in mapping.items()
    }
    return {"text": _desanitize(text, entries)}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
