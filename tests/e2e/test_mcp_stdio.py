"""Real end-to-end test of the MCP server: spawns `oneleaks-mcp` as an actual
subprocess and talks to it over real stdio using the `mcp` SDK's own client
transport, the same way a real MCP client (Claude Code, Claude Desktop)
would.

tests/test_mcp_server.py deliberately tests the tool functions directly, not
over a real transport, since protocol framing correctness is the `mcp` SDK's
responsibility, not oneleaks's. This file exists for the gap that leaves:
does the server actually start, register its tools, and respond correctly
when a real client connects, end to end? That's oneleaks's responsibility
(entry point, FastMCP registration, our tool functions) even though the
wire format isn't.

Async tests are run via `asyncio.run()` inside plain sync test functions,
rather than pulling in pytest-asyncio for one file.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_PARAMS = StdioServerParameters(command=sys.executable, args=["-m", "oneleaks.mcp_server"])


async def _call_tool(name: str, arguments: dict) -> dict:
    async with (
        stdio_client(SERVER_PARAMS) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool(name, arguments)
        assert not result.isError, result.content
        return json.loads(result.content[0].text)


async def _list_tool_names() -> list[str]:
    async with (
        stdio_client(SERVER_PARAMS) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        return [t.name for t in tools.tools]


def test_server_starts_and_registers_all_four_tools():
    names = asyncio.run(_list_tool_names())
    assert set(names) == {"scan_text", "scan_path", "sanitize_text", "desanitize_text"}


def test_scan_text_over_real_stdio_finds_a_secret():
    payload = asyncio.run(
        _call_tool("scan_text", {"content": "OPENAI_API_KEY=sk-proj-" + "a" * 20})
    )
    assert payload["safe"] is False
    assert payload["risk"] == "critical"
    assert payload["findings"][0]["rule_id"] == "openai-api-key"
    assert "sk-proj-" not in json.dumps(payload)  # never the raw value, even over the wire


def test_scan_text_over_real_stdio_clean_input():
    payload = asyncio.run(_call_tool("scan_text", {"content": "hello world"}))
    assert payload == {"safe": True, "risk": None, "findings": []}


async def _sanitize_then_desanitize_round_trip(text: str) -> str:
    async with (
        stdio_client(SERVER_PARAMS) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        sanitize_result = await session.call_tool(
            "sanitize_text", {"content": text, "reveal": True}
        )
        sanitized = json.loads(sanitize_result.content[0].text)
        assert sanitized["mapping"] is not None

        desanitize_result = await session.call_tool(
            "desanitize_text", {"text": sanitized["text"], "mapping": sanitized["mapping"]}
        )
        restored = json.loads(desanitize_result.content[0].text)
        return restored["text"]


def test_sanitize_then_desanitize_round_trip_over_real_stdio():
    text = "email=alice@example.com key=sk-proj-" + "a" * 20
    restored = asyncio.run(_sanitize_then_desanitize_round_trip(text))
    assert restored == text
