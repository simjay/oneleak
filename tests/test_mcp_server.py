"""Tests the MCP tool functions directly (not over a real stdio transport --
the protocol framing is the `mcp` SDK's responsibility, not oneleak's; what
needs testing here is that each tool produces correct, JSON-serializable
output matching the CLI's shapes).
"""

import pytest

pytest.importorskip("mcp")

from pathlib import Path

from oneleak.mcp_server import (
    desanitize_text,
    sanitize_text,
    scan_path,
    scan_text,
)


class TestScanText:
    def test_finds_a_secret(self):
        result = scan_text("OPENAI_API_KEY=sk-proj-" + "a" * 20)
        assert result["safe"] is False
        assert result["risk"] == "critical"
        assert result["findings"][0]["rule_id"] == "openai-api-key"

    def test_clean_text(self):
        result = scan_text("hello world")
        assert result == {"safe": True, "risk": None, "findings": []}


class TestScanPath:
    def test_scans_a_directory(self, tmp_path: Path):
        (tmp_path / "config.py").write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        result = scan_path(str(tmp_path))
        assert result["safe"] is False
        assert result["findings"][0]["path"] == "config.py"


class TestSanitizeAndDesanitize:
    def test_sanitize_without_reveal_has_no_mapping(self):
        result = sanitize_text("email=alice@example.com")
        assert "<EMAIL_1>" in result["text"]
        assert result["mapping"] is None

    def test_sanitize_reveal_and_desanitize_round_trip(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\nemail=alice@example.com\n"
        sanitized = sanitize_text(text, reveal=True)
        assert sanitized["mapping"] is not None

        restored = desanitize_text(sanitized["text"], sanitized["mapping"])
        assert restored["text"] == text

    def test_referential_consistency_via_mcp_tool(self):
        text = "alice@example.com twice: alice@example.com"
        result = sanitize_text(text)
        assert result["text"].count("<EMAIL_1>") == 2
