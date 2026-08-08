import io
import json
import stat
import sys
from pathlib import Path

from oneleak.cli import main


class _FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def run_cli(argv, stdin_text="", monkeypatch=None, capsys=None):
    if monkeypatch is not None and stdin_text is not None:
        monkeypatch.setattr(sys, "stdin", _FakeStdin(stdin_text.encode("utf-8")))
    code = main(argv)
    out = capsys.readouterr() if capsys else None
    return code, out


class TestScanCommand:
    def test_clean_text_exit_code_0(self, monkeypatch, capsys):
        code, out = run_cli(
            ["scan", "-"], stdin_text="hello world\n", monkeypatch=monkeypatch, capsys=capsys
        )
        assert code == 0
        assert "No findings" in out.out

    def test_findings_exit_code_1(self, monkeypatch, capsys):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n"
        code, out = run_cli(["scan", "-"], stdin_text=text, monkeypatch=monkeypatch, capsys=capsys)
        assert code == 1
        assert "openai-api-key" in out.out

    def test_json_output_shape(self, monkeypatch, capsys):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n"
        code, out = run_cli(
            ["scan", "-", "--json"], stdin_text=text, monkeypatch=monkeypatch, capsys=capsys
        )
        payload = json.loads(out.out)
        assert payload["safe"] is False
        assert payload["risk"] == "critical"
        assert payload["findings"][0]["rule_id"] == "openai-api-key"
        assert code == 1

    def test_fail_on_threshold(self, monkeypatch, capsys):
        # email is "low" severity; --fail-on high should not block on it.
        code, _out = run_cli(
            ["scan", "-", "--fail-on", "high"],
            stdin_text="contact alice@example.com\n",
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        assert code == 0

    def test_scan_file_path(self, tmp_path: Path, capsys):
        f = tmp_path / "config.py"
        f.write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        code = main(["scan", str(f)])
        out = capsys.readouterr()
        assert code == 1
        assert "openai-api-key" in out.out


class TestSanitizeCommand:
    def test_sanitize_file_to_stdout(self, tmp_path: Path, capsys):
        f = tmp_path / "leak.txt"
        f.write_text("email=alice@example.com\n")
        code = main(["sanitize", str(f)])
        out = capsys.readouterr()
        assert code == 0
        assert "<EMAIL_1>" in out.out
        assert "alice@example.com" not in out.out

    def test_sanitize_with_map_writes_restrictive_permissions(self, tmp_path: Path, capsys):
        f = tmp_path / "leak.txt"
        f.write_text("email=alice@example.com\n")
        map_path = tmp_path / "mapping.json"
        code = main(["sanitize", str(f), "--map", str(map_path)])
        capsys.readouterr()
        assert code == 0
        assert map_path.exists()
        mode = stat.S_IMODE(map_path.stat().st_mode)
        assert mode == 0o600
        payload = json.loads(map_path.read_text())
        assert payload["mapping"]["<EMAIL_1>"]["value"] == "alice@example.com"


class TestDesanitizeCommand:
    def test_round_trip_via_cli(self, tmp_path: Path, capsys):
        f = tmp_path / "leak.txt"
        f.write_text("email=alice@example.com\n")
        map_path = tmp_path / "mapping.json"
        main(["sanitize", str(f), "--map", str(map_path)])
        sanitized_out = capsys.readouterr().out

        sanitized_file = tmp_path / "sanitized.txt"
        sanitized_file.write_text(sanitized_out)

        code = main(["desanitize", str(sanitized_file), "--map", str(map_path)])
        out = capsys.readouterr()
        assert code == 0
        assert out.out == "email=alice@example.com\n"


class TestErrorHandling:
    def test_nonexistent_path_exit_code_2(self, capsys):
        code = main(["scan", "/nonexistent/path/xyz"])
        out = capsys.readouterr()
        assert code == 2
        assert "error:" in out.err

    def test_changed_with_paths_errors_instead_of_silently_ignoring_paths(self, capsys):
        code = main(["scan", "somefile.txt", "--changed"])
        out = capsys.readouterr()
        assert code == 2
        assert "error:" in out.err
