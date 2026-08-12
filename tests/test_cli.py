import io
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from oneleaks.cli import main


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
        # email is "low" severity, --fail-on high should not block on it.
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


class TestHistoryCommand:
    def _repo_with_removed_secret(self, tmp_path: Path) -> Path:
        def run(*args):
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

        run("init", "-q")
        run("config", "user.email", "test@test.com")
        run("config", "user.name", "test")
        (tmp_path / "app.py").write_text("x = 1\n")
        run("add", "-A")
        run("commit", "-q", "-m", "c1")
        (tmp_path / "app.py").write_text("x = 1\nOPENAI_API_KEY=sk-proj-" + "a" * 30 + "\n")
        run("add", "-A")
        run("commit", "-q", "-m", "c2")
        (tmp_path / "app.py").write_text("x = 1\n")
        run("add", "-A")
        run("commit", "-q", "-m", "c3")
        return tmp_path

    def test_history_finds_removed_secret_with_commit_in_output(
        self, tmp_path: Path, capsys, monkeypatch
    ):
        repo = self._repo_with_removed_secret(tmp_path)
        # cmd_scan doesn't pass an explicit cwd to git.scan_history(), so it
        # falls back to the process's actual cwd, same as running `oneleaks
        # scan --history` from within the repo on a real shell.
        monkeypatch.chdir(repo)

        code = main(["scan", "--history"])
        out = capsys.readouterr()

        assert code == 1
        assert "openai-api-key" in out.out
        assert "@" in out.out  # commit SHA suffix

    def test_history_with_paths_errors(self, capsys):
        code = main(["scan", "somefile.txt", "--history"])
        out = capsys.readouterr()
        assert code == 2
        assert "error:" in out.err

    def test_history_and_changed_together_is_argparse_error(self, capsys):
        # argparse's mutually-exclusive group raises SystemExit directly from
        # parse_args(), before cmd_scan's own try/except gets a chance to run.
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", "--history", "--changed"])
        assert exc_info.value.code == 2


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


# Python exception class names that must never reach a user-facing error line.
# Asserting only `code == 2` and `"error:" in err` would pass both before and
# after the fix that introduced these tests, pinning nothing, so every case
# below also asserts the message names the offending file and leaks no type.
_LEAKY_TYPE_NAMES = [
    "FileNotFoundError",
    "JSONDecodeError",
    "ParserError",
    "ScannerError",
    "KeyError",
    "TypeError",
    "OSError",
    "Traceback",
]


def _assert_clean_error(err: str, *, names: str) -> None:
    assert err.startswith("error: "), err
    for leaked in _LEAKY_TYPE_NAMES:
        assert leaked not in err, f"raw exception type {leaked!r} leaked to user: {err!r}"
    assert names in err, f"error should name the offending file/subject: {err!r}"


class TestErrorMessagesAreUserFacing:
    def test_missing_config_file(self, tmp_path: Path, capsys):
        target = tmp_path / "in.txt"
        target.write_text("x")
        missing = tmp_path / "nope.yaml"
        code = main(["scan", str(target), "--config", str(missing)])
        assert code == 2
        _assert_clean_error(capsys.readouterr().err, names=str(missing))

    def test_malformed_config_file(self, tmp_path: Path, capsys):
        target = tmp_path / "in.txt"
        target.write_text("x")
        cfg = tmp_path / "bad.yaml"
        cfg.write_text("exclude: [unclosed\n")
        code = main(["scan", str(target), "--config", str(cfg)])
        assert code == 2
        err = capsys.readouterr().err
        _assert_clean_error(err, names=str(cfg))
        assert "invalid YAML" in err

    def test_malformed_mapping_file(self, tmp_path: Path, capsys):
        target = tmp_path / "in.txt"
        target.write_text("x")
        bad_map = tmp_path / "bad.json"
        bad_map.write_text("not json at all")
        code = main(["desanitize", str(target), "--map", str(bad_map)])
        assert code == 2
        _assert_clean_error(capsys.readouterr().err, names=str(bad_map))

    def test_mapping_entry_missing_required_key(self, tmp_path: Path, capsys):
        target = tmp_path / "in.txt"
        target.write_text("x")
        bad_map = tmp_path / "bad.json"
        bad_map.write_text('{"mapping": {"<EMAIL_1>": {"value": "a@b.c"}}}')
        code = main(["desanitize", str(target), "--map", str(bad_map)])
        assert code == 2
        err = capsys.readouterr().err
        _assert_clean_error(err, names="<EMAIL_1>")

    def test_git_scans_outside_a_repository(self, tmp_path: Path, capsys, monkeypatch):
        # All three git modes must fail identically and cleanly. --staged used
        # to dump git's entire usage text here: outside a repo `git diff
        # --cached` falls back to --no-index mode, where --cached is invalid.
        monkeypatch.chdir(tmp_path)
        for flag in ("--changed", "--staged", "--history"):
            code = main(["scan", flag])
            err = capsys.readouterr().err
            assert code == 2, flag
            assert err.strip() == "error: not a git repository", f"{flag}: {err!r}"


class TestErrorMessagesFromPythonAPI:
    """The CLI is not the only caller: `load_config` is reached from the
    library too, so these must be fixed at the source, not in cli.main().
    """

    def test_missing_config_raises_config_error(self, tmp_path: Path):
        import oneleaks

        with pytest.raises(oneleaks.ConfigError) as exc_info:
            oneleaks.scan("x", config=str(tmp_path / "nope.yaml"))
        assert "not found" in str(exc_info.value)

    def test_missing_rule_file_raises_config_error(self, tmp_path: Path):
        import oneleaks

        with pytest.raises(oneleaks.ConfigError) as exc_info:
            oneleaks.scan("x", rules=[str(tmp_path / "nope.yaml")])
        assert "not found" in str(exc_info.value)

    def test_malformed_rule_file_raises_config_error(self, tmp_path: Path):
        import oneleaks

        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: [unclosed\n")
        with pytest.raises(oneleaks.ConfigError) as exc_info:
            oneleaks.scan("x", rules=[str(bad)])
        assert "invalid YAML" in str(exc_info.value)


class TestVersionFlag:
    def test_version_matches_package_metadata(self, capsys):
        from importlib.metadata import version

        import oneleaks

        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert oneleaks.__version__ in out
        # pyproject declares the version dynamically from oneleaks/__init__.py.
        # This pins that the two can never drift apart.
        assert version("oneleaks") == oneleaks.__version__


class TestBaselineFlag:
    _SECRET_TEXT = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n"

    def test_baseline_requires_stable_fingerprint_key(self, tmp_path: Path, monkeypatch, capsys):
        monkeypatch.delenv("ONELEAKS_FINGERPRINT_KEY", raising=False)
        baseline = tmp_path / "baseline.json"
        code, out = run_cli(
            ["scan", "-", "--baseline", str(baseline)],
            stdin_text=self._SECRET_TEXT,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        assert code == 2
        assert "ONELEAKS_FINGERPRINT_KEY" in out.err

    def test_update_baseline_without_baseline_flag_is_an_error(self, monkeypatch, capsys):
        code, out = run_cli(
            ["scan", "-", "--update-baseline"],
            stdin_text=self._SECRET_TEXT,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        assert code == 2
        assert "--update-baseline requires --baseline" in out.err

    def test_update_baseline_then_rescan_reports_no_new_findings(
        self, tmp_path: Path, monkeypatch, capsys
    ):
        monkeypatch.setenv("ONELEAKS_FINGERPRINT_KEY", "test-stable-key")
        baseline = tmp_path / "baseline.json"

        code, out = run_cli(
            ["scan", "-", "--baseline", str(baseline), "--update-baseline"],
            stdin_text=self._SECRET_TEXT,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        assert code == 0
        assert "No findings" in out.out
        assert baseline.exists()

        code, out = run_cli(
            ["scan", "-", "--baseline", str(baseline)],
            stdin_text=self._SECRET_TEXT,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        assert code == 0
        assert "No findings" in out.out

    def test_new_finding_not_in_baseline_still_reported(self, tmp_path: Path, monkeypatch, capsys):
        monkeypatch.setenv("ONELEAKS_FINGERPRINT_KEY", "test-stable-key")
        baseline = tmp_path / "baseline.json"
        baseline.write_text('{"version": 1, "findings": []}', encoding="utf-8")

        code, out = run_cli(
            ["scan", "-", "--baseline", str(baseline)],
            stdin_text=self._SECRET_TEXT,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        assert code == 1
        assert "openai-api-key" in out.out

    def test_baseline_shrinks_when_secret_is_removed(self, tmp_path: Path, monkeypatch, capsys):
        monkeypatch.setenv("ONELEAKS_FINGERPRINT_KEY", "test-stable-key")
        baseline = tmp_path / "baseline.json"

        run_cli(
            ["scan", "-", "--baseline", str(baseline), "--update-baseline"],
            stdin_text=self._SECRET_TEXT,
            monkeypatch=monkeypatch,
            capsys=capsys,
        )
        run_cli(
            ["scan", "-", "--baseline", str(baseline), "--update-baseline"],
            stdin_text="hello world\n",
            monkeypatch=monkeypatch,
            capsys=capsys,
        )

        data = json.loads(baseline.read_text(encoding="utf-8"))
        assert data["findings"] == []
