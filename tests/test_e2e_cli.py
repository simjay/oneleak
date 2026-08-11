"""Real end-to-end tests: invoke `oneleak` as an actual subprocess (real
process boundary, real argv/stdin/stdout/stderr/exit code), not by calling
`cli.main()` in-process the way tests/test_cli.py does.

This is what actually catches entry-point/packaging breakage and confirms a
real user or CI pipeline sees clean output on stderr, not just that the
internal function returns the right value. Unit-level behavior (every flag
combination, every error message's exact wording) stays in test_cli.py; this
file only re-covers the same ground where crossing a real process boundary
could plausibly change the answer (exit codes, stdin/stdout/stderr framing,
file permissions, real git subprocess interaction, real config discovery
from a real cwd).

Uses `sys.executable -m oneleak.cli` rather than the installed `oneleak`
console script: works identically in any environment where the package is
importable, with no dependency on PATH or how the package was installed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ONELEAK = [sys.executable, "-m", "oneleak.cli"]


def run_oneleak(args, *, cwd=None, input_text=None, env=None):
    return subprocess.run(
        [*ONELEAK, *args],
        cwd=cwd,
        input=input_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class TestSmoke:
    def test_version(self):
        result = run_oneleak(["--version"])
        assert result.returncode == 0
        assert "oneleak" in result.stdout

    def test_help(self):
        result = run_oneleak(["--help"])
        assert result.returncode == 0
        assert "scan" in result.stdout
        assert "sanitize" in result.stdout

    def test_scan_help(self):
        result = run_oneleak(["scan", "--help"])
        assert result.returncode == 0
        assert "--baseline" in result.stdout

    def test_no_args_is_a_clean_usage_error_not_a_crash(self):
        result = run_oneleak([])
        assert result.returncode == 2
        assert "Traceback" not in result.stderr


class TestScanViaSubprocess:
    def test_clean_stdin_exit_0(self):
        result = run_oneleak(["scan", "-"], input_text="hello world\n")
        assert result.returncode == 0
        assert "No findings" in result.stdout
        assert result.stderr == ""

    def test_secret_in_stdin_exit_1(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n"
        result = run_oneleak(["scan", "-"], input_text=text)
        assert result.returncode == 1
        assert "openai-api-key" in result.stdout

    def test_json_output_is_valid_and_well_shaped(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n"
        result = run_oneleak(["scan", "-", "--json"], input_text=text)
        payload = json.loads(result.stdout)
        assert payload["safe"] is False
        assert payload["risk"] == "critical"
        assert payload["findings"][0]["rule_id"] == "openai-api-key"
        assert "sk-proj-" not in json.dumps(payload)  # never the raw value

    def test_scan_a_real_file(self, tmp_path: Path):
        f = tmp_path / "config.py"
        f.write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        result = run_oneleak(["scan", str(f)])
        assert result.returncode == 1
        assert "openai-api-key" in result.stdout

    def test_scan_a_real_directory(self, tmp_path: Path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        (tmp_path / "leaky.py").write_text("email = 'alice@example.com'\n")
        result = run_oneleak(["scan", str(tmp_path)])
        assert result.returncode == 1
        assert "leaky.py" in result.stdout
        assert "clean.py" not in result.stdout

    def test_fail_on_threshold_via_subprocess(self):
        # Low-severity email alone shouldn't block with --fail-on high.
        result = run_oneleak(["scan", "-", "--fail-on", "high"], input_text="alice@example.com\n")
        assert result.returncode == 0
        assert "email" in result.stdout  # still printed, just not blocking

    def test_nonexistent_path_exits_2_with_no_traceback(self):
        result = run_oneleak(["scan", "/nonexistent/path/xyz"])
        assert result.returncode == 2
        assert result.stdout == ""
        assert result.stderr.startswith("error:")
        assert "Traceback" not in result.stderr

    def test_malformed_config_exits_2_with_no_traceback(self, tmp_path: Path):
        target = tmp_path / "app.py"
        target.write_text("x = 1\n")
        bad_config = tmp_path / "bad.yaml"
        bad_config.write_text("pii: [email, phone]\n")
        result = run_oneleak(["scan", str(target), "--config", str(bad_config)])
        assert result.returncode == 2
        assert "Traceback" not in result.stderr
        assert "ValueError" not in result.stderr
        assert "must be a mapping" in result.stderr


class TestSanitizeDesanitizeRoundTrip:
    def test_full_round_trip_through_real_files_and_pipes(self, tmp_path: Path):
        src = tmp_path / "input.txt"
        src.write_text("contact alice@example.com key=sk-proj-" + "a" * 20 + "\n")
        map_path = tmp_path / "map.json"

        sanitized = run_oneleak(["sanitize", str(src), "--map", str(map_path)])
        assert sanitized.returncode == 0
        assert "<EMAIL_1>" in sanitized.stdout
        assert "alice@example.com" not in sanitized.stdout
        assert map_path.exists()
        assert oct(map_path.stat().st_mode)[-3:] == "600"
        assert "do not commit" in sanitized.stderr

        restored = run_oneleak(
            ["desanitize", "-", "--map", str(map_path)], input_text=sanitized.stdout
        )
        assert restored.returncode == 0
        assert restored.stdout == src.read_text()


class TestBaselineWorkflowViaSubprocess:
    def test_requires_stable_fingerprint_key(self, tmp_path: Path):
        env = {k: v for k, v in os.environ.items() if k != "ONELEAK_FINGERPRINT_KEY"}
        result = run_oneleak(
            ["scan", "-", "--baseline", str(tmp_path / "b.json"), "--update-baseline"],
            input_text="OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n",
            env=env,
        )
        assert result.returncode == 2
        assert "ONELEAK_FINGERPRINT_KEY" in result.stderr

    def test_update_then_recheck_is_clean_then_new_secret_is_reported(self, tmp_path: Path):
        env = {**os.environ, "ONELEAK_FINGERPRINT_KEY": "e2e-stable-key"}
        target = tmp_path / "app.py"
        target.write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        baseline = tmp_path / ".oneleak-baseline.json"

        first = run_oneleak(
            ["scan", str(target), "--baseline", str(baseline), "--update-baseline"], env=env
        )
        assert first.returncode == 0
        assert baseline.exists()

        recheck = run_oneleak(["scan", str(target), "--baseline", str(baseline)], env=env)
        assert recheck.returncode == 0

        target.write_text(target.read_text() + "\nANTHROPIC_API_KEY = 'sk-ant-" + "b" * 20 + "'\n")
        with_new_secret = run_oneleak(["scan", str(target), "--baseline", str(baseline)], env=env)
        assert with_new_secret.returncode == 1
        assert "anthropic-api-key" in with_new_secret.stdout
        assert "openai-api-key" not in with_new_secret.stdout  # still baselined


class TestGitScanningViaSubprocess:
    def _init_repo(self, cwd: Path) -> None:
        _git(["init", "-q"], cwd)
        _git(["config", "user.email", "e2e@test.com"], cwd)
        _git(["config", "user.name", "e2e"], cwd)

    def test_staged_scan(self, tmp_path: Path):
        self._init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "-A"], tmp_path)
        result = run_oneleak(["scan", "--staged"], cwd=tmp_path)
        assert result.returncode == 0

        (tmp_path / "app.py").write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        _git(["add", "-A"], tmp_path)
        result = run_oneleak(["scan", "--staged"], cwd=tmp_path)
        assert result.returncode == 1
        assert "openai-api-key" in result.stdout

    def test_changed_scan(self, tmp_path: Path):
        self._init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "-A"], tmp_path)
        _git(["commit", "-q", "-m", "init"], tmp_path)

        (tmp_path / "app.py").write_text("email = 'alice@example.com'\n")
        result = run_oneleak(["scan", "--changed"], cwd=tmp_path)
        assert result.returncode == 1
        assert "email" in result.stdout

    def test_history_scan_finds_removed_secret(self, tmp_path: Path):
        self._init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "-A"], tmp_path)
        _git(["commit", "-q", "-m", "c1"], tmp_path)

        (tmp_path / "app.py").write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        _git(["add", "-A"], tmp_path)
        _git(["commit", "-q", "-m", "c2 (adds secret)"], tmp_path)

        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "-A"], tmp_path)
        _git(["commit", "-q", "-m", "c3 (removes secret)"], tmp_path)

        clean_scan = run_oneleak(["scan", str(tmp_path)])
        assert clean_scan.returncode == 0  # gone from the working tree

        history_scan = run_oneleak(["scan", "--history"], cwd=tmp_path)
        assert history_scan.returncode == 1
        assert "openai-api-key" in history_scan.stdout
        assert "@" in history_scan.stdout  # commit SHA suffix


class TestConfigDiscoveryFromRealCwd:
    def test_oneleak_yaml_is_auto_discovered_and_custom_rule_fires(self, tmp_path: Path):
        (tmp_path / "custom-rules.yaml").write_text(
            "rules:\n"
            "  - id: company-token\n"
            "    category: secret\n"
            "    type: company_token\n"
            "    severity: high\n"
            "    pattern: '\\bCTOK_[A-Za-z0-9]{8}\\b'\n"
        )
        (tmp_path / ".oneleak.yaml").write_text("rule_paths:\n  - custom-rules.yaml\n")
        (tmp_path / "app.py").write_text("token = CTOK_abcdefgh\n")

        result = run_oneleak(["scan", "app.py"], cwd=tmp_path)
        assert result.returncode == 1
        assert "company-token" in result.stdout

    def test_disabled_rules_suppresses_a_finding(self, tmp_path: Path):
        (tmp_path / ".oneleak.yaml").write_text("disabled_rules:\n  - email\n")
        (tmp_path / "app.py").write_text("contact = 'alice@example.com'\n")

        result = run_oneleak(["scan", "app.py"], cwd=tmp_path)
        assert result.returncode == 0
        assert "No findings" in result.stdout
