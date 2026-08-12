import json
from pathlib import Path

import pytest

from oneleaks.baseline import (
    filter_new,
    load_baseline,
    require_stable_fingerprint_key,
    write_baseline,
)
from oneleaks.errors import ConfigError
from oneleaks.models import Finding


def _finding(rule_id="generic-secret", path="app.py", fingerprint="sec_abc123") -> Finding:
    return Finding(
        rule_id=rule_id,
        category="secret",
        type="generic_credential",
        severity="medium",
        start=0,
        end=10,
        path=path,
        fingerprint=fingerprint,
    )


class TestWriteAndLoad:
    def test_roundtrip(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        write_baseline(baseline_path, [_finding()])

        keys = load_baseline(baseline_path)
        assert keys == {("generic-secret", "app.py", "sec_abc123")}

    def test_written_file_never_contains_raw_values(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        write_baseline(baseline_path, [_finding()])

        raw = baseline_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert data["version"] == 1
        assert set(data["findings"][0]) == {"rule_id", "path", "fingerprint"}

    def test_update_is_a_full_resnapshot_not_a_merge(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        write_baseline(baseline_path, [_finding(fingerprint="sec_old")])
        write_baseline(baseline_path, [_finding(fingerprint="sec_new")])

        keys = load_baseline(baseline_path)
        assert keys == {("generic-secret", "app.py", "sec_new")}

    def test_missing_file_raises_config_error_naming_the_file(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist.json"
        with pytest.raises(ConfigError, match=str(missing)):
            load_baseline(missing)

    def test_malformed_json_raises_config_error(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_baseline(baseline_path)

    def test_missing_findings_key_raises_config_error(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps({"version": 1}), encoding="utf-8")
        with pytest.raises(ConfigError):
            load_baseline(baseline_path)

    def test_entry_missing_required_field_raises_config_error(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(
            json.dumps({"version": 1, "findings": [{"rule_id": "x"}]}), encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            load_baseline(baseline_path)

    def test_wrong_version_raises_config_error(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps({"version": 2, "findings": []}), encoding="utf-8")
        with pytest.raises(ConfigError, match="version"):
            load_baseline(baseline_path)

    def test_missing_version_raises_config_error(self, tmp_path: Path):
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
        with pytest.raises(ConfigError, match="version"):
            load_baseline(baseline_path)


class TestFilterNew:
    def test_excludes_baselined_findings(self):
        f = _finding()
        baseline_keys = {(f.rule_id, f.path, f.fingerprint)}
        assert filter_new([f], baseline_keys) == []

    def test_keeps_findings_not_in_baseline(self):
        f = _finding(fingerprint="sec_different")
        baseline_keys = {("generic-secret", "app.py", "sec_abc123")}
        assert filter_new([f], baseline_keys) == [f]

    def test_matches_on_rule_id_path_and_fingerprint_together(self):
        # Same fingerprint (same secret value) in a different file must not
        # be silently swallowed by a baseline entry for a different path.
        f = _finding(path="other.py")
        baseline_keys = {("generic-secret", "app.py", "sec_abc123")}
        assert filter_new([f], baseline_keys) == [f]


class TestRequireStableFingerprintKey:
    def test_raises_when_env_var_unset(self, monkeypatch):
        monkeypatch.delenv("ONELEAKS_FINGERPRINT_KEY", raising=False)
        with pytest.raises(ConfigError, match="ONELEAKS_FINGERPRINT_KEY"):
            require_stable_fingerprint_key()

    def test_passes_when_env_var_set(self, monkeypatch):
        monkeypatch.setenv("ONELEAKS_FINGERPRINT_KEY", "a-stable-test-key")
        require_stable_fingerprint_key()  # must not raise
