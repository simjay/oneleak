import pytest

from oneleak.config import Config, discover_config, parse_config
from oneleak.errors import ConfigError


class TestParseConfig:
    def test_defaults(self):
        cfg = parse_config("")
        assert cfg == Config()

    def test_full_config(self):
        text = """
version: 1
exclude:
  - ".git/**"
  - "node_modules/**"
pii:
  email: true
  phone: false
rule_paths:
  - ".oneleak/rules/"
allow:
  paths:
    - "tests/fixtures/**"
sanitize:
  mode: typed
disabled_rules:
  - some-rule
severity_overrides:
  some-rule: low
"""
        cfg = parse_config(text)
        assert cfg.exclude == [".git/**", "node_modules/**"]
        assert cfg.pii == {"email": True, "phone": False}
        assert cfg.rule_paths == [".oneleak/rules/"]
        assert cfg.allow_paths == ["tests/fixtures/**"]
        assert cfg.sanitize == {"mode": "typed"}
        assert cfg.disabled_rules == ["some-rule"]
        assert cfg.severity_overrides == {"some-rule": "low"}

    def test_unknown_top_level_field_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("made_up_field: true\n")

    def test_unknown_pii_key_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("pii:\n  made_up_detector: true\n")

    def test_non_mapping_top_level_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("- just\n- a\n- list\n")


class TestDiscoverConfig:
    def test_returns_none_when_absent(self, tmp_path):
        assert discover_config(tmp_path) is None

    def test_loads_when_present(self, tmp_path):
        (tmp_path / ".oneleak.yaml").write_text("exclude:\n  - foo/**\n")
        cfg = discover_config(tmp_path)
        assert cfg is not None
        assert cfg.exclude == ["foo/**"]
