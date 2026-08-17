import pytest

from oneleaks.config import Config, discover_config, parse_config
from oneleaks.errors import ConfigError


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
  - ".oneleaks/rules/"
allow:
  paths:
    - "tests/fixtures/**"
disabled_rules:
  - some-rule
severity_overrides:
  some-rule: low
"""
        cfg = parse_config(text)
        assert cfg.exclude == [".git/**", "node_modules/**"]
        assert cfg.pii == {"email": True, "phone": False}
        assert cfg.rule_paths == [".oneleaks/rules/"]
        assert cfg.allow_paths == ["tests/fixtures/**"]
        assert cfg.disabled_rules == ["some-rule"]
        assert cfg.severity_overrides == {"some-rule": "low"}

    def test_unknown_top_level_field_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("made_up_field: true\n")

    def test_unknown_pii_key_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("pii:\n  made_up_detector: true\n")

    def test_new_pii_keys_accepted(self):
        cfg = parse_config(
            "pii:\n  imei: false\n  mac_address: false\n  bank_routing_number: false\n"
        )
        assert cfg.pii == {"imei": False, "mac_address": False, "bank_routing_number": False}

    def test_non_mapping_top_level_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("- just\n- a\n- list\n")

    def test_unknown_severity_override_value_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("severity_overrides:\n  some-rule: extreme\n")

    def test_removed_sanitize_field_is_now_unknown(self):
        # `sanitize:` was removed as unused config plumbing: parsed but never consumed.
        with pytest.raises(ConfigError):
            parse_config("sanitize:\n  mode: typed\n")


class TestFieldShapeValidation:
    """A field given the wrong YAML shape (e.g. a bare string where a list is
    expected) must raise a clean ConfigError, not silently iterate the string
    character-by-character or crash with a raw Python exception. See the
    `_require_list_of_str`/`_require_mapping` docstrings in config.py.
    """

    @pytest.mark.parametrize("field_name", ["exclude", "rule_paths", "disabled_rules"])
    def test_list_field_given_a_bare_string_is_rejected(self, field_name):
        with pytest.raises(ConfigError) as exc_info:
            parse_config(f'{field_name}: "not-a-list"\n')
        assert "ValueError" not in str(exc_info.value)
        assert field_name in str(exc_info.value)

    @pytest.mark.parametrize("field_name", ["pii", "severity_overrides"])
    def test_mapping_field_given_a_list_is_rejected(self, field_name):
        with pytest.raises(ConfigError) as exc_info:
            parse_config(f"{field_name}: [a, b]\n")
        assert "ValueError" not in str(exc_info.value)
        assert field_name in str(exc_info.value)

    def test_allow_given_a_list_is_rejected(self):
        with pytest.raises(ConfigError) as exc_info:
            parse_config("allow: [a, b]\n")
        assert "AttributeError" not in str(exc_info.value)

    def test_allow_paths_given_a_bare_string_is_rejected(self):
        with pytest.raises(ConfigError) as exc_info:
            parse_config('allow:\n  paths: "not-a-list"\n')
        assert "allow.paths" in str(exc_info.value)

    def test_exclude_given_a_list_of_non_strings_is_rejected(self):
        with pytest.raises(ConfigError):
            parse_config("exclude:\n  - 1\n  - 2\n")


class TestDiscoverConfig:
    def test_returns_none_when_absent(self, tmp_path):
        assert discover_config(tmp_path) is None

    def test_loads_when_present(self, tmp_path):
        (tmp_path / ".oneleaks.yaml").write_text("exclude:\n  - foo/**\n")
        cfg = discover_config(tmp_path)
        assert cfg is not None
        assert cfg.exclude == ["foo/**"]

    def test_found_in_a_parent_directory(self, tmp_path):
        # The config sits at the project root, but scans are often launched
        # from below it: a pre-commit hook, an editor, or `cd src && scan`.
        (tmp_path / ".oneleaks.yaml").write_text("exclude:\n  - foo/**\n")
        nested = tmp_path / "src" / "deep"
        nested.mkdir(parents=True)
        cfg = discover_config(nested)
        assert cfg is not None
        assert cfg.exclude == ["foo/**"]

    def test_records_the_directory_it_was_loaded_from(self, tmp_path):
        (tmp_path / ".oneleaks.yaml").write_text("exclude:\n  - foo/**\n")
        cfg = discover_config(tmp_path)
        assert cfg is not None and cfg.root == tmp_path.resolve()

    def test_nearest_config_wins(self, tmp_path):
        (tmp_path / ".oneleaks.yaml").write_text("exclude:\n  - outer/**\n")
        nested = tmp_path / "inner"
        nested.mkdir()
        (nested / ".oneleaks.yaml").write_text("exclude:\n  - inner/**\n")
        cfg = discover_config(nested)
        assert cfg is not None and cfg.exclude == ["inner/**"]


class TestConfigVersion:
    """A config claiming a version this build does not know was written for a
    oneleaks that reads fields differently. Running it anyway would apply
    settings the author never asked for. Baseline files are checked the same
    way; this closes the same gap on the config side.
    """

    def test_current_version_is_accepted(self):
        assert parse_config("version: 1\nexclude: []\n").version == 1

    def test_missing_version_defaults_to_current(self):
        assert parse_config("exclude: []\n").version == 1

    def test_future_version_is_rejected(self):
        with pytest.raises(ConfigError, match="unsupported config version"):
            parse_config("version: 99\n")

    def test_version_as_a_string_is_rejected(self):
        with pytest.raises(ConfigError, match="unsupported config version"):
            parse_config('version: "1"\n')
