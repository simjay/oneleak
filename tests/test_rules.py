from pathlib import Path

import pytest
import yaml

import oneleaks
from oneleaks.errors import ConfigError
from oneleaks.models import PythonRule, RuleMatch
from oneleaks.rules import RuleRegistry


class TestBuiltinLoading:
    def test_builtin_rules_load_without_duplicate_ids(self):
        registry = RuleRegistry()
        registry.load_builtin()
        assert len(registry.rules) > 10


class TestYAMLRules:
    def test_custom_yaml_rule_detected(self, tmp_path: Path):
        rule_file = tmp_path / "company-rules.yaml"
        rule_file.write_text(
            "rules:\n"
            "  - id: company-api-key\n"
            "    category: secret\n"
            "    type: company_api_key\n"
            "    severity: high\n"
            "    pattern: '\\bCOMPANY_[A-Za-z0-9]{10}\\b'\n"
        )
        result = oneleaks.scan("token = COMPANY_abcdefghij", rules=[str(rule_file)])
        assert any(f.rule_id == "company-api-key" for f in result.findings)

    def test_invalid_regex_raises_config_error(self, tmp_path: Path):
        rule_file = tmp_path / "bad.yaml"
        rule_file.write_text(
            "rules:\n  - id: bad\n    category: secret\n    type: bad\n"
            "    severity: high\n    pattern: '['\n"
        )
        with pytest.raises(ConfigError):
            oneleaks.scan("text", rules=[str(rule_file)])

    def test_missing_required_field_raises(self, tmp_path: Path):
        rule_file = tmp_path / "incomplete.yaml"
        rule_file.write_text("rules:\n  - id: incomplete\n    category: secret\n")
        with pytest.raises(ConfigError):
            oneleaks.scan("text", rules=[str(rule_file)])

    def test_null_keywords_does_not_crash(self, tmp_path: Path):
        # Regression test: `keywords:` with no value parses as None in YAML.
        # This used to crash with a raw, unhandled TypeError (tuple(None) is
        # not iterable) instead of loading cleanly with no keywords, same
        # as if the field had been omitted entirely.
        rule_file = tmp_path / "null-keywords.yaml"
        rule_file.write_text(
            "rules:\n"
            "  - id: null-keywords-rule\n"
            "    category: secret\n"
            "    type: bad\n"
            "    severity: high\n"
            "    pattern: 'ZZZMARKERZZZ'\n"
            "    keywords:\n"
        )
        result = oneleaks.scan("ZZZMARKERZZZ", rules=[str(rule_file)])
        assert any(f.rule_id == "null-keywords-rule" for f in result.findings)

    def test_priority_given_as_a_string_is_rejected(self, tmp_path: Path):
        # Regression: this used to pass validation and crash deep inside
        # overlap resolution with a raw, unhandled TypeError instead of a
        # clean ConfigError at load time.
        rule_file = tmp_path / "bad-priority.yaml"
        rule_file.write_text(
            "rules:\n  - id: bad\n    category: secret\n    type: bad\n"
            "    severity: high\n    pattern: 'x'\n    priority: \"high\"\n"
        )
        with pytest.raises(ConfigError) as exc_info:
            oneleaks.scan("x", rules=[str(rule_file)])
        assert "TypeError" not in str(exc_info.value)

    def test_validator_given_as_a_list_is_rejected(self, tmp_path: Path):
        rule_file = tmp_path / "bad-validator.yaml"
        rule_file.write_text(
            "rules:\n  - id: bad\n    category: secret\n    type: bad\n"
            "    severity: high\n    pattern: 'x'\n    validator: [luhn]\n"
        )
        with pytest.raises(ConfigError) as exc_info:
            oneleaks.scan("x", rules=[str(rule_file)])
        assert "TypeError" not in str(exc_info.value)

    def test_pattern_given_as_a_list_is_rejected(self, tmp_path: Path):
        rule_file = tmp_path / "bad-pattern.yaml"
        rule_file.write_text(
            "rules:\n  - id: bad\n    category: secret\n    type: bad\n"
            "    severity: high\n    pattern: ['not', 'a', 'string']\n"
        )
        with pytest.raises(ConfigError) as exc_info:
            oneleaks.scan("x", rules=[str(rule_file)])
        assert "TypeError" not in str(exc_info.value)

    def test_keywords_given_as_a_bare_string_is_rejected(self, tmp_path: Path):
        # Regression: this used to silently accept it and split the string
        # into individual-character "keywords" (tuple("xyz") == ('x','y','z')),
        # which then matched almost any nearby text containing a common
        # letter, silently defeating the keyword gate instead of erroring.
        rule_file = tmp_path / "bad-keywords.yaml"
        rule_file.write_text(
            "rules:\n  - id: bad\n    category: secret\n    type: bad\n"
            "    severity: high\n    pattern: 'x'\n    keywords: \"xyz\"\n"
        )
        with pytest.raises(ConfigError):
            oneleaks.scan("x", rules=[str(rule_file)])

    @pytest.mark.parametrize("field_name", ["id", "category", "type", "severity"])
    def test_required_field_given_as_a_non_string_is_rejected(self, tmp_path: Path, field_name):
        entry = {"id": "bad", "category": "secret", "type": "bad", "severity": "high"}
        entry[field_name] = 123
        entry["pattern"] = "x"
        rule_file = tmp_path / "bad-field.yaml"
        rule_file.write_text(yaml.safe_dump({"rules": [entry]}))
        with pytest.raises(ConfigError):
            oneleaks.scan("x", rules=[str(rule_file)])

    def test_duplicate_rule_id_raises(self, tmp_path: Path):
        rule_file = tmp_path / "dup.yaml"
        rule_file.write_text(
            "rules:\n"
            "  - id: email\n"  # collides with a builtin rule id
            "    category: secret\n"
            "    type: whatever\n"
            "    severity: high\n"
            "    pattern: 'x'\n"
        )
        with pytest.raises(ConfigError):
            oneleaks.scan("text", rules=[str(rule_file)])


class TestJSONRules:
    def test_custom_json_rule_detected(self, tmp_path: Path):
        rule_file = tmp_path / "company-rules.json"
        rule_file.write_text(
            '{"rules": [{"id": "company-token", "category": "secret", '
            '"type": "company_token", "severity": "high", '
            '"pattern": "\\\\bCTOK_[A-Za-z0-9]{8}\\\\b"}]}'
        )
        result = oneleaks.scan("CTOK_abcdefgh", rules=[str(rule_file)])
        assert any(f.rule_id == "company-token" for f in result.findings)


class TestPythonRules:
    def test_python_rule_must_be_explicitly_passed(self):
        class EmployeeIdRule(PythonRule):
            id = "employee-id"
            category = "pii"
            type = "employee_id"
            severity = "medium"

            def detect(self, text):
                idx = text.find("EMP-")
                if idx == -1:
                    return []
                return [RuleMatch(start=idx, end=idx + 10)]

        result_without = oneleaks.scan("badge: EMP-1234567")
        assert not any(f.rule_id == "employee-id" for f in result_without.findings)

        result_with = oneleaks.scan("badge: EMP-1234567", rules=[EmployeeIdRule()])
        assert any(f.rule_id == "employee-id" for f in result_with.findings)

    def test_python_rule_with_nonstandard_category(self):
        # PythonRule.category is a free-form string, not validated against
        # Category (unlike declarative rules). Confirms the fingerprint
        # prefix fallback for an unrecognized category actually gets hit.
        class SimpleRule(PythonRule):
            id = "simple-rule"
            category = "custom"
            type = "simple"
            severity = "low"

            def detect(self, text):
                if "MARK" in text:
                    idx = text.index("MARK")
                    return [RuleMatch(start=idx, end=idx + 4)]
                return []

        result = oneleaks.scan("here is MARK in text", rules=[SimpleRule()])
        finding = next(f for f in result.findings if f.rule_id == "simple-rule")
        assert finding.fingerprint.startswith("fnd_")
