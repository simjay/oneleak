from pathlib import Path

import pytest

import oneleak
from oneleak.errors import ConfigError
from oneleak.models import PythonRule, RuleMatch
from oneleak.rules import RuleRegistry


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
        result = oneleak.scan("token = COMPANY_abcdefghij", rules=[str(rule_file)])
        assert any(f.rule_id == "company-api-key" for f in result.findings)

    def test_invalid_regex_raises_config_error(self, tmp_path: Path):
        rule_file = tmp_path / "bad.yaml"
        rule_file.write_text(
            "rules:\n  - id: bad\n    category: secret\n    type: bad\n"
            "    severity: high\n    pattern: '['\n"
        )
        with pytest.raises(ConfigError):
            oneleak.scan("text", rules=[str(rule_file)])

    def test_missing_required_field_raises(self, tmp_path: Path):
        rule_file = tmp_path / "incomplete.yaml"
        rule_file.write_text("rules:\n  - id: incomplete\n    category: secret\n")
        with pytest.raises(ConfigError):
            oneleak.scan("text", rules=[str(rule_file)])

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
            oneleak.scan("text", rules=[str(rule_file)])


class TestJSONRules:
    def test_custom_json_rule_detected(self, tmp_path: Path):
        rule_file = tmp_path / "company-rules.json"
        rule_file.write_text(
            '{"rules": [{"id": "company-token", "category": "secret", '
            '"type": "company_token", "severity": "high", '
            '"pattern": "\\\\bCTOK_[A-Za-z0-9]{8}\\\\b"}]}'
        )
        result = oneleak.scan("CTOK_abcdefgh", rules=[str(rule_file)])
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

        result_without = oneleak.scan("badge: EMP-1234567")
        assert not any(f.rule_id == "employee-id" for f in result_without.findings)

        result_with = oneleak.scan("badge: EMP-1234567", rules=[EmployeeIdRule()])
        assert any(f.rule_id == "employee-id" for f in result_with.findings)

    def test_python_rule_tuple_match(self):
        class SimpleRule(PythonRule):
            id = "simple-rule"
            category = "sensitive"
            type = "simple"
            severity = "low"

            def detect(self, text):
                if "MARK" in text:
                    idx = text.index("MARK")
                    return [(idx, idx + 4)]
                return []

        result = oneleak.scan("here is MARK in text", rules=[SimpleRule()])
        assert any(f.rule_id == "simple-rule" for f in result.findings)
